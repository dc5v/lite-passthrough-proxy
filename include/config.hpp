#pragma once

#include <algorithm>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <netdb.h>
#include <optional>
#include <regex>
#include <sys/socket.h>
#include <variant>
#include <vector>
#include <yaml-cpp/yaml.h>

using namespace std;

/**
 * 단위를 통일해요.
 *
 * 시간: milliseconds
 * 버퍼: bytes
 */
namespace lite_through_proxy
{
  struct Route
  {
    string protocol{ "tcp" };

    uint16_t src_port_from{ 0 };
    uint16_t src_port_to{ 0 };

    string dest_host{ "" };
    uint16_t dest_port_from{ 0 };
    uint16_t dest_port_to{ 0 };

    bool is_single_port{ false }; // 단일 포트인지 범위인지 구분
    bool is_preserve_ip{ false }; // preserve, forwarding origin client IP
    bool is_correct{ false };     // FLAG - correct route

    vector<sockaddr_storage> resolved_addrs;
  };

  struct OptionConnection
  {
    uint32_t idle_timeout{ 60000 };
    uint32_t connect_timeout{ 10000 };
    uint32_t shutdown_timeout{ 30000 };
  };

  struct Options
  {
    OptionConnection connection;

    uint32_t worker_threads{ 0 }; // Worker threads (0 = 힘닿는데까지쥐어짜용)
    string log_level{ "error" };
    // uint16_t metrics_port{ 0 }; // metric port (Grafana) (0: 비활성화)
  };

  struct SecurityTCP
  {
    uint32_t connection_limits{ 100000 };
    uint32_t connection_ip_limits{ 100 }; // 각 IP - 연결 제한
  };

  struct SecurityUDP
  {
    uint32_t connection_limits{ 50000 }; // 정확히 표현하자면: session_limits
    uint32_t pps_ip_limits{ 10000 };     // 각 IP - pps 제한 10kb
    uint32_t bps_ip_limits{ 10485760 };  // 각 IP - bps 제한 10mb
  };

  struct Security
  {
    SecurityTCP tcp;
    SecurityUDP udp;
  };

  struct PerformanceKernelSocket
  {
    /**
     * @see 리눅스의 디폴트 kernel buffer 사이즈를 보려면 cat 해봐용
     * recv: /proc/sys/net/core/rmem_default, /proc/sys/net/core/rmem_max,/proc/sys/net/ipv4/tcp_rmem
     * send(write): /proc/sys/net/core/wmem_default, /proc/sys/net/core/wmem_max, /proc/sys/net/ipv4/tcp_wmem
     */
    size_t recv_buffer_size{ 0 };
    size_t send_buffer_size{ 0 };
  };

  struct Performance
  {
    vector<int> cpu_affinity;
    PerformanceKernelSocket kernel_socket;
  };

  struct Config
  {
    vector<Route> routes;

    Options options;
    Performance performance;
    Security security;
  };

  class ConfigManager
  {
  private:
    atomic<shared_ptr<Config>> m_current{ make_shared<Config>() };
    atomic<uint64_t> m_version{ 0 };

    const regex m_regex_ipv4{ R"(^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)" };
    const regex m_regex_ipv6{ R"(^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$|^([0-9a-fA-F]{1,4}:)*::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$)" };
    const regex m_regex_domain{ R"(^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$)" };

    template <typename T>
    void yaml_bind( T& target, const YAML::Node& node, const optional<T>& default_value = nullopt )
    {
      if ( node && !node.IsNull() )
      {
        try
        {
          target = node.as<T>();
          return;
        }
        catch ( const YAML::Exception& )
        {
        }
      }

      if ( default_value.has_value() )
      {
        target = default_value.value();
      }
    }

    void str_to_lower( string& str )
    {
      transform( str.begin(), str.end(), str.begin(), ::tolower );

      str.erase( 0, str.find_first_not_of( " \t\n\r" ) );
      str.erase( str.find_last_not_of( " \t\n\r" ) + 1 );
    }

    bool compare( const string& src, const string& comp )
    {
      string src_copy = src, comp_copy = comp;

      str_to_lower( src_copy );
      str_to_lower( comp_copy );

      return src_copy == comp_copy;
    }

    bool is_empty( const string& str )
    {
      return str.empty() || str.find_first_not_of( " \t\n\r" ) == string::npos;
    }

    // [RFC-1035](https://www.rfc-editor.org/rfc/rfc1035.html)
    bool is_valid_hostname( const string& hostname )
    {
      if ( is_empty( hostname ) || hostname.length() > 253 )
      {
        return false;
      }

      try
      {
        return regex_match( hostname, m_regex_ipv4 ) || regex_match( hostname, m_regex_ipv6 ) || regex_match( hostname, m_regex_domain );
      }
      catch ( const regex_error& )
      {
        return false;
      }
    }

    bool is_valid_port( uint16_t port )
    {
      return port > 0 && port <= 65535;
    }

    void resolve_routes( Config& cfg )
    {
      for ( auto& route : cfg.routes )
      {
        addrinfo hints{}, *result = nullptr;

        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = compare( route.protocol, "tcp" ) ? SOCK_STREAM : SOCK_DGRAM;

        string port_str = to_string( route.dest_port_from );
        if ( getaddrinfo( route.dest_host.c_str(), port_str.c_str(), &hints, &result ) == 0 && result )
        {
          unique_ptr<addrinfo, decltype( &freeaddrinfo )> guard( result, freeaddrinfo );

          for ( auto* rp = result; rp; rp = rp->ai_next )
          {
            sockaddr_storage addr{};

            memcpy( &addr, rp->ai_addr, rp->ai_addrlen );
            route.resolved_addrs.push_back( addr );
          }
        }
      }
    }

  public:
    static ConfigManager& instance()
    {
      static ConfigManager singleton;
      return singleton;
    }

    bool load( const filesystem::path& fullpath )
    {
      if ( !filesystem::exists( fullpath ) )
      {
        return false;
      }

      try
      {
        auto config = make_shared<Config>();
        YAML::Node yaml = YAML::LoadFile( fullpath.string() );

        if ( yaml["routes"] )
        {
          for ( const auto& o : yaml["routes"] )
          {
            Route route;

            // ## ROUTE SOURCE HOST
            if ( o["port"] )
            {
              yaml_bind<uint16_t>( route.src_port_from, o["port"], 0 );
              route.src_port_to = route.src_port_from;
              route.is_single_port = true;
            }
            else if ( o["port_range"] )
            {
              auto ranges = o["port_range"];

              yaml_bind<uint16_t>( route.src_port_from, ranges["from"], 0 );
              yaml_bind<uint16_t>( route.src_port_to, ranges["to"], 0 );
              route.is_single_port = ( route.src_port_from == route.src_port_to );
            }

            if ( o["protocol"] )
            {
              yaml_bind<string>( route.protocol, o["protocol"], "tcp" );
            }

            if ( is_empty( route.protocol ) || ( !compare( route.protocol, "tcp" ) && !compare( route.protocol, "udp" ) ) )
            {
              route.protocol = "tcp";
            }

            // ## ROUTE DESTINATION
            if ( o["dest_host"] )
            {
              yaml_bind<string>( route.dest_host, o["dest_host"], "" );
            }

            if ( o["dest_port"] )
            {
              yaml_bind<uint16_t>( route.dest_port_from, o["dest_port"], 0 );
              route.dest_port_to = route.dest_port_from;
            }
            else if ( o["dest_port_range"] )
            {
              auto range = o["dest_port_range"];

              yaml_bind<uint16_t>( route.dest_port_from, range["from"], 0 );
              yaml_bind<uint16_t>( route.dest_port_to, range["to"], 0 );
            }

            if ( route.dest_port_from == 0 && route.dest_port_to == 0 )
            {
              route.dest_port_from = route.src_port_from;
              route.dest_port_to = route.src_port_to;
            }

            if ( route.dest_port_from != 0 && route.dest_port_to == 0 )
            {
              uint16_t src_range_size = route.src_port_to - route.src_port_from;
              route.dest_port_to = route.dest_port_from + src_range_size;
            }

            if ( route.src_port_from > route.src_port_to )
            {
              swap( route.src_port_from, route.src_port_to );
            }

            if ( route.dest_port_from > route.dest_port_to )
            {
              swap( route.dest_port_from, route.dest_port_to );
            }

            if ( route.src_port_from == route.src_port_to )
            {
              route.is_single_port = true;
            }

            if ( o["preserve_ip"] )
            {
              yaml_bind<bool>( route.is_preserve_ip, o["preserve_ip"], false );
            }

            // ## ROUTE VALIDATION
            uint16_t src_port_len = route.src_port_to - route.src_port_from;
            uint16_t dest_port_len = route.dest_port_to - route.dest_port_from;

            // clang-format off
            if ( is_empty( route.dest_host ) 
              || !is_valid_hostname( route.dest_host ) 
              || route.src_port_from == 0 
              || route.src_port_to == 0 
              || route.dest_port_from == 0 
              || route.dest_port_to == 0 
              || src_port_len != dest_port_len ) // clang-format on
            {
              route.is_correct = false;
            }
            else
            {
              route.is_correct = true;
            }

            if ( route.is_correct )
            {
              for ( const auto& existing : config->routes )
              {
                if ( route.src_port_from <= existing.src_port_to && route.src_port_to >= existing.src_port_from )
                {
                  route.is_correct = false;
                  break;
                }
              }
            }

            if ( !is_valid_port( route.src_port_from ) || !is_valid_port( route.src_port_to ) || !is_valid_port( route.dest_port_from ) || !is_valid_port( route.dest_port_to ) )
            {
              route.is_correct = false;
            }

            config->routes.push_back( move( route ) );
          }
        } // yml["routes"]

        if ( yaml["options"] )
        {
          auto options = yaml["options"];

          yaml_bind<uint32_t>( config->options.worker_threads, options["worker_threads"], 0 );
          yaml_bind<string>( config->options.log_level, options["log_level"], "error" );

          if ( options["connection"] )
          {
            auto connection = options["connection"];

            yaml_bind<uint32_t>( config->options.connection.idle_timeout, connection["idle_timeout"], 60000 );
            yaml_bind<uint32_t>( config->options.connection.connect_timeout, connection["connect_timeout"], 10000 );
            yaml_bind<uint32_t>( config->options.connection.shutdown_timeout, connection["shutdown_timeout"], 30000 );
          }
        }

        if ( yaml["security"] )
        {
          auto security = yaml["security"];

          if ( security["tcp"] )
          {
            auto tcp = security["tcp"];

            yaml_bind<uint32_t>( config->security.tcp.connection_limits, tcp["connection_limits"], 100000 );
            yaml_bind<uint32_t>( config->security.tcp.connection_ip_limits, tcp["connection_ip_limits"], 100 );
          }

          if ( security["udp"] )
          {
            auto udp = security["udp"];

            yaml_bind<uint32_t>( config->security.udp.connection_limits, udp["connection_limits"], 50000 );
            yaml_bind<uint32_t>( config->security.udp.pps_ip_limits, udp["pps_ip_limits"], 10000 );
            yaml_bind<uint32_t>( config->security.udp.bps_ip_limits, udp["bps_ip_limits"], 10485760 );
          }
        }

        if ( yaml["performance"] )
        {
          auto performance = yaml["performance"];

          if ( performance["cpu_affinity"] )
          {
            for ( const auto& cpu : performance["cpu_affinity"] )
            {
              int cpu_id = cpu.as<int>();

              if ( find( config->performance.cpu_affinity.begin(), config->performance.cpu_affinity.end(), cpu_id ) == config->performance.cpu_affinity.end() )
              {
                config->performance.cpu_affinity.push_back( cpu_id );
              }
            }
          }

          if ( performance["kernel_socket"] )
          {
            auto kernel_socket = performance["kernel_socket"];

            yaml_bind<size_t>( config->performance.kernel_socket.recv_buffer_size, kernel_socket["recv_buffer_size"], 0 );
            yaml_bind<size_t>( config->performance.kernel_socket.send_buffer_size, kernel_socket["send_buffer_size"], 0 );
          }
        }

        // 모든 route가 유효한지 검증
        bool all_routes_valid = true;
        for ( const auto& route : config->routes )
        {
          if ( !route.is_correct )
          {
            all_routes_valid = false;
            break;
          }
        }

        if ( !all_routes_valid )
        {
          return false;
        }

        resolve_routes( *config );

        auto old_version = m_version.load();
        m_current.store( config );
        m_version.store( old_version + 1 );

        return true;
      }
      catch ( const exception& )
      {
        return false;
      }
    }

    shared_ptr<Config> get() const
    {
      return m_current.load();
    }

    uint64_t version() const
    {
      return m_version.load();
    }
  };

} // namespace lite_through_proxy