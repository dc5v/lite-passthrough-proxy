#pragma once

#include <algorithm>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <netdb.h>
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
    string protocol;
    uint16_t src_port_from;
    uint16_t src_port_to;
    string dest_host;
    uint16_t dest_port;

    bool preserve_ip{ false }; // preserve, forwarding origin client IP
    vector<sockaddr_storage> resolved_addrs;

    bool is_correct{ false };
  };

  struct OptionConnection
  {
    uint32_t idle_timeout{ 60000 };
    uint32_t connect_timeout{ 10000 };
    uint32_t shutdown_timeout{ 30000 };
  };

  struct Options
  {
    uint32_t worker_threads{ 0 }; // Worker threads (0 = 힘닿는데까지쥐어짜용)
    string log_level{ "error" };
    // uint16_t metrics_port{ 0 }; // metric port (Grafana) (0: 비활성화)

    OptionConnection connection;
  };

  struct SecurityTCP
  {
    uint32_t connection_limits{ 100000 };
    uint32_t connection_ip_limits{ 1000 };
  };

  struct SecurityUDP
  {
    uint32_t connection_limits{ 50000 }; // 정확히 표현하자면: session_limits
    uint32_t pps_ip_limits{ 10000 };
    uint32_t bps_ip_limits{ 10485760 };
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
     * receive: /proc/sys/net/core/rmem_default, /proc/sys/net/core/rmem_max,/proc/sys/net/ipv4/tcp_rmem
     * write: /proc/sys/net/core/wmem_default, /proc/sys/net/core/wmem_max, /proc/sys/net/ipv4/tcp_wmem
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
    atomic<shared_ptr<Config>> m_current{ make_shared<Config>() };
    atomic<uint64_t> m_version{ 0 };

    bool compare( const string& src, const string& comp )
    {
      auto to_lower_trim = []( string& str )
      {
        transform( str.begin(), str.end(), str.begin(), ::tolower );
        str.erase( 0, str.find_first_not_of( " \t\n\r" ) );
        str.erase( str.find_last_not_of( " \t\n\r" ) + 1 );
      };

      string src_copy = src, comp_copy = comp;

      to_lower_trim( src_copy );
      to_lower_trim( comp_copy );

      return src_copy == comp_copy;
    }

    void resolve_routes( Config& cfg )
    {
      for ( auto& route : cfg.routes )
      {
        addrinfo hints{}, *result;

        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = compare( route.protocol, "tcp" ) ? SOCK_STREAM : SOCK_DGRAM;

        string port_str = to_string( route.dest_port );

        if ( getaddrinfo( route.dest_host.c_str(), port_str.c_str(), &hints, &result ) == 0 )
        {
          for ( auto* rp = result; rp; rp = rp->ai_next )
          {
            sockaddr_storage addr{};

            memcpy( &addr, rp->ai_addr, rp->ai_addrlen );
            route.resolved_addrs.push_back( addr );
          }

          freeaddrinfo( result );
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
      auto config = make_shared<Config>();
      YAML::Node yml = YAML::LoadFile( fullpath.string() );

      if ( yml["routes"] )
      {
        for ( const auto& o : yml["routes"] )
        {
          Route route;

          if ( o["port"] )
          {
            route.src_port_from = route.src_port_to = o["port"].as<uint16_t>();
          }
          else if ( o["port_range"] )
          {
            auto ranges = o["port_range"];

            if ( ranges["from"] )
            {
              route.src_port_from = ranges["from"].as<uint16_t>();
            }

            if ( ranges["to"] )
            {
              route.src_port_to = ranges["to"].as<uint16_t>();
            }
          }

          if ( o["protocol"] )
          {
            route.protocol = o["protocol"].as<string>();

            if ( !compare( route.protocol, "tcp" ) && !compare( route.protocol, "udp" ) )
            {
              route.protocol = "tcp";
            }
          }

          if ( o["dest_host"] )
          {
            route.dest_host = o["dest_host"].as<uint16_t>();
          }

          if ( o["dest_port"] )
          {
            route.dest_port = o["dest_port"].as<uint16_t>();
          }
          else
          {
            route.dest_port = uint16_t( 0 );
          }

          if ( o["preserve_ip"] )
          {
            route.preserve_ip = o["preserve_ip"].as<bool>();
          }

          config->routes.push_back( move( route ) );
        }
      }

      if ( yml["options"] )
      {
        auto options = yml["options"];

        if ( options["worker_threads"] )
        {
          config->options.worker_threads = options["worker_threads"].as<uint32_t>();
        }

        if ( options["connection"] )
        {
          auto connection = options["connection"];

          if ( connection["idle_timeout"] )
          {
            config->options.connection.idle_timeout = connection["idle_timeout"].as<uint32_t>();
          }

          if ( connection["connect_timeout"] )
          {
            config->options.connection.connect_timeout = connection["connect_timeout"].as<uint32_t>();
          }

          if ( connection["shutdown_timeout"] )
          {
            config->options.connection.shutdown_timeout = connection["shutdown_timeout"].as<uint32_t>();
          }
        }

        if ( options["log_level"] )
        {
          config->options.log_level = options["log_level"].as<string>();
        }

        /*
        if ( opts["metrics_port"] )
        {
          cfg->options.metrics_port = opts["metrics_port"].as<uint16_t>();
        }
        */
      }


      if ( yml["security"] )
      {
        auto security = yml["security"];

        if ( security["tcp"] )
        {
          auto tcp = security["tcp"];

          if ( tcp["connection_limits"] )
          {
            config->security.tcp.connection_limits = tcp["connection_limits"].as<uint32_t>();
          }

          if ( tcp["connection_ip_limits"] )
          {
            config->security.tcp.connection_ip_limits = tcp["connection_ip_limits"].as<uint32_t>();
          }
        }

        if ( security["udp"] )
        {
          auto udp = security["udp"];

          if ( udp["connection_limits"] )
          {
            config->security.udp.connection_limits = udp["connection_limits"].as<uint32_t>();
          }

          if ( udp["pps_ip_limits"] )
          {
            config->security.udp.pps_ip_limits = udp["pps_ip_limits"].as<uint32_t>();
          }

          if ( udp["bps_ip_limits"] )
          {
            config->security.udp.bps_ip_limits = udp["bps_ip_limits"].as<uint32_t>();
          }
        }
      }

      if ( yml["performance"] )
      {
        auto performance = yml["performance"];

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

          if ( kernel_socket["recv_buffer_size"] )
          {
            config->performance.kernel_socket.recv_buffer_size = kernel_socket["recv_buffer_size"].as<uint32_t>();
          }

          if ( kernel_socket["send_buffer_size"] )
          {
            config->performance.kernel_socket.send_buffer_size = kernel_socket["send_buffer_size"].as<uint32_t>();
          }
        }
      }

      resolve_routes( *config );

      m_current.store( config );
      m_version++;

      return true;
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