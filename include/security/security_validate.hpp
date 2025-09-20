#pragma once

#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <netinet/in.h>

using namespace std;

namespace lite_passthrough_proxy
{
  class SecurityValidate
  {
  private:
    static constexpr uint32_t PRIVATE_10 = 0x0A000000;  // 10.0.0.0
    static constexpr uint32_t PRIVATE_172 = 0xAC100000; // 172.16.0.0
    static constexpr uint32_t PRIVATE_192 = 0xC0A80000; // 192.168.0.0
    static constexpr uint32_t LOOPBACK = 0x7F000000;    // 127.0.0.0
    static constexpr uint32_t MULTICAST = 0xE0000000;   // 224.0.0.0

  public:
    static bool ip_spoof_attack( const sockaddr_storage& address, bool is_allow_private_ip = false ) noexcept
    {
      /**
       * ====
       * IPv4
       * ====
       */
      if ( address.ss_family == AF_INET )
      {
        auto* sin = reinterpret_cast<const sockaddr_in*>( &address );
        uint32_t ip = ntohl( sin->sin_addr.s_addr );

        // loopback
        if ( ( ip & 0xFF000000 ) == LOOPBACK )
        {
          return false;
        }

        // multicast
        if ( ( ip & 0xF0000000 ) == MULTICAST )
        {
          return false;
        }

        // private addresses
        if ( !is_allow_private_ip )
        {
          if ( ( ip & 0xFF000000 ) == PRIVATE_10 || ( ip & 0xFFF00000 ) == PRIVATE_172 || ( ip & 0xFFFF0000 ) == PRIVATE_192 )
          {
            return false;
          }
        }

        // 0.0.0.0, 255.255.255.255
        if ( ip == 0 || ip == 0xFFFFFFFF )
        {
          return false;
        }
      }
      /**
       * ====
       * IPv6
       * ====
       *
       */
      else if ( address.ss_family == AF_INET6 )
      {
        auto* sin6 = reinterpret_cast<const sockaddr_in6*>( &address );

        // loopback (::1)
        static const uint8_t loopback[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
        if ( memcmp( &sin6->sin6_addr, loopback, 16 ) == 0 )
        {
          return false;
        }

        if ( !is_allow_private_ip )
        {
          // private address (fc00::)
          if ( ( sin6->sin6_addr.s6_addr[0] & 0xFE ) == 0xFC )
          {
            return false;
          }

          // local address (fe80::)
          if ( sin6->sin6_addr.s6_addr[0] == 0xFE && ( sin6->sin6_addr.s6_addr[1] & 0xC0 ) == 0x80 )
          {
            return false;
          }
        }

        // (::)
        static const uint8_t unspecified[16] = { 0 };
        if ( memcmp( &sin6->sin6_addr, unspecified, 16 ) == 0 )
        {
          return false;
        }
      }
      /**
       * ====
       * Unknown address family
       * ====
       *
       */
      else
      {
        return false;
      }

      return true;
    }
  };

} // namespace lite_passthrough_proxy