#pragma once

#include <cstdint>

using namespace std;

namespace lite_passthrough_proxy
{

  class SecurityValidate
  {
    /**
     * RFC-1918
     * @link https://www.rfc-editor.org/rfc/rfc1918.html#section-3
     *
     */
  private:
    static constexpr uint32_t START_10 = 0x0A000000;  // 10.0.0.0/8
    static constexpr uint32_t START_172 = 0xAC100000; // 172.16.0.0/12
    static constexpr uint32_t START_192 = 0xC0A80000; // 192.168.0.0/16
    static constexpr uint32_t LBACK = 0x7F000000;     // 127.0.0.0/8
    static constexpr uint32_t MCAST = 0xE0000000;     // 224.0.0.0/4

  public:
    static bool ip_spoof_attack( uint32_t addr, bool is_allow_private_ip = false )
    {
      return true;
    }
  };

} // namespace lite_passthrough_proxy