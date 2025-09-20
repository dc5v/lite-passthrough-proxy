#pragma once

#include <cstdint>

using namespace std;

namespace lite_passthrough_proxy
{
  class SecurityRatelimit
  {
  private:
    static constexpr size_t BUCKET = 65536;

  public:
    SecurityRatelimit( uint64_t rate, uint64_t maximum ) {}
  };

} // namespace lite_passthrough_proxy