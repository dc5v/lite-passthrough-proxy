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
  class SecurityRatelimit
  {
  private:
    struct alignas( 64 ) Bucket
    {
      atomic<uint64_t> tokens;
      atomic<int64_t> last_refill_ns;
    };

    static constexpr size_t BUCKET_COUNT = 65536; // ^2
    alignas( 64 ) array<Bucket, BUCKET_COUNT> m_buckets;

    uint64_t m_rate;  // tokens/1sec
    uint64_t m_burst; // burst size

    static uint32_t address_hash( const sockaddr_storage& addr ) noexcept
    {
      uint32_t hash = 0;

      if ( addr.ss_family == AF_INET )
      {
        auto* sin = reinterpret_cast<const sockaddr_in*>( &addr );
        hash = sin->sin_addr.s_addr;
        hash ^= sin->sin_port;
      }
      else if ( addr.ss_family == AF_INET6 )
      {
        auto* sin6 = reinterpret_cast<const sockaddr_in6*>( &addr );
        hash = sin6->sin6_addr.s6_addr32[0];
        hash ^= sin6->sin6_addr.s6_addr32[1];
        hash ^= sin6->sin6_addr.s6_addr32[2];
        hash ^= sin6->sin6_addr.s6_addr32[3];
        hash ^= sin6->sin6_port;
      }

      hash ^= ( hash >> 16 );
      hash *= 0x85ebca6b;
      hash ^= ( hash >> 13 );
      hash *= 0xc2b2ae35;
      hash ^= ( hash >> 16 );

      return hash & ( BUCKET_COUNT - 1 );
    }

  public:
    SecurityRatelimit( uint64_t rate, uint64_t burst ) : m_rate( rate ), m_burst( burst )
    {
      for ( auto& bucket : m_buckets )
      {
        bucket.tokens.store( burst, memory_order_relaxed );
        bucket.last_refill_ns.store( 0, memory_order_relaxed );
      }
    }

    bool eat( const sockaddr_storage& addr, uint64_t tokens = 1 ) noexcept
    {
      auto& bucket = m_buckets[address_hash( addr )];

      auto now_ns = chrono::steady_clock::now().time_since_epoch().count();

      int64_t last_refill = bucket.last_refill_ns.load( memory_order_acquire );
      if ( last_refill > 0 )
      {
        int64_t elapsed_ns = now_ns - last_refill;
        if ( elapsed_ns > 0 )
        {
          uint64_t new_tokens = ( elapsed_ns * m_rate ) / 1'000'000'000;

          if ( new_tokens > 0 )
          {
            uint64_t current = bucket.tokens.load( memory_order_acquire );
            uint64_t updated = min( m_burst, current + new_tokens );

            bucket.tokens.compare_exchange_weak( current, updated, memory_order_acq_rel, memory_order_acquire );
            bucket.last_refill_ns.store( now_ns, memory_order_release );
          }
        }
      }
      else
      {
        bucket.last_refill_ns.store( now_ns, memory_order_release );
      }

      uint64_t current = bucket.tokens.load( memory_order_acquire );
      while ( current >= tokens )
      {
        if ( bucket.tokens.compare_exchange_weak( current, current - tokens, memory_order_acq_rel, memory_order_acquire ) )
        {
          return true;
        }
      }

      return false;
    }

    uint64_t tokens( const sockaddr_storage& addr ) const noexcept
    {
      const auto& bucket = m_buckets[address_hash( addr )];
      return bucket.tokens.load( memory_order_relaxed );
    }

    void reset() noexcept
    {
      for ( auto& bucket : m_buckets )
      {
        bucket.tokens.store( m_burst, memory_order_relaxed );
        bucket.last_refill_ns.store( 0, memory_order_relaxed );
      }
    }
  };
} // namespace lite_passthrough_proxy