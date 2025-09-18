#pragma once

#include <array>
#include <atomic>
#include <bit>
#include <cstddef>
#include <span>

using namespace std;

namespace lite_through_proxy
{
  // Cache optimize - using alignas( 64 )
  // @see `cat /sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size`

  template <size_t BLOCK_SIZE = 65536, size_t POOL_SIZE = 1024> class alignas( 64 ) MemPool
  {
  private:
    static_assert( has_single_bit( PoolSize ), "PoolSize must be ^2" );
    static_assert( BlockSize % 64 == 0, "BlockSize must be ^64" );


    struct alignas( 64 ) Block
    {
      alignas( 64 ) byte data[BLOCK_SIZE];
      atomic<uint64_t> epoch{ 0 }; // fixed uint32_t -> uint64_t 엠병 오버플로날뻔 🫩
      atomic<bool> in_use{ false };
    };

    alignas( 64 ) array<Block, PoolSize> m_pool;
    alignas( 64 ) atomic<uint64_t> m_free_bitmap[POOL_SIZE / 64];
    alignas( 64 ) atomic<uint64_t> m_alloc_counter{ 0 };

  public:
    MemPool()
    {
      for ( auto &o : m_free_bitmap )
      {
        o.store( ~0ULL, memory_order_relaxed );
      }
    }

    [[nodiscard]] span<byte> acquire() noexcept
    {
      const uint64_t ticket = m_alloc_counter.fetch_add( 1, memory_order_relaxed );
      const size_t start = ticket & ( POOL_SIZE - 1 );

      for ( size_t attempts = 0; attempts < POOL_SIZE; ++attempts )
      {
        const size_t i = ( start + attempts ) & ( POOL_SIZE - 1 );
        const size_t idx = i / 64;
        const uint64_t mask = 1ULL << ( i % 64 );

        uint64_t now = m_free_bitmap[idx].load( memory_order_acquire );
        while ( now & mask )
        {
          if ( m_free_bitmap[idx].compare_exchange_weak( now, now & ~mask, memory_order_acq_rel, memory_order_acquire ) )
          {
            auto &block = m_pool[i];

            block.in_use.store( true, memory_order_release );
            block.epoch.fetch_add( 1, memory_order_acq_rel );

            return { block.data, BLOCK_SIZE };
          }
        }
      }

      return {};
    }

    void release( span<byte> block ) noexcept
    {
      if ( block.empty() )
      {
        return;
      }

      const auto *ptr = block.data();
      const size_t offset = ptr - reinterpret_cast<byte *>( &m_pool[0] );
      const size_t i = offset / sizeof( Block );

      if ( i >= POOL_SIZE ) // Check pool size range
      {
        return;
      }

      auto &target_block = m_pool[i];
      bool expected = true;

      // Check duplicate free exception
      if ( !target_block.in_use.compare_exchange_strong( expected, false, memory_order_acq_rel ) )
      {
        return;
      }

      const size_t bitmap_idx = i / 64;
      const uint64_t bit = 1ULL << ( i % 64 );

      // bitmap update
      atomic_thread_fence( memory_order_release );
      m_free_bitmap[bitmap_idx].fetch_or( bit, memory_order_release );
    }

    bool is_valid_block( span<byte> block ) const noexcept
    {
      if ( block.empty() || block.size() != BLOCK_SIZE )
      {
        return false;
      }

      const auto *ptr = block.data();
      const size_t offset = ptr - reinterpret_cast<const byte *>( &m_pool[0] );
      const size_t idx = offset / sizeof( Block );

      return idx < POOL_SIZE && reinterpret_cast<const byte *>( &m_pool[idx].data[0] ) == ptr;
    }
  };

  thread_local inline MemPool<> packet_pool;

} // namespace lite_through_proxy