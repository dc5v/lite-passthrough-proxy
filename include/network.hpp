#pragma once

#include <array>
#include <fcntl.h>
#include <span>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "pool/mem_pool.hpp"
#include "pool/pools.hpp"

using namespace std;

namespace lite_passthrough_proxy
{
  /**
   * Batch network I/O class for UDP
   * 
   */
  template <size_t BATCH_SIZE = 256> class UdpBatchNetworkIO
  {
  private:
    static thread_local inline BatchBuffer m_batch_buffer;

    struct alignas( 64 ) BatchBuffer
    {
      array<span<byte>, BATCH_SIZE> buffers;
      array<sockaddr_storage, BATCH_SIZE> addresses;
      array<socklen_t, BATCH_SIZE> address_lengths;
      array<ssize_t, BATCH_SIZE> bytes_received_array;

      BatchBuffer()
      {
        for ( size_t i = 0; i < BATCH_SIZE; ++i )
        {
          address_lengths[i] = sizeof( sockaddr_storage );
          bytes_received_array[i] = 0;
        }
      }
    };

  public:
    static sockaddr_storage& gte_address( size_t i ) noexcept
    {
      return m_batch_buffer.addresses[i];
    }

    static size_t get_buffer_size( size_t i ) noexcept
    {
      return static_cast<size_t>( m_batch_buffer.bytes_received_array[i] );
    }

    static span<byte>& get_buffer( size_t i ) noexcept
    {
      return m_batch_buffer.buffers[i];
    }

    static int receive( int fd ) noexcept
    {
      int count = 0;

      for ( size_t i = 0; i < BATCH_SIZE; ++i )
      {
        m_batch_buffer.buffers[i] = PacketPool.acquire();

        if ( m_batch_buffer.buffers[i].empty() )
        {
          return 0;
        }

        m_batch_buffer.address_lengths[i] = sizeof( sockaddr_storage );

        ssize_t bytes = recvfrom( fd, m_batch_buffer.buffers[i].data(), m_batch_buffer.buffers[i].size(), MSG_DONTWAIT, reinterpret_cast<sockaddr*>( &m_batch_buffer.addresses[i] ), &m_batch_buffer.address_lengths[i] );

        if ( bytes < 0 )
        {
          if ( errno == EAGAIN || errno == EWOULDBLOCK )
          {
            PacketPool.release( m_batch_buffer.buffers[i] );
            return count;
          }

          PacketPool.release( m_batch_buffer.buffers[i] );
          return -1;
        }

        m_batch_buffer.bytes_received_array[i] = bytes;
        ++count;
      }

      return count;
    }


    static int send( int fd, int count ) noexcept
    {
      int sent_count = 0;

      for ( int i = 0; i < count; ++i )
      {

        ssize_t bytes = sendto( fd, m_batch_buffer.buffers[i].data(), m_batch_buffer.bytes_received_array[i], 0, reinterpret_cast<const sockaddr*>( &m_batch_buffer.addresses[i] ), m_batch_buffer.address_lengths[i] );

        if ( bytes < 0 )
        {
          if ( errno == EAGAIN || errno == EWOULDBLOCK )
          {
            return sent_count;
          }

          return -1;
        }

        ++sent_count;
      }

      return sent_count;
    }


    static void released( int count ) noexcept
    {
      for ( int i = 0; i < count; ++i )
      {
        PacketPool.release( m_batch_buffer.buffers[i] );
      }
    }


    static void prepare( size_t i, const sockaddr_storage& dest_address, socklen_t dest_len ) noexcept
    {
      m_batch_buffer.addresses[i] = dest_address;
      m_batch_buffer.address_lengths[i] = dest_len;
    }
  };


  class PassThroughTransfer
  {
  public:
    static ssize_t splice_data( int from_fd, int to_fd, size_t len = 65536 ) noexcept
    {
      return splice( from_fd, nullptr, to_fd, nullptr, len, SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_NONBLOCK );
    }

    static ssize_t sendfile_data( int out_fd, int in_fd, size_t count ) noexcept
    {
      return sendfile( out_fd, in_fd, nullptr, count );
    }
  };

} // namespace lite_passthrough_proxy
