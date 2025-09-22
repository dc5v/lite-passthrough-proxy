#pragma once

#include <array>
#include <cstddef>
#include <cstring>
#include <fcntl.h>
#include <span>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include "pool/mem_pool.hpp"

using namespace std;

namespace LitePassthroughProxy
{
  namespace Network
  {
    /**
     * -----
     * BatchIO
     *
     */
    template <size_t BATCH_SIZE = 256> class BatchIO
    {
    private:
      struct alignas( 64 ) BatchBuffer
      {
        array<mmsghdr, BATCH_SIZE> msgs;
        array<iovec, BATCH_SIZE> iovecs; // 오버헤드를 줄이기위해 I/O Vectors 를 써용
        array<sockaddr_storage, BATCH_SIZE> addrs;
        array<span<byte>, BATCH_SIZE> buffers;
        size_t active_count{ 0 };

        BatchBuffer()
        {
          for ( size_t i = 0; i < BATCH_SIZE; ++i )
          {
            msgs[i].msg_hdr.msg_name = &addrs[i];
            msgs[i].msg_hdr.msg_namelen = sizeof( sockaddr_storage );
            msgs[i].msg_hdr.msg_iov = &iovecs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_control = nullptr;
            msgs[i].msg_hdr.msg_controllen = 0;
            msgs[i].msg_hdr.msg_flags = 0;
          }
        }

        ~BatchBuffer()
        {
          for ( size_t i = 0; i < active_count; ++i )
          {
            if ( !buffers[i].empty() )
            {
              packet_pool<>.release( buffers[i] );
            }
          }
        }
      };

      thread_local static inline BatchBuffer m_batch;

    public:
      static int receive_batch( int fd ) noexcept
      {
        for ( size_t i = 0; i < m_batch.active_count; ++i )
        {
          if ( !m_batch.buffers[i].empty() )
          {
            packet_pool<>.release( m_batch.buffers[i] );
            m_batch.buffers[i] = {};
          }
        }

        size_t allocated = 0;
        for ( size_t i = 0; i < BATCH_SIZE; ++i )
        {
          m_batch.buffers[i] = packet_pool<>.acquire();
          if ( m_batch.buffers[i].empty() )
          {
            break;
          }

          m_batch.iovecs[i].iov_base = m_batch.buffers[i].data();
          m_batch.iovecs[i].iov_len = m_batch.buffers[i].size();
          allocated++;
        }

        if ( allocated == 0 )
        {
          return -1;
        }

        int count = recvmmsg( fd, m_batch.msgs.data(), allocated, MSG_DONTWAIT, nullptr );
        m_batch.active_count = ( count > 0 ) ? count : 0;

        return count;
      }

      static int send_batch( int fd, int count ) noexcept
      {
        if ( count <= 0 || count > static_cast<int>( BATCH_SIZE ) )
        {
          return 0;
        }

        return sendmmsg( fd, m_batch.msgs.data(), count, 0 );
      }

      /**
       * ---------------
       * PREPARE BEFORE SEND
       *
       */
      static bool prepare( size_t i, const void* data, size_t len, const sockaddr_storage* address ) noexcept
      {
        if ( i >= BATCH_SIZE )
        {
          return false;
        }

        if ( m_batch.buffers[i].empty() )
        {
          m_batch.buffers[i] = packet_pool<>.acquire();
          if ( m_batch.buffers[i].empty() )
          {
            return false;
          }
        }

        size_t copy_len = min( len, m_batch.buffers[i].size() );
        memcpy( m_batch.buffers[i].data(), data, copy_len );

        m_batch.iovecs[i].iov_base = m_batch.buffers[i].data();
        m_batch.iovecs[i].iov_len = copy_len;

        if ( address )
        {
          m_batch.addrs[i] = *address;
          m_batch.msgs[i].msg_hdr.msg_namelen = ( address->ss_family == AF_INET ) ? sizeof( sockaddr_in ) : sizeof( sockaddr_in6 );
        }

        return true;
      }

      /**
       * ---------------
       * RELEASE BUFFERS
       *
       */
      static void release() noexcept
      {
        for ( size_t i = 0; i < m_batch.active_count; ++i )
        {
          if ( !m_batch.buffers[i].empty() )
          {
            packet_pool<>.release( m_batch.buffers[i] );
            m_batch.buffers[i] = {};
          }
        }

        m_batch.active_count = 0;
      }

      /**
       * ---------------
       * GETTTERS
       *
       */
      static mmsghdr& get_msg( size_t idx ) noexcept
      {
        return m_batch.msgs[idx];
      }

      static sockaddr_storage& get_addr( size_t idx ) noexcept
      {
        return m_batch.addrs[idx];
      }

      static span<byte> get_buffer( size_t idx ) noexcept
      {
        return m_batch.buffers[idx];
      }

      static size_t get_received_bytes( size_t idx ) noexcept
      {
        return m_batch.msgs[idx].msg_len;
      }

      static size_t get_active_count() noexcept
      {
        return m_batch.active_count;
      }
    };

    /**
     * ---------------
     * Zerocopy Utils
     *
     */
    class ZeroCopyTransfer
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

      static ssize_t vmsplice_data( int fd, const iovec* iov, size_t nr_segs ) noexcept
      {
        return vmsplice( fd, iov, nr_segs, SPLICE_F_GIFT | SPLICE_F_NONBLOCK );
      }
    };
  } // namespace Network

} // namespace LitePassthroughProxy