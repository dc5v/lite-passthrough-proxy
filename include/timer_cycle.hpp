#pragma once

#include <array>
#include <chrono>
#include <functional>
#include <list>
#include <mutex>
#include <atomic>

using namespace std;

namespace lite_passthrough_proxy
{
  static constexpr size_t TICK_DURATION_MS = 100;

  using Clock = chrono::steady_clock;
  using TimePoint = Clock::time_point;
  using Callback = function<void()>;

  class TimerCycle
  {
  private:
    mutable mutex m_mutex;

    atomic<uint32_t> m_timer_id{ 0 };

    struct Timer
    {
      uint32_t id;
      TimePoint expired_time;
      Callback callback;
    };
  };

} // namespace lite_passthrough_proxy