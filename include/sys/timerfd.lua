require "include.time"

require"ffi".cdef [[
enum
  {
    TFD_CLOEXEC = 02000000,
    TFD_NONBLOCK = 04000
  };
enum
  {
    TFD_TIMER_ABSTIME = 1 << 0
  };

extern int timerfd_create (clockid_t __clock_id, int __flags) __attribute__ ((__nothrow__ , __leaf__));
extern int timerfd_settime (int __ufd, int __flags,
       __const struct itimerspec *__utmr,
       struct itimerspec *__otmr) __attribute__ ((__nothrow__ , __leaf__));
extern int timerfd_gettime (int __ufd, struct itimerspec *__otmr) __attribute__ ((__nothrow__ , __leaf__));
]]
