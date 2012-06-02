require "ffi".cdef [[
enum
  {
    EPOLL_CLOEXEC = 02000000,
    EPOLL_NONBLOCK = 04000
  };
enum EPOLL_EVENTS
  {
    EPOLLIN = 0x001,
    EPOLLPRI = 0x002,
    EPOLLOUT = 0x004,
    EPOLLRDNORM = 0x040,
    EPOLLRDBAND = 0x080,
    EPOLLWRNORM = 0x100,
    EPOLLWRBAND = 0x200,
    EPOLLMSG = 0x400,
    EPOLLERR = 0x008,
    EPOLLHUP = 0x010,
    EPOLLRDHUP = 0x2000,
    EPOLLONESHOT = 1u << 30,
    EPOLLET = 1u << 31
  };
typedef union epoll_data
{
  void *ptr;
  int fd;
  uint32_t u32;
  uint64_t u64;
} epoll_data_t;
struct epoll_event
{
  uint32_t events;
  epoll_data_t data;
} __attribute__ ((__packed__));

extern int epoll_create (int __size) __attribute__ ((__nothrow__ , __leaf__));
extern int epoll_create1 (int __flags) __attribute__ ((__nothrow__ , __leaf__));
extern int epoll_ctl (int __epfd, int __op, int __fd,
        struct epoll_event *__event) __attribute__ ((__nothrow__ , __leaf__));
extern int epoll_wait (int __epfd, struct epoll_event *__events,
         int __maxevents, int __timeout);
extern int epoll_pwait (int __epfd, struct epoll_event *__events,
   int __maxevents, int __timeout,
   __const __sigset_t *__ss);
]]

module ( ... )

EPOLL_CTL_ADD = 1 ; -- Add a file decriptor to the interface.
EPOLL_CTL_DEL = 2	; -- Remove a file decriptor from the interface.
EPOLL_CTL_MOD = 3	; -- Change file decriptor epoll_event structure.

return _M
