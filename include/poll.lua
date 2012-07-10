require "ffi".cdef [[
typedef unsigned long int nfds_t;
struct pollfd
  {
    int fd;
    short int events;
    short int revents;
  };

extern int poll (struct pollfd *__fds, nfds_t __nfds, int __timeout);
]]

module ( ... )

POLLIN = 0x001 -- There is data to read.
POLLPRI = 0x002 -- There is urgent data to read.
POLLOUT = 0x004 -- Writing now will not block.

-- These values are defined in XPG4.2.
POLLRDNORM = 0x040 -- Normal data may be read.
POLLRDBAND = 0x080 -- Priority data may be read.
POLLWRNORM = 0x100 -- Writing now will not block.
POLLWRBAND = 0x200 -- Priority data may be written.

-- These are extensions for Linux.
POLLMSG = 0x400
POLLREMOVE = 0x1000
POLLRDHUP = 0x2000

--[[Event types always implicitly polled for.  These bits need not be set in
    `events', but they will appear in `revents' to indicate the status of
    the file descriptor.]]
POLLERR = 0x008 -- Error condition.
POLLHUP = 0x010 -- Hung up.
POLLNVAL = 0x020 -- Invalid polling request.

return _M
