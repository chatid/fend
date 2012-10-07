include "sys/types"

ffi.cdef[[
extern ssize_t sendfile (int __out_fd, int __in_fd, off_t *__offset,
    size_t __count) __attribute__ ((__nothrow__ , __leaf__));
extern ssize_t sendfile64 (int __out_fd, int __in_fd, __off64_t *__offset,
      size_t __count) __attribute__ ((__nothrow__ , __leaf__));
]]
