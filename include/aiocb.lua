include "sys/types"
include "time"
include "signal"

ffi.cdef [[
struct aiocb
{
  int aio_fildes;
  int aio_lio_opcode;
  int aio_reqprio;
  volatile void *aio_buf;
  size_t aio_nbytes;
  struct sigevent aio_sigevent;
  struct aiocb *__next_prio;
  int __abs_prio;
  int __policy;
  int __error_code;
  __ssize_t __return_value;
  __off_t aio_offset;
  char __pad[sizeof (__off64_t) - sizeof (__off_t)];
  char __unused[32];
};
enum
{
  AIO_CANCELED,
  AIO_NOTCANCELED,
  AIO_ALLDONE
};
enum
{
  LIO_READ,
  LIO_WRITE,
  LIO_NOP
};
enum
{
  LIO_WAIT,
  LIO_NOWAIT
};
extern int aio_read (struct aiocb *__aiocbp) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int aio_write (struct aiocb *__aiocbp) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int lio_listio (int __mode,
         struct aiocb *const __list[__restrict],
         int __nent, struct sigevent *__restrict __sig)
  __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2)));
extern int aio_error (const struct aiocb *__aiocbp) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern __ssize_t aio_return (struct aiocb *__aiocbp) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int aio_cancel (int __fildes, struct aiocb *__aiocbp) __attribute__ ((__nothrow__ , __leaf__));
extern int aio_suspend (const struct aiocb *const __list[], int __nent,
   const struct timespec *__restrict __timeout)
  __attribute__ ((__nonnull__ (1)));
extern int aio_fsync (int __operation, struct aiocb *__aiocbp)
  __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2)));
]]
