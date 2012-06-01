require "ffi".cdef [[
extern int fcntl (int __fd, int __cmd, ...);
extern int open (__const char *__file, int __oflag, ...) __attribute__ ((__nonnull__ (1)));
extern int openat (int __fd, __const char *__file, int __oflag, ...)
     __attribute__ ((__nonnull__ (2)));
extern int creat (__const char *__file, __mode_t __mode) __attribute__ ((__nonnull__ (1)));
extern int lockf (int __fd, int __cmd, __off_t __len);
extern int posix_fadvise (int __fd, __off_t __offset, __off_t __len,
     int __advise) __attribute__ ((__nothrow__ , __leaf__));
extern int posix_fallocate (int __fd, __off_t __offset, __off_t __len);
]]

local tonumber = tonumber
module ( ... )
F_RDLCK = 0
F_EXLCK = 4
F_GETLK = 5
F_DUPFD = 0
F_UNLCK = 2
F_SHLCK = 8
F_GETFD = 1
F_GETFL = 3
F_LOCK = 1
F_SETLKW64 = 7
F_SETOWN = 8
F_ULOCK = 0
F_SETFL = 4
F_OK = 0
F_GETOWN = 9
F_SETLK = 6
F_WRLCK = 1
F_SETLK64 = 6
F_TLOCK = 2
F_TEST = 3
F_DUPFD_CLOEXEC = 1030
F_GETLK64 = 5
F_SETLKW = 7
F_SETFD = 2

O_NOCTTY = tonumber("0400",8)
O_ACCMODE = tonumber("0003",8)
O_APPEND = tonumber("02000",8)
O_NDELAY = O_NONBLOCK
O_WRONLY = tonumber("01",8)
O_FSYNC = tonumber("O_SYNC",8)
O_NONBLOCK = tonumber("04000",8)
O_RSYNC = tonumber("O_SYNC",8)
O_DSYNC = tonumber("010000",8)
O_RDWR = tonumber("02",8)
O_SYNC = tonumber("04010000",8)
O_CLOEXEC = tonumber("02000000",8)
O_CREAT = tonumber("0100",8)
O_ASYNC = tonumber("020000",8)
O_RDONLY = tonumber("00",8)
O_TRUNC = tonumber("01000",8)
O_EXCL = tonumber("0200",8)
O_NOFOLLOW = tonumber("0400000",8)
O_DIRECTORY = tonumber("0200000",8)

return _M
