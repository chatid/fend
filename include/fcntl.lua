include "sys.types"

ffi.cdef [[
struct flock
  {
    short int l_type;
    short int l_whence;
    __off_t l_start;
    __off_t l_len;
    __pid_t l_pid;
  };
struct flock64
  {
    short int l_type;
    short int l_whence;
    __off64_t l_start;
    __off64_t l_len;
    __pid_t l_pid;
  };
enum __pid_type
  {
    F_OWNER_TID = 0,
    F_OWNER_PID,
    F_OWNER_PGRP,
    F_OWNER_GID = F_OWNER_PGRP
  };
struct f_owner_ex
  {
    enum __pid_type type;
    __pid_t pid;
  };
struct file_handle
{
  unsigned int handle_bytes;
  int handle_type;
  unsigned char f_handle[0];
};

extern ssize_t readahead (int __fd, __off64_t __offset, size_t __count)
    __attribute__ ((__nothrow__ , __leaf__));
extern int sync_file_range (int __fd, __off64_t __offset, __off64_t __count,
       unsigned int __flags);
extern ssize_t vmsplice (int __fdout, const struct iovec *__iov,
    size_t __count, unsigned int __flags);
extern ssize_t splice (int __fdin, __off64_t *__offin, int __fdout,
         __off64_t *__offout, size_t __len,
         unsigned int __flags);
extern ssize_t tee (int __fdin, int __fdout, size_t __len,
      unsigned int __flags);
extern int fallocate (int __fd, int __mode, __off_t __offset, __off_t __len);
extern int fallocate64 (int __fd, int __mode, __off64_t __offset,
   __off64_t __len);
extern int name_to_handle_at (int __dfd, const char *__name,
         struct file_handle *__handle, int *__mnt_id,
         int __flags) __attribute__ ((__nothrow__ , __leaf__));
extern int open_by_handle_at (int __mountdirfd, struct file_handle *__handle,
         int __flags);

struct stat
  {
    __dev_t st_dev;
    __ino_t st_ino;
    __nlink_t st_nlink;
    __mode_t st_mode;
    __uid_t st_uid;
    __gid_t st_gid;
    int __pad0;
    __dev_t st_rdev;
    __off_t st_size;
    __blksize_t st_blksize;
    __blkcnt_t st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    __syscall_slong_t __unused[3];
  };
struct stat64
  {
    __dev_t st_dev;
    __ino64_t st_ino;
    __nlink_t st_nlink;
    __mode_t st_mode;
    __uid_t st_uid;
    __gid_t st_gid;
    int __pad0;
    __dev_t st_rdev;
    __off_t st_size;
    __blksize_t st_blksize;
    __blkcnt64_t st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    __syscall_slong_t __unused[3];
  };
extern int fcntl (int __fd, int __cmd, ...);
extern int open (const char *__file, int __oflag, ...) __attribute__ ((__nonnull__ (1)));
extern int open64 (const char *__file, int __oflag, ...) __attribute__ ((__nonnull__ (1)));
extern int openat (int __fd, const char *__file, int __oflag, ...)
     __attribute__ ((__nonnull__ (2)));
extern int openat64 (int __fd, const char *__file, int __oflag, ...)
     __attribute__ ((__nonnull__ (2)));
extern int creat (const char *__file, __mode_t __mode) __attribute__ ((__nonnull__ (1)));
extern int creat64 (const char *__file, __mode_t __mode) __attribute__ ((__nonnull__ (1)));
extern int lockf (int __fd, int __cmd, __off_t __len);
extern int lockf64 (int __fd, int __cmd, __off64_t __len);
extern int posix_fadvise (int __fd, __off_t __offset, __off_t __len,
     int __advise) __attribute__ ((__nothrow__ , __leaf__));
extern int posix_fadvise64 (int __fd, __off64_t __offset, __off64_t __len,
       int __advise) __attribute__ ((__nothrow__ , __leaf__));
extern int posix_fallocate (int __fd, __off_t __offset, __off_t __len);
extern int posix_fallocate64 (int __fd, __off64_t __offset, __off64_t __len);
]]

O_ACCMODE   = tonumber ( "0003"      , 8 )
O_RDONLY    = tonumber ( "00"        , 8 )
O_WRONLY    = tonumber ( "01"        , 8 )
O_RDWR      = tonumber ( "02"        , 8 )
O_CREAT     = tonumber ( "0100"      , 8 ) -- not fcntl
O_EXCL      = tonumber ( "0200"      , 8 ) -- not fcntl
O_NOCTTY    = tonumber ( "0400"      , 8 ) -- not fcntl
O_TRUNC     = tonumber ( "01000"     , 8 ) -- not fcntl
O_APPEND    = tonumber ( "02000"     , 8 )
O_NONBLOCK  = tonumber ( "04000"     , 8 )
O_NDELAY    = O_NONBLOCK
O_SYNC      = tonumber ( "04010000"  , 8 )
O_FSYNC     = O_SYNC
O_ASYNC     = tonumber ( "020000"    , 8 )
O_DIRECTORY = tonumber ( "0200000"   , 8 ) -- Must be a directory.
O_NOFOLLOW  = tonumber ( "0400000"   , 8 ) -- Do not follow links.
O_CLOEXEC   = tonumber ( "02000000"  , 8 ) -- Set close_on_exec.
O_DIRECT    = tonumber ( "040000"    , 8 ) -- Direct disk access.
O_NOATIME   = tonumber ( "01000000"  , 8 ) -- Do not set atime.
O_PATH      = tonumber ( "010000000" , 8 ) -- Resolve pathname but do not open file.
O_DSYNC     = tonumber ( "010000"    , 8 ) -- Synchronize data.
O_RSYNC     = O_SYNC -- Synchronize read operations.
O_LARGEFILE = 0
O_LARGEFILE = tonumber ( "0100000"   , 8 )

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
