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

F_DUPFD         = 0 -- Duplicate file descriptor.
F_GETFD         = 1 -- Get file descriptor flags.
F_SETFD         = 2 -- Set file descriptor flags.
F_GETFL         = 3 -- Get file status flags.
F_SETFL         = 4 -- Set file status flags.
F_GETLK         = 5 -- Get record locking info.
F_SETLK         = 6 -- Set record locking info (non-blocking).
F_SETLKW        = 7 -- Set record locking info (blocking).
F_GETLK64       = 5 -- Get record locking info.
F_SETLK64       = 6 -- Set record locking info (non-blocking).
F_SETLKW64      = 7 -- Set record locking info (blocking).
F_GETLK         = 5 -- Get record locking info.
F_SETLK         = 6 -- Set record locking info (non-blocking).
F_SETLKW        = 7 -- Set record locking info (blocking).
F_GETLK64       = 12 -- Get record locking info.
F_SETLK64       = 13 -- Set record locking info (non-blocking).
F_SETLKW64      = 14 -- Set record locking info (blocking).
F_GETLK         = F_GETLK64  -- Get record locking info.
F_SETLK         = F_SETLK64  -- Set record locking info (non-blocking).
F_SETLKW        = F_SETLKW64 -- Set record locking info (blocking).
F_SETOWN        = 8 -- Get owner (process receiving SIGIO).
F_GETOWN        = 9 -- Set owner (process receiving SIGIO).
F_SETSIG        = 10 -- Set number of signal to be sent.
F_GETSIG        = 11 -- Get number of signal to be sent.
F_SETOWN_EX     = 15 -- Get owner (thread receiving SIGIO).
F_GETOWN_EX     = 16 -- Set owner (thread receiving SIGIO).
F_SETLEASE      = 1024 -- Set a lease.
F_GETLEASE      = 1025 -- Enquire what lease is active.
F_NOTIFY        = 1026 -- Request notfications on a directory.
F_SETPIPE_SZ    = 1031 -- Set pipe page size array.
F_GETPIPE_SZ    = 1032 -- Set pipe page size array.
F_DUPFD_CLOEXEC = 1030 -- Duplicate file descriptor with
FD_CLOEXEC      = 1 -- actually anything with low bit set goes
F_RDLCK         = 0 -- Read lock.
F_WRLCK         = 1 -- Write lock.
F_UNLCK         = 2 -- Remove lock.
F_EXLCK         = 4 -- or 3
F_SHLCK         = 8 -- or 4

LOCK_SH    = 1 -- shared lock
LOCK_EX    = 2 -- exclusive lock
LOCK_NB    = 4 -- or'd with one of the above to prevent blocking
LOCK_UN    = 8 -- remove lock
LOCK_MAND  = 32 -- This is a mandatory flock:
LOCK_READ  = 64 -- ... which allows concurrent read operations.
LOCK_WRITE = 128 -- ... which allows concurrent write operations.
LOCK_RW    = 192 -- ... Which allows concurrent read & write operations.

DN_ACCESS    = 0x00000001 -- File accessed.
DN_MODIFY    = 0x00000002 -- File modified.
DN_CREATE    = 0x00000004 -- File created.
DN_DELETE    = 0x00000008 -- File removed.
DN_RENAME    = 0x00000010 -- File renamed.
DN_ATTRIB    = 0x00000020 -- File changed attibutes.
DN_MULTISHOT = 0x80000000 -- Don't remove notifier.

FAPPEND   = O_APPEND
FFSYNC    = O_FSYNC
FASYNC    = O_ASYNC
FNONBLOCK = O_NONBLOCK
FNDELAY   = O_NDELAY

POSIX_FADV_NORMAL     = 0 -- No further special treatment.
POSIX_FADV_RANDOM     = 1 -- Expect random page references.
POSIX_FADV_SEQUENTIAL = 2 -- Expect sequential page references.
POSIX_FADV_WILLNEED   = 3 -- Will need these pages.
POSIX_FADV_DONTNEED   = 4 -- Don't need these pages.
POSIX_FADV_NOREUSE    = 5 -- Data will be accessed once.

SYNC_FILE_RANGE_WAIT_BEFORE = 1 -- Wait upon writeout of all pages in the range before performing the write.
SYNC_FILE_RANGE_WRITE       = 2 -- Initiate writeout of all those dirty pages in the range which are not presently under writeback.
SYNC_FILE_RANGE_WAIT_AFTER  = 4 -- Wait upon writeout of all pages in the range after performing the write.

SPLICE_F_MOVE     = 1 -- Move pages instead of copying.
SPLICE_F_NONBLOCK = 2 -- Don't block on the pipe splicing (but we may still block on the fd we splice from/to).
SPLICE_F_MORE     = 4 -- Expect more data.
SPLICE_F_GIFT     = 8 -- Pages passed in are a gift.

MAX_HANDLE_SZ = 128
