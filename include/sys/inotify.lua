include "sys/types"

ffi.cdef [[
enum
	{
		IN_CLOEXEC = 02000000,
		IN_NONBLOCK = 00004000
	};
struct inotify_event
{
	int wd;
	uint32_t mask;
	uint32_t cookie;
	uint32_t len;
	char name [];
};

extern int inotify_init (void) __attribute__ ((__nothrow__ , __leaf__));
extern int inotify_init1 (int __flags) __attribute__ ((__nothrow__ , __leaf__));
extern int inotify_add_watch (int __fd, const char *__name, uint32_t __mask)
	__attribute__ ((__nothrow__ , __leaf__));
extern int inotify_rm_watch (int __fd, int __wd) __attribute__ ((__nothrow__ , __leaf__));
]]

-- Supported events suitable for MASK parameter of INOTIFY_ADD_WATCH.
IN_ACCESS        = 0x00000001     -- File was accessed.
IN_MODIFY        = 0x00000002     -- File was modified.
IN_ATTRIB        = 0x00000004     -- Metadata changed.
IN_CLOSE_WRITE   = 0x00000008     -- Writtable file was closed.
IN_CLOSE_NOWRITE = 0x00000010     -- Unwrittable file closed.
IN_CLOSE         = bit.bor ( IN_CLOSE_WRITE , IN_CLOSE_NOWRITE) -- Close.
IN_OPEN          = 0x00000020     -- File was opened.
IN_MOVED_FROM    = 0x00000040     -- File was moved from X.
IN_MOVED_TO      = 0x00000080     -- File was moved to Y.
IN_MOVE          = bit.bor ( IN_MOVED_FROM , IN_MOVED_TO) -- Moves.
IN_CREATE        = 0x00000100     -- Subfile was created.
IN_DELETE        = 0x00000200     -- Subfile was deleted.
IN_DELETE_SELF   = 0x00000400     -- Self was deleted.
IN_MOVE_SELF     = 0x00000800     -- Self was moved.

-- Events sent by the kernel.
IN_UNMOUNT       = 0x00002000     -- Backing fs was unmounted.
IN_Q_OVERFLOW    = 0x00004000     -- Event queued overflowed.
IN_IGNORED       = 0x00008000     -- File was ignored.

-- Helper events.
IN_CLOSE         = bit.bor ( IN_CLOSE_WRITE , IN_CLOSE_NOWRITE)    -- Close.
IN_MOVE          = bit.bor ( IN_MOVED_FROM , IN_MOVED_TO)          -- Moves.

-- Special flags.
IN_ONLYDIR       = 0x01000000     -- Only watch the path if it is a directory.
IN_DONT_FOLLOW   = 0x02000000     -- Do not follow a sym link.
IN_EXCL_UNLINK   = 0x04000000     -- Exclude events on unlinked objects.
IN_MASK_ADD      = 0x20000000     -- Add to the mask of an already existing watch.
IN_ISDIR         = 0x40000000     -- Event occurred against dir.
IN_ONESHOT       = 0x80000000     -- Only send event once.

-- All events which a program can wait on.
IN_ALL_EVENTS    = bit.bor ( IN_ACCESS , IN_MODIFY , IN_ATTRIB , IN_CLOSE_WRITE
	, IN_CLOSE_NOWRITE , IN_OPEN , IN_MOVED_FROM , IN_MOVED_TO , IN_CREATE , IN_DELETE
	, IN_DELETE_SELF , IN_MOVE_SELF )
