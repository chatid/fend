local ffi = require"ffi"
local bit = require"bit"

require "include.stdio"
require "include.strings"
require "include.sys.signalfd"

ffi.cdef [[
typedef struct
  {
    unsigned long int __val[(1024 / (8 * sizeof (unsigned long int)))];
  } __sigset_t;
typedef __sigset_t sigset_t;
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

local EPOLL_CTL = {
	ADD = 1 ; -- Add a file decriptor to the interface.
	DEL = 2	; -- Remove a file decriptor from the interface.
	MOD = 3	; -- Change file decriptor epoll_event structure.
}

local sigfds_to_epoll_obs = { }
local signal_cb_table = {
	read = function ( fd )
		local self = sigfds_to_epoll_obs [ fd ]

		local info = ffi.new ( "struct signalfd_siginfo[1]" )
		local r = ffi.C.read ( fd , info , ffi.sizeof ( info ) )
		if r == -1 then
			error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
		end
		assert ( r == ffi.sizeof ( info ) )

		local signum = info[0].ssi_signo
		local id = info[0].ssi_int
		local cb = self.sigcbs [ signum ] [ id ]
		cb ( info )
	end
}
local epoll_methods = { }
local epoll_mt = {
	__index = epoll_methods ;
	__gc = function ( self )
		sigfds_to_epoll_obs [ self.sigfd ] = nil
		ffi.C.close ( self.sigfd )
		ffi.C.close ( self.epfd )
	end ;
}

local function new_epoll ( guesstimate )
	guesstimate = guesstimate or 10
	local epfd = ffi.C.epoll_create ( guesstimate )
	if epfd == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	local mask = ffi.new ( "sigset_t[1]" )
	ffi.C.sigemptyset ( mask )
	local sigfd = ffi.C.signalfd ( -1 , mask , 0 )
	if sigfd == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end

	local self = setmetatable ( {
			epfd = epfd ;
			-- Signal handling stuff
			sigfd = sigfd ;
			sigmask = mask ;
			sigcbs = { } ;

			-- Holds registered file descriptors, has maps to each one's callbacks
			registered = { } ;
		} , epoll_mt )
	sigfds_to_epoll_obs [ sigfd ] = self

	self:add_fd ( sigfd , signal_cb_table )

	return self
end

-- cbs is a table of callbacks: read,write
function epoll_methods:add_fd ( fd , cbs )
	local op
	if self.registered [ fd ] then
		op = EPOLL_CTL.MOD
	else
		op = EPOLL_CTL.ADD
	end

	local __events = ffi.new ( "struct epoll_event[1]" )
	__events[0].events = bit.bor (
		cbs.read and ffi.C.EPOLLIN or 0 ,
		cbs.write and ffi.C.EPOLLOUT or 0 ,
		cbs.oneshot and ffi.C.EPOLLONESHOT or 0 )
	__events[0].data.fd = fd

	if ffi.C.epoll_ctl ( self.epfd , op , fd , __events ) ~= 0 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	self.registered [ fd ] = cbs
	return true
end

function epoll_methods:del_fd ( fd )
	if ffi.C.epoll_ctl ( self.epfd , EPOLL_CTL.DEL , fd , nil ) ~= 0 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	self.registered [ fd ] = nil
	return true
end

local wait_size = 0
local wait_events -- One big shared array...
function epoll_methods:dispatch ( max_events , timeout )
	if max_events == nil then
		max_events = wait_size
	elseif max_events > wait_size then -- Expand the array
		wait_events = ffi.new ( "struct epoll_event[?]" , max_events )
		wait_size = max_events
	end
	if timeout then
		timeout = timeout * 1000
	else
		timeout = -1
	end
	local n = ffi.C.epoll_wait ( self.epfd , wait_events , max_events , timeout )
	if n == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	for i=1,n do
		local events = wait_events[i-1].events
		local fd = wait_events[i-1].data.fd
		local cbs = self.registered [ fd ]
		if cbs.oneshot then
			if ffi.C.epoll_ctl ( self.epfd , EPOLL_CTL.DEL , fd , nil ) ~= 0 then
				cbs.error ( fd , ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
			end
			self.registered [ fd ] = nil
		end
		if cbs.read and bit.band ( events , ffi.C.EPOLLIN ) ~= 0 then
			cbs.read ( fd )
		end
		if cbs.write and bit.band ( events , ffi.C.EPOLLOUT ) ~= 0 then
			cbs.write ( fd )
		end
		if cbs.error and bit.band ( events , ffi.C.EPOLLERR ) ~= 0 then
			cbs.error ( fd )
		end
		if cbs.close and bit.band ( events , ffi.C.EPOLLHUP ) ~= 0 then
			cbs.close ( fd )
		end
	end
end

--[[function watch_signal ( signum , cb )
	local action = ffi.new ( "struct sigaction" )
	action.__sigaction_handler.sa_sigaction = function ( signum , info , content )
		print("SIGNAL",signum,info,content)
	end
	--action.sa_mask
	action.sa_flags = signal.SA_SIGINFO
	ffi.C.sigaction ( signum , action , nil )
end--]]

function epoll_methods:add_signal ( signum , id , cb )
	local cbs = self.sigcbs [ signum ]
	if cbs then
		cbs [ id ] = cb
	else
		cbs = { [ id ] = cb }
		self.sigcbs [ signum ] = cbs

		ffi.C.sigaddset ( self.sigmask , signum )
		if ffi.C.signalfd ( self.sigfd , self.sigmask , 0 ) == -1 then
			error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
		end
	end
end

function epoll_methods:del_signal ( signum )
	local fd = sigfds [ signum ]
	epoll_methods:del_fd ( fd )
	ffi.C.sigdelset ( self.sigmask , signum )
	sigfds [ signum ] = nil
end

return new_epoll
