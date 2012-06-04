--- Epoll based event framework
-- Events can originate from file descriptors, signals or timers.
-- The module returns an epoll object constructor

local ffi = require "ffi"
local bit = require "bit"
local new_fd = require "fend.fd"
require "fend.common"
include "stdio"
include "strings"
include "sys/signalfd"
include "sys/timerfd"
local time = include "time"
local epoll_lib = include "sys/epoll"

local sigfds_to_epoll_obs = setmetatable ( { } , { __mode = "kv" } )
local signal_cb_table = {
	read = function ( fd )
		local self = sigfds_to_epoll_obs [ fd ]

		local info = ffi.new ( "struct signalfd_siginfo[1]" )
		local r = tonumber ( ffi.C.read ( fd.fd , info , ffi.sizeof ( info ) ) )
		if r == -1 then
			error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
		end
		assert ( r == ffi.sizeof ( info ) )

		local signum = info[0].ssi_signo
		for id , cb in pairs ( self.sigcbs [ signum ] ) do
			cb ( info , id )
		end
	end
}
local epoll_methods = { }
local epoll_mt = {
	__index = epoll_methods ;
}

--- Creates a new epoll object.
-- guesstimate is a guess for how many file handles will be watched (to help memory allocation)
-- returns the new object
local function new_epoll ( guesstimate )
	guesstimate = guesstimate or 10
	local epfd = ffi.C.epoll_create ( guesstimate )
	if epfd == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	epfd = new_fd ( epfd )

	local mask = ffi.new ( "sigset_t[1]" )
	if ffi.C.sigemptyset ( mask ) == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	local sigfd = ffi.C.signalfd ( -1 , mask , 0 )
	if sigfd == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	sigfd = new_fd ( sigfd )

	local self = setmetatable ( {
			epfd = epfd ;
			-- Signal handling stuff
			sigfd = sigfd ;
			sigmask = mask ;
			sigcbs = { } ;

			-- Holds registered file descriptors, has maps to each one's callbacks
			registered = { } ;
			raw_fd_map = { } ;

			-- Data structures for dispatch
			wait_size = 0 ;
			wait_events = nil ;
		} , epoll_mt )
	sigfds_to_epoll_obs [ sigfd ] = self

	self:add_fd ( sigfd , signal_cb_table )

	return self
end

--- Add a file descriptor to be watched.
-- fd is the file descriptor to watch
-- cbs is a table of callbacks, the events to watch for are selected based on the callbacks given
function epoll_methods:add_fd ( fd , cbs )
	local op
	if self.registered [ fd ] then
		op = epoll_lib.EPOLL_CTL_MOD
	else
		op = epoll_lib.EPOLL_CTL_ADD
	end

	local __events = ffi.new ( "struct epoll_event[1]" )
	__events[0].events = bit.bor (
		cbs.read and ffi.C.EPOLLIN or 0 ,
		cbs.write and ffi.C.EPOLLOUT or 0 ,
		cbs.oneshot and ffi.C.EPOLLONESHOT or 0 ,
		ffi.C.EPOLLRDHUP )
	__events[0].data.fd = fd.fd

	if ffi.C.epoll_ctl ( self.epfd.fd , op , fd.fd , __events ) ~= 0 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	self.registered [ fd ] = cbs
	self.raw_fd_map [ fd:getfd() ] = fd
end

--- Stop watching a file descriptor
-- fd is the file descriptor to stop watching
function epoll_methods:del_fd ( fd )
	if ffi.C.epoll_ctl ( self.epfd.fd , epoll_lib.EPOLL_CTL_DEL , fd.fd , nil ) ~= 0 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	self.registered [ fd ] = nil
	self.raw_fd_map [ fd:getfd() ] = nil
end

--- Wait for a number of events and call their callbacks.
-- max_events (optional) is the number of events to wait for. Defaults to 1.
-- timeout (optional) is the maximum time to wait for an event before returning. Default is to wait forever
function epoll_methods:dispatch ( max_events , timeout )
	max_events = max_events or 1
	if max_events > self.wait_size then -- Expand the array
		self.wait_events = ffi.new ( "struct epoll_event[?]" , max_events )
		self.wait_size = max_events
	end
	if timeout then
		timeout = timeout * 1000
	else
		timeout = -1
	end
	local n = ffi.C.epoll_wait ( self.epfd.fd , self.wait_events , max_events , timeout )
	if n == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	for i=0,n-1 do
		local events = self.wait_events[i].events
		local fd = self.wait_events[i].data.fd
		fd = self.raw_fd_map [ fd ]
		local cbs = self.registered [ fd ]
		if cbs.oneshot then
			if ffi.C.epoll_ctl ( self.epfd.fd , epoll_lib.EPOLL_CTL_DEL , fd.fd , nil ) ~= 0 then
				error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
			end
			self.registered [ fd ] = nil
			self.raw_fd_map [ fd:getfd() ] = nil
		end
		if bit.band ( events , ffi.C.EPOLLIN ) ~= 0 then
			if cbs.read then
				cbs.read ( fd , cbs )
			end
		end
		if bit.band ( events , ffi.C.EPOLLOUT ) ~= 0 then
			if cbs.write then
				cbs.write ( fd , cbs )
			end
		end
		if bit.band ( events , ffi.C.EPOLLERR ) ~= 0 then
			self:del_fd ( fd )
			if cbs.error then
				cbs.error ( fd , cbs )
			end
		end
		if bit.band ( events , ffi.C.EPOLLRDHUP ) ~= 0 then
			if cbs.rdclose then
				cbs.rdclose ( fd , cbs )
			else
				ffi.C.shutdown ( fd.fd , ffi.C.SHUT_RDWR )
			end
		end
		if bit.band ( events , ffi.C.EPOLLHUP ) ~= 0 then
			self:del_fd ( fd )
			if cbs.close then
				cbs.close ( fd , cbs )
			end
		end
	end
end

--- Watch for a signal.
-- This function will not block the signal for you; you must do that yourself
-- signum is the signal to watch for
-- cb is the callback to call when a signal arrives; it will receive a `struct signalfd_siginfo[1]` and the watcher's identifier
-- returns an identifier that should be used to delete the signal later
function epoll_methods:add_signal ( signum , cb )
	local cbs = self.sigcbs [ signum ]
	if cbs then
		local n = #cbs + 1
		cbs [ n ] = cb
		return n
	else
		cbs = { cb }
		self.sigcbs [ signum ] = cbs

		if ffi.C.sigaddset ( self.sigmask , signum ) == -1 then
			error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
		end
		if ffi.C.signalfd ( self.sigfd.fd , self.sigmask , 0 ) == -1 then
			error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
		end
		return 1
	end
end

--- Stop watching for a signal.
-- signum is the signal to stop watching
-- id is the signal id to stop watching (obtained from add_signal)
function epoll_methods:del_signal ( signum , id )
	local cbs = self.sigcbs [ signum ]
	cbs [ id ] = nil
	if next ( cbs ) == nil then -- No callbacks left for this signal; remove it from the watched set
		if ffi.C.sigdelset ( self.sigmask , signum ) == -1 then
			error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
		end
		if ffi.C.signalfd ( self.sigfd.fd , self.sigmask , 0 ) == -1 then
			error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
		end
	end
end

local timerspec = ffi.new ( "struct itimerspec[1]" )
local timer_mt = {
	__index = {
		set = function ( timer , value , interval , flags )
			flags = flags or 0
			interval = interval or 0
			timerspec[0].it_interval.tv_sec = math.floor ( interval )
			timerspec[0].it_interval.tv_nsec = ( interval % 1 )*1e9
			timerspec[0].it_value.tv_sec = math.floor ( value )
			timerspec[0].it_value.tv_nsec = ( value % 1 )*1e9
			if ffi.C.timerfd_settime ( timer.fd.fd , flags , timerspec , nil ) == -1 then
				error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
			end
		end ;
		disarm = function ( timer )
			timer:set ( 0 , 0 )
		end ;
		status = function ( timer )
			if ffi.C.timerfd_gettime ( timer.fd.fd , timerspec ) == -1 then
				error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
			end
			return tonumber ( timerspec[0].it_value.tv_sec ) + tonumber ( timerspec[0].it_value.tv_nsec ) / 1e9 ,
				tonumber ( timerspec[0].it_interval.tv_sec ) + tonumber ( timerspec[0].it_interval.tv_nsec ) / 1e9
		end ;
	} ;
}

--- Create a timer that creates events.
-- start is how long from now to fire the timer
-- interval (optional) is the period of the timer. Defaults to never (0)
-- cb is the callback to call when the timer fires; it will receive the timer object and the interval; return values from callback change the timer's start and interval
-- returns a timer object that has methods `set`, `disarm` and `status`
function epoll_methods:add_timer ( start , interval , cb )
	local timerfd = ffi.C.timerfd_create ( time.CLOCK_MONOTONIC , bit.bor ( ffi.C.TFD_NONBLOCK ) )
	if timerfd == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	timerfd = new_fd ( timerfd )
	local timer = setmetatable ( { fd = timerfd } , timer_mt )

	self:add_fd ( timerfd , {
		read = function ( fd )
			local expired = ffi.new ( "uint64_t[1]" )
			local c = tonumber ( ffi.C.read ( fd.fd , expired , ffi.sizeof ( expired ) ) )
			if c == -1 then
				cb ( nil , ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
			end
			--assert ( c == ffi.sizeof ( expired ) )
			start , interval = cb ( timer , expired[0] )
			if start then
				timer:set ( start , interval )
			end
		end ;
	} )
	timer:set ( start , interval )

	return timer
end

return new_epoll
