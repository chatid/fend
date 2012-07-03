--- Epoll based event framework
-- Events can originate from file descriptors, signals or timers.
-- The module returns an epoll object constructor

local ffi = require "ffi"
local bit = require "bit"
local new_file = require "fend.file"
require "fend.common"
include "stdio"
include "strings"
include "sys/signalfd"
include "sys/timerfd"
local time = include "time"
local epoll_lib = include "sys/epoll"

local sigfiles_to_epoll_obs = setmetatable ( { } , { __mode = "kv" } )
local signal_cb_table = {
	read = function ( file )
		local self = sigfiles_to_epoll_obs [ file ]

		local info = ffi.new ( "struct signalfd_siginfo[1]" )
		local r = tonumber ( ffi.C.read ( file:getfd() , info , ffi.sizeof ( info ) ) )
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
	epfd = new_file ( epfd )

	local mask = ffi.new ( "sigset_t[1]" )
	if ffi.C.sigemptyset ( mask ) == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	local sigfd = ffi.C.signalfd ( -1 , mask , 0 )
	if sigfd == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	sigfd = new_file ( sigfd )

	local self = setmetatable ( {
			epfile = epfd ;
			-- Signal handling stuff
			sigfile = sigfd ;
			sigmask = mask ;
			sigcbs = { } ;

			-- Holds registered file descriptors, has maps to each one's callbacks
			registered = { } ;
			raw_fd_map = { } ;

			-- Data structures for dispatch
			wait_size = 0 ;
			wait_events = nil ;
			locked = false ;
		} , epoll_mt )
	sigfiles_to_epoll_obs [ sigfd ] = self

	self:add_fd ( sigfd , signal_cb_table )

	return self
end

--- Add a file descriptor to be watched.
-- fd is the file descriptor to watch
-- cbs is a table of callbacks, the events to watch for are selected based on the callbacks given
function epoll_methods:add_fd ( file , cbs )
	local fd = file:getfd()
	local op
	if self.registered [ file ] then
		op = epoll_lib.EPOLL_CTL_MOD
	else
		op = epoll_lib.EPOLL_CTL_ADD
	end

	local __events = ffi.new ( "struct epoll_event[1]" )
	__events[0].events = bit.bor (
		cbs.read and ffi.C.EPOLLIN or 0 ,
		cbs.write and ffi.C.EPOLLOUT or 0 ,
		cbs.rdclose and ffi.C.EPOLLRDHUP or 0,
		cbs.oneshot and ffi.C.EPOLLONESHOT or 0 ,
		cbs.edge and ffi.C.EPOLLET or 0 )
	__events[0].data.fd = fd

	if ffi.C.epoll_ctl ( self.epfile:getfd() , op , fd , __events ) ~= 0 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	self.registered [ file ] = cbs
	self.raw_fd_map [ fd ] = file
end

--- Stop watching a file descriptor
-- fd is the file descriptor to stop watching
function epoll_methods:del_fd ( file )
	local fd = file:getfd()
	if ffi.C.epoll_ctl ( self.epfile:getfd() , epoll_lib.EPOLL_CTL_DEL , fd , nil ) ~= 0 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	self.registered [ file ] = nil
	self.raw_fd_map [ fd ] = nil
end

function epoll_methods:remove_lock ( )
	self.locked = false
end

local function event_string(events)
	local t = {}
	local function ap ( v ) if v then t[#t+1] = v end end
	ap(bit.band ( events , ffi.C.EPOLLIN ) ~= 0 and "R")
	ap(bit.band ( events , ffi.C.EPOLLOUT ) ~= 0 and "W")
	ap(bit.band ( events , ffi.C.EPOLLERR ) ~= 0 and "E")
	ap(bit.band ( events , ffi.C.EPOLLHUP ) ~= 0 and "C")
	ap(bit.band ( events , ffi.C.EPOLLRDHUP ) ~= 0 and "D")
	return table.concat(t,",")
end

--- Wait for a number of events and call their callbacks.
-- Raising an error in a callback will propagate through, leaving the dispatch operation locked.
-- max_events (optional) is the number of events to wait for. Defaults to 1.
-- timeout (optional) is the maximum time to wait for an event before returning. Default is to wait forever
function epoll_methods:dispatch ( max_events , timeout )
	if self.locked then error ( "dispatch already running, call :remove_lock() to recover" ) end
	self.locked = true
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
	local n = ffi.C.epoll_wait ( self.epfile:getfd() , self.wait_events , max_events , timeout )
	if n == -1 then
		self.locked = false
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	for i=0,n-1 do
		local events = self.wait_events[i].events
		local fd = self.wait_events[i].data.fd
		local file = self.raw_fd_map [ fd ]
		local cbs = self.registered [ file ]
		--print(string.format("EVENT on %s: %s", tostring(file), event_string(events)))
		if cbs.oneshot then
			if ffi.C.epoll_ctl ( self.epfile:getfd() , epoll_lib.EPOLL_CTL_DEL , fd , nil ) ~= 0 then
				self.locked = false
				error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
			end
			self.registered [ file ] = nil
			self.raw_fd_map [ fd ] = nil
		end
		if bit.band ( events , ffi.C.EPOLLIN ) ~= 0 then
			if cbs.read then
				cbs.read ( file , cbs )
			end
		end
		if bit.band ( events , ffi.C.EPOLLOUT ) ~= 0 then
			if cbs.write then
				cbs.write ( file , cbs )
			end
		end
		if bit.band ( events , ffi.C.EPOLLERR ) ~= 0 then
			if cbs.error then
				cbs.error ( file , cbs )
			end
		end
		if bit.band ( events , ffi.C.EPOLLHUP ) ~= 0 then
			if cbs.close then
				cbs.close ( file , cbs )
			else
				e:del_fd ( file , cbs )
			end
		elseif bit.band ( events , ffi.C.EPOLLRDHUP ) ~= 0 then
			if cbs.rdclose then
				cbs.rdclose ( file , cbs )
			elseif cbs.close then
				cbs.close ( file , cbs )
			else
				self:del_fd ( file , cbs )
			end
		end
	end
	self.locked = false
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
		if ffi.C.signalfd ( self.sigfile:getfd() , self.sigmask , 0 ) == -1 then
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
		if ffi.C.signalfd ( self.sigfile:getfd() , self.sigmask , 0 ) == -1 then
			error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
		end
	end
end

local file_to_timer = setmetatable ( { } , { __mode = "k" ; } )
local timerspec = ffi.new ( "struct itimerspec[1]" )
local timer_cbs = {
	read = function ( file , cbs )
		local timer = file_to_timer [ file ]
		local expired = ffi.new ( "uint64_t[1]" )
		local c = tonumber ( ffi.C.read ( file:getfd() , expired , ffi.sizeof ( expired ) ) )
		if c == -1 then
			timer.cb ( nil , ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
		end
		--assert ( c == ffi.sizeof ( expired ) )
		local start , interval = timer.cb ( timer , expired[0] )
		if start then
			timer:set ( start , interval )
		end
	end ;
}
local timer_mt = {
	__index = {
		set = function ( timer , value , interval , flags )
			flags = flags or 0
			interval = interval or 0
			timerspec[0].it_interval.tv_sec = math.floor ( interval )
			timerspec[0].it_interval.tv_nsec = ( interval % 1 )*1e9
			timerspec[0].it_value.tv_sec = math.floor ( value )
			timerspec[0].it_value.tv_nsec = ( value % 1 )*1e9
			if ffi.C.timerfd_settime ( timer.file:getfd() , flags , timerspec , nil ) == -1 then
				error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
			end
			timer.dispatcher:add_fd ( timer.file , timer_cbs )
		end ;
		disarm = function ( timer )
			timer:set ( 0 , 0 )
			timer.dispatcher:del_fd ( timer.file )
		end ;
		status = function ( timer )
			if ffi.C.timerfd_gettime ( timer.file:getfd() , timerspec ) == -1 then
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
	timerfd = new_file ( timerfd )
	local timer = setmetatable ( {
			file = timerfd ;
			dispatcher = self ;
			cb = cb ;
		} , timer_mt )
	file_to_timer [ timerfd ] = timer

	timer:set ( start , interval )

	return timer
end

return new_epoll
