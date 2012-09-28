--- Epoll based event framework
-- Events can originate from file descriptors, signals or timers.
-- The module returns an epoll object constructor

local ffi = require "ffi"
local bit = require "bit"
local new_file = require "fend.file"
local signalfd = require "fend.signalfd"
local timerfd  = require "fend.timerfd"
local inotify  = require "fend.inotify"

require "fend.common"
include "string"
include "sys/epoll"

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

	local self = setmetatable ( {
			epfile = epfd ;

			-- Holds registered file descriptors, has maps to each one's callbacks
			registered = { } ;
			raw_fd_map = { } ;

			-- Data structures for dispatch
			wait_size = 0 ;
			wait_events = nil ;
			locked = false ;

		} , epoll_mt )

	self.signalfd = signalfd.new ( self ) ;
	self.inotify  = inotify.new ( self ) ;

	return self
end

--- Add a file descriptor to be watched.
-- fd is the file descriptor to watch
-- cbs is a table of callbacks, the events to watch for are selected based on the callbacks given
function epoll_methods:add_fd ( file , cbs )
	local fd = file:getfd()
	local op
	if self.registered [ file ] then
		op = defines.EPOLL_CTL_MOD
	else
		op = defines.EPOLL_CTL_ADD
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
	if ffi.C.epoll_ctl ( self.epfile:getfd() , defines.EPOLL_CTL_DEL , fd , nil ) ~= 0 then
		local err = ffi.errno ( )
		if err == defines.ENOENT then
			-- Ignore unregistered files
		else
			error ( ffi.string ( ffi.C.strerror ( err ) ) )
		end
		return
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
-- max_events (optional) is the number of events to wait for. Defaults to 1.
-- timeout (optional) is the maximum time to wait for an event before returning. Default is to wait forever
-- onerror (optional) is a function to call on a non-handled error, receives `( file , cbs , err , eventtype )`
function epoll_methods:dispatch ( max_events , timeout , onerror )
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
			if ffi.C.epoll_ctl ( self.epfile:getfd() , defines.EPOLL_CTL_DEL , fd , nil ) ~= 0 then
				self.locked = false
				error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
			end
			self.registered [ file ] = nil
			self.raw_fd_map [ fd ] = nil
		end
		if bit.band ( events , ffi.C.EPOLLIN ) ~= 0 then
			if cbs.read then
				local ok , err = pcall ( cbs.read , file , cbs , "read" )
				if not ok and ( not onerror or onerror ( file , cbs , err , "read" ) == false ) then
					error ( err )
				end
			end
		end
		if bit.band ( events , ffi.C.EPOLLERR ) ~= 0 then
			if cbs.error then
				local ok , err = pcall ( cbs.error , file , cbs , "error" )
				if not ok and ( not onerror or onerror ( file , cbs , err , "error" ) == false ) then
					error ( err )
				end
			end
		elseif bit.band ( events , ffi.C.EPOLLOUT ) ~= 0 then
			if cbs.write then
				local ok , err = pcall ( cbs.write , file , cbs , "write" )
				if not ok and ( not onerror or onerror ( file , cbs , err , "write" ) == false ) then
					error ( err )
				end
			end
		end
		if bit.band ( events , ffi.C.EPOLLHUP ) ~= 0 then
			if cbs.close then
				local ok , err = pcall ( cbs.close , file , cbs , "close" )
				if not ok and ( not onerror or onerror ( file , cbs , err , "close" ) == false ) then
					error ( err )
				end
			else
				self:del_fd ( file , cbs )
			end
		elseif bit.band ( events , ffi.C.EPOLLRDHUP ) ~= 0 then
			if cbs.rdclose then
				local ok , err = pcall ( cbs.rdclose , file , cbs , "rdclose" )
				if not ok and ( not onerror or onerror ( file , cbs , err , "rdclose" ) == false ) then
					error ( err )
				end
			elseif cbs.close then
				local ok , err = pcall ( cbs.close , file , cbs , "close" )
				if not ok and ( not onerror or onerror ( file , cbs , err , "close" ) == false ) then
					error ( err )
				end
			else
				self:del_fd ( file , cbs )
			end
		end
	end
	self.locked = false
end

epoll_methods.add_signal = signalfd.add
epoll_methods.del_signal = signalfd.del
epoll_methods.add_timer  = timerfd.add
epoll_methods.add_path   = inotify.add

return new_epoll
