local ffi = require "ffi"
local bit = require "bit"
local signalfd = require "fend.signalfd"
local timerfd  = require "fend.timerfd"
local inotify  = require "fend.inotify"

require "fend.common"
include "stdlib"
include "string"
include "poll"

local poll_methods = { }
local poll_mt = {
	__index = poll_methods ;
}

local function expand_pollfds ( old , n )
	ffi.gc ( old , nil )
	local new = ffi.C.realloc ( old , ffi.sizeof("struct pollfd")*n )
	if new == ffi.NULL then
		error ( "Cannot allocate memory" )
	else
		return ffi.gc ( ffi.cast ( "struct pollfd*" , new ) , ffi.C.free )
	end
end

local function new ( guesstimate )
	if not guesstimate or guesstimate < 1 then
		guesstimate = 8
	end
	local self = setmetatable ( {
			map = { } ;
			fds = expand_pollfds ( ffi.cast("struct pollfd*",0) , guesstimate ) ;
			nfds = 0 ;
			allocated = guesstimate ;
		} , poll_mt )

	self.signalfd = signalfd.new ( self ) ;
	self.inotify  = inotify.new ( self ) ;

	return self
end

function poll_methods:remove_lock ( )
end

function poll_methods:dispatch ( max_events , timeout , onerror )
	if timeout then
		timeout = timeout * 1000
	else
		timeout = -1
	end
	local n = ffi.C.poll ( self.fds , self.nfds , timeout )
	if n == -1 then
		self.locked = false
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	max_events = math.min ( n , max_events or 1 )
	local evs = { }
	local served = 0
	for i=self.nfds-1,0,-1 do
		local pollfd = self.fds [ i ]
		local r = pollfd.revents
		if r ~= 0 then
			local info = self.map [ pollfd.fd ]
			evs [ info ] = r
			served = served + 1
		end
		if served == max_events then break end
	end
	for info , revents in pairs ( evs ) do
		local file , cbs = info.file , info.cbs
		if cbs.oneshot then
			self:del_fd ( file )
		end
		if bit.band ( revents , defines.POLLIN ) ~= 0 then
			if cbs.read then
				local ok , err = pcall ( cbs.read , file , cbs , "write" )
				if not ok and ( not onerror or onerror ( file , cbs , err , "write" ) == false ) then
					error ( err )
				end
			end
		end
		if bit.band ( revents , defines.POLLERR ) ~= 0 then
			if cbs.error then
				local ok , err = pcall ( cbs.error , file , cbs , "write" )
				if not ok and ( not onerror or onerror ( file , cbs , err , "write" ) == false ) then
					error ( err )
				end
			end
		elseif bit.band ( revents , defines.POLLOUT ) ~= 0 then -- "This event and POLLOUT are mutually-exclusive; a stream can never be writable if a hangup has occurred."
			if cbs.write then
				local ok , err = pcall ( cbs.write , file , cbs , "write" )
				if not ok and ( not onerror or onerror ( file , cbs , err , "write" ) == false ) then
					error ( err )
				end
			end
		end
		if bit.band ( revents , defines.POLLHUP ) ~= 0 then
			if cbs.close then
				local ok , err = pcall ( cbs.close , file , cbs , "write" )
				if not ok and ( not onerror or onerror ( file , cbs , err , "write" ) == false ) then
					error ( err )
				end
			else
				self:del_fd ( file , cbs )
			end
		elseif bit.band ( revents , defines.POLLRDHUP ) ~= 0 then
			if cbs.rdclose then
				local ok , err = pcall ( cbs.rdclose , file , cbs , "write" )
				if not ok and ( not onerror or onerror ( file , cbs , err , "write" ) == false ) then
					error ( err )
				end
			elseif cbs.close then
				local ok , err = pcall ( cbs.close , file , cbs , "write" )
				if not ok and ( not onerror or onerror ( file , cbs , err , "write" ) == false ) then
					error ( err )
				end
			else
				self:del_fd ( file , cbs )
			end
		end
	end
end

function poll_methods:add_fd ( file , cbs )
	local fd = file:getfd()

	local info = self.map [ fd ]
	if info then
		info.cbs = cbs
	else
		if self.nfds == self.allocated then -- Expand
			local newsize = self.allocated*2
			self.fds = expand_pollfds ( self.fds , newsize )
			self.allocated = newsize
		end
		info = {
			index = self.nfds ;
			file = file ;
			cbs = cbs ;
		}
		self.nfds = self.nfds + 1
		self.map [ fd ] = info
	end
	local pollfd = self.fds [ info.index ]
	pollfd.events = bit.bor (
		cbs.read and defines.POLLIN or 0 ,
		cbs.write and defines.POLLOUT or 0 ,
		cbs.rdclose and defines.POLLRDHUP or 0 )
	pollfd.fd = fd
end

function poll_methods:del_fd ( file )
	local fd = file:getfd()

	local m = self.map [ fd ]
	if m == nil then
		return
	end
	local index = m.index
	self.map [ fd ] = nil
	self.nfds = self.nfds - 1
	if index ~= self.nfds then -- If not last item, move an item from end of list to fill the empty spot
		local lastfd , lastevent = self.fds [ self.nfds ].fd , self.fds [ self.nfds ].events
		local lastinfo = self.map [ lastfd ]
		self.fds [ index ].fd , self.fds [ index ].events = lastfd , lastevent
		lastinfo.index = index
	end
end

poll_methods.add_signal = signalfd.add
poll_methods.del_signal = signalfd.del
poll_methods.add_timer  = timerfd.add
poll_methods.add_path   = inotify.add

return new
