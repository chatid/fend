local ffi = require "ffi"
local bit = require "bit"
local signalfd = require "fend.signalfd"
local timerfd = require "fend.timerfd"
require "fend.common"
include "stdlib"
include "strings"
local poll = include "poll"

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

	signalfd.new ( self )

	return self
end

function poll_methods:remove_lock ( )
end

function poll_methods:dispatch ( max_events , timeout )
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
		if bit.band ( revents , poll.POLLIN ) ~= 0 then
			if cbs.read then
				cbs.read ( file , cbs )
			end
		end
		if bit.band ( revents , poll.POLLOUT ) ~= 0 then
			if cbs.write then
				cbs.write ( file , cbs )
			end
		end
		if bit.band ( revents , poll.POLLERR ) ~= 0 then
			if cbs.error then
				cbs.error ( file , cbs )
			end
		end
		if bit.band ( revents , poll.POLLHUP ) ~= 0 then
			if cbs.close then
				cbs.close ( file , cbs )
			else
				self:del_fd ( file , cbs )
			end
		elseif bit.band ( revents , poll.POLLRDHUP ) ~= 0 then
			if cbs.rdclose then
				cbs.rdclose ( file , cbs )
			elseif cbs.close then
				cbs.close ( file , cbs )
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
		index = self.nfds
		self.nfds = self.nfds + 1
		info = {
			index = index ;
			file = file ;
			cbs = cbs ;
		}
		self.map [ fd ] = info
	end
	local pollfd = self.fds [ info.index ]
	pollfd.events = bit.bor (
		cbs.read and poll.POLLIN or 0 ,
		cbs.write and poll.POLLOUT or 0 ,
		cbs.rdclose and poll.POLLRDHUP or 0 )
	pollfd.fd = fd
end

function poll_methods:del_fd ( file )
	local fd = file:getfd()

	local index = assert ( self.map [ fd ] , "File not watched" ).index
	self.map [ fd ] = nil
	self.fds [ index ].events = 0
	self.nfds = self.nfds - 1

	if index ~= self.nfds then -- If not last item, move an item from end of list to fill the empty spot
		self.fds [ index ].fd , self.fds [ index ].events = self.fds [ self.nfds ].fd , self.fds [ self.nfds ].events
		self.fds [ self.nfds ].events = 0 -- Mark old as invalid
		self.map [ self.fds [ index ].fd ].index = index
	end
end

poll_methods.add_signal = signalfd.add
poll_methods.del_signal = signalfd.del
poll_methods.add_timer = timerfd.add

return new
