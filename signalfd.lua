local next = next
local pairs = pairs

local ffi = require "ffi"
local new_file = require "fend.file"
require "fend.common"
include "stdio"
include "string"
include "errno"
include "sys/signalfd"

local sigfiles_map = setmetatable ( { } , { __mode = "k" } )

local signal_cb_table = {
	read = function ( file , cbs )
		local info = ffi.new ( "struct signalfd_siginfo[1]" )
		local r = tonumber ( ffi.C.read ( file:getfd() , info , ffi.sizeof ( info ) ) )
		if r == -1 then
			local err = ffi.errno ( )
			if err == defines.EAGAIN then
				return
			else
				error ( ffi.string ( ffi.C.strerror ( err ) ) )
			end
		end
		assert ( r == ffi.sizeof ( info ) )

		local self = sigfiles_map [ file ]
		local signum = info[0].ssi_signo
		for id , cb in pairs ( self.sigcbs [ signum ] ) do
			cb ( info , id )
		end

		return cbs.read ( file , cbs ) -- Call self until EAGAIN
	end ;
	edge = true ;
}

local function new ( dispatcher )
	local mask = ffi.new ( "sigset_t[1]" )
	if ffi.C.sigemptyset ( mask ) == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	local sigfd = ffi.C.signalfd ( -1 , mask , ffi.C.SFD_NONBLOCK )
	if sigfd == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	sigfd = new_file ( sigfd )

	local self = {
		sigfile = sigfd ;
		sigmask = mask ;
		sigcbs = { } ;
	}

	sigfiles_map [ sigfd ] = self

	dispatcher:add_fd ( sigfd , signal_cb_table )

	return self
end

--- Watch for a signal.
-- This function will not block the signal for you; you must do that yourself
-- signum is the signal to watch for
-- cb is the callback to call when a signal arrives; it will receive a `struct signalfd_siginfo[1]` and the watcher's identifier
-- returns an identifier that should be used to delete the signal later
local function add_signal ( dispatcher , signum , cb )
	local self = dispatcher.signalfd
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
local function del_signal ( dispatcher , signum , id )
	local self = dispatcher.signalfd
	local cbs = self.sigcbs [ signum ]
	cbs [ id ] = nil
	if next ( cbs ) == nil then -- No callbacks left for this signal; remove it from the watched set
		self.sigcbs [ signum ] = nil
		if ffi.C.sigdelset ( self.sigmask , signum ) == -1 then
			error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
		end
		if ffi.C.signalfd ( self.sigfile:getfd() , self.sigmask , 0 ) == -1 then
			error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
		end
	end
end

return {
	new = new ;
	add = add_signal ;
	del = del_signal ;
}
