local ffi = require "ffi"
local new_file = require "fend.file"
require "fend.common"
include "stdio"
include "strings"
local errors = include "errno"
include "sys/signalfd"

local sigfiles_to_dispatchers = setmetatable ( { } , { __mode = "kv" } )
local dispatchers_to_data = setmetatable ( { } , { __mode = "k" } )

local signal_cb_table = {
	read = function ( file , cbs )
		local dispatcher = sigfiles_to_dispatchers [ file ]
		local data = dispatchers_to_data [ dispatcher ]

		local info = ffi.new ( "struct signalfd_siginfo[1]" )
		local r = tonumber ( ffi.C.read ( file:getfd() , info , ffi.sizeof ( info ) ) )
		if r == -1 then
			local err = ffi.errno ( )
			if err == errors.EAGAIN then
				return
			else
				error ( ffi.string ( ffi.C.strerror ( err ) ) )
			end
		end
		assert ( r == ffi.sizeof ( info ) )

		local signum = info[0].ssi_signo
		for id , cb in pairs ( data.sigcbs [ signum ] ) do
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

	sigfiles_to_dispatchers [ sigfd ] = dispatcher
	dispatchers_to_data [ dispatcher ] = {
		sigfile = sigfd ;
		sigmask = mask ;
		sigcbs = { } ;
	}

	dispatcher:add_fd ( sigfd , signal_cb_table )
end

--- Watch for a signal.
-- This function will not block the signal for you; you must do that yourself
-- signum is the signal to watch for
-- cb is the callback to call when a signal arrives; it will receive a `struct signalfd_siginfo[1]` and the watcher's identifier
-- returns an identifier that should be used to delete the signal later
local function add_signal ( dispatcher , signum , cb )
	local data = dispatchers_to_data [ dispatcher ]
	local cbs = data.sigcbs [ signum ]
	if cbs then
		local n = #cbs + 1
		cbs [ n ] = cb
		return n
	else
		cbs = { cb }
		data.sigcbs [ signum ] = cbs

		if ffi.C.sigaddset ( data.sigmask , signum ) == -1 then
			error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
		end
		if ffi.C.signalfd ( data.sigfile:getfd() , data.sigmask , 0 ) == -1 then
			error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
		end
		return 1
	end
end

--- Stop watching for a signal.
-- signum is the signal to stop watching
-- id is the signal id to stop watching (obtained from add_signal)
local function del_signal ( dispatcher , signum , id )
	local data = dispatchers_to_data [ dispatcher ]
	local cbs = data.sigcbs [ signum ]
	cbs [ id ] = nil
	if next ( cbs ) == nil then -- No callbacks left for this signal; remove it from the watched set
		data.sigcbs [ signum ] = nil
		if ffi.C.sigdelset ( data.sigmask , signum ) == -1 then
			error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
		end
		if ffi.C.signalfd ( data.sigfile:getfd() , data.sigmask , 0 ) == -1 then
			error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
		end
	end
end

return {
	new = new ;
	add = add_signal ;
	del = del_signal ;
}
