local ffi = require "ffi"
local bit = require "bit"
require "ffi_ev.common"
local fcntl = include "fcntl"
include "unistd"

ffi.cdef [[
	typedef struct {
		const int fd;
		bool closed;
	} fd_t;
]]

local new = ffi.typeof ( "fd_t" )
local fd_methods = { }

function fd_methods:close ( )
	if not self.closed then
		if ffi.C.close ( self.fd ) == -1 then
			error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
		end
		self.closed = true
	end
end
function fd_methods:getfd ( )
	return self.fd
end

function fd_methods:set_blocking ( bool )
	local flags = ffi.C.fcntl ( self:getfd() , fcntl.F_GETFL )
	if flags == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	if not bool then
		flags = bit.bor ( flags , fcntl.O_NONBLOCK )
	else
		flags = bit.band ( flags , bit.bnot ( fcntl.O_NONBLOCK ) )
	end
	if ffi.C.fcntl ( self:getfd() , fcntl.F_SETFL , ffi.cast ( "int" , flags ) ) == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
end

ffi.metatype ( "fd_t" , {
		__index = fd_methods ;
		__tostring = function ( self )
			return "file: " .. self:getfd()
		end ;
		__gc = function ( self )
			self:close ( )
		end ;
	} )

return function ( fd )
	local is_luafile = io.type ( fd )
	if is_luafile then
		fd = ffi.C.fileno ( fd )
		if fd == -1 then
			error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
		end
	end
	return new ( { fd , is_luafile == "closed file" } ) -- COMPAT: Wrap in table for luaffi
end
