local ffi = require "ffi"
local bit = require "bit"
require "fend.common"
include "fcntl"
include "unistd"

ffi.cdef [[
	typedef struct {
		const int fd;
		bool no_close:1; // Should the file handle be closed on collection?
	} file_t;
]]

local new = ffi.typeof ( "file_t" )
local file_methods = { }

function file_methods:close ( )
	if not self.no_close then
		if ffi.C.close ( self:getfd() ) == -1 then
			error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
		end
		self.no_close = true
	end
end
function file_methods:getfd ( )
	return self.fd
end

function file_methods:set_blocking ( bool )
	local flags = ffi.C.fcntl ( self:getfd() , defines.F_GETFL )
	if flags == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	if not bool then
		flags = bit.bor ( flags , defines.O_NONBLOCK )
	else
		flags = bit.band ( flags , bit.bnot ( defines.O_NONBLOCK ) )
	end
	if ffi.C.fcntl ( self:getfd() , defines.F_SETFL , ffi.cast ( "int" , flags ) ) == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
end

ffi.metatype ( "file_t" , {
		__index = file_methods ;
		__tostring = function ( self )
			return "file(" .. tostring(self:getfd()) .. ")"
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
	return new ( { fd = fd , no_close = (is_luafile == "closed file") } ) -- COMPAT: Wrap in table for luaffi
end
