local ffi = require"ffi"
ffi.cdef [[
	typedef struct { int fd; } fd_t;
]]
ffi.metatype ( "fd_t" , {
		__gc = function ( self )
			ffi.C.close ( self.fd )
		end ;
	} )
