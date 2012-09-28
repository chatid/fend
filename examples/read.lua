local ffi = require "ffi"
include "stdlib"

local start_size = 32

local function expand ( old , n )
	local new = ffi.C.realloc ( old , n )
	if new == ffi.NULL then
		error ( "Cannot allocate memory" )
	else
		ffi.gc ( old , nil )
		return ffi.gc ( ffi.cast ( "char*" , new ) , ffi.C.free )
	end
end

local function read_line ( sock )
	local i = 0
	local size = start_size
	local buff = ffi.cast("char*",ffi.NULL)
	while true do
		buff = expand ( buff , size )
		local n , err = sock:recv ( buff , size )
		if not n then
			return n , err , buff , i
		end
		for j=0 , n do
			local k = i+j
			if buff[k] == 10 then -- 10 is newline
				return expand ( buff , k+1 ) , k+1 -- realloc to be actual length, and return
			end
		end
		i = i + n
		if n < size then
			return nil , "wantread" , buff , i
		end
		size = size*2
	end
end

return {
	read_line = read_line ;
}
