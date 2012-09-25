local includeENV

local includecache = { }
local function include ( lib )
	lib = "fend.include." .. lib:gsub("%.h$",""):gsub("/",".")
	local res = includecache [ lib ]
	if res == nil then
		local mod = setfenv ( package.loaders [ 2 ] ( lib ) , includeENV )
		res = mod ( lib )
		if res == nil then
			res = true
		end
		includecache [ lib ] = res
	end
	return res
end

includeENV = setmetatable ( { } , {
		__index = {
			ffi      = require "ffi" ;
			bit      = require "bit" ;
			tonumber = tonumber ; -- Some libraries have octals to convert
			include  = include ;
		} ;
		__newindex = function ( t , k , v )
			if t [ k ] then
				error ( "Cannot overwrite key (" .. tostring(k) .. ")" )
			end
			rawset ( t , k , v )
		end ;
	} )


_G.include = include
_G.defines = includeENV

return {
	include = include ;
	defines = includeENV ;
}
