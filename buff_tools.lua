local ffi = require "ffi"

-- Essentially memcmp
local function equal ( b1 , b2 , l )
	for i=0,l-1 do
		if b1[i] ~= b2[i] then
			return false
		end
	end
	return true
end

-- Find b2 in b1; returns indexes of beginning and end of match
local function find ( b1 , l1 , b2 , l2 )
	for i=0,l1-l2 do
		if equal ( b1+i , b2 , l2 ) then
			return i , i+l2-1
		end
	end
	return false
end

-- `for buff , len , last in split(...) do`
local function split ( b1 , l1 , b2 , l2 )
	local from = 0
	return function ( )
			if from >= l1 then return nil end
			local initial = from
			local s , e = find ( b1+initial , l1-initial , b2 , l2 )
			if s then
				from = initial+e+1
				return b1+initial , s
			else
				from = l1
				return b1+initial , l1-initial , true
			end
		end
end

local function new ( str )
	return ffi.cast("const char*",str) , #str
end

return {
	new = new ;
	equal = equal ;
	find = find ;
	split = split ;
}
