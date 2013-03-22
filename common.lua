local ffi = require "ffi"

local _M = { }

local function current_module_path ( level )
	level = level or 2
	local path = debug.getinfo(level,"S").source
	if path:sub(1,1) == "@" then
		path = path:sub(2):gsub("[^/]+$","include/?.lua")
	else
		return nil
	end
	return path
end
_M.current_module_path = current_module_path

local default_path = current_module_path ( ) or ""
local fend_path = os.getenv ( "FEND_PATH" )
if fend_path then
	fend_path:gsub(";;",";"..default_path..";")
else
	fend_path = default_path
end
_M.path = fend_path

function _M.add_current_module ( level )
	level = (level or 2)+1
	_M.path = _M.path .. ";" .. assert ( current_module_path ( level ) , "Not a file" )
end

local includeENV

local includecache = { }
local function include ( lib , submodule )
	submodule = submodule or "fend"
	lib = lib:gsub("%.h$",""):gsub("/",".")
	local res = includecache [ lib ]
	if res == nil then
		local file_path , err = package.searchpath ( lib , _M.path )
		if not file_path then
			error ( err )
		end
		local mod = assert ( loadfile ( file_path , "bt" , includeENV ) )
		if setfenv then
			setfenv ( mod , includeENV )
		end
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
			ffi      = ffi ;
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

_M.include = include
_M.defines = includeENV
_G.include = include
_G.defines = includeENV

-- Select a signal to use, and block it
include "signal"
local signum = ffi.C.__libc_current_sigrtmin()
local mask = ffi.new ( "sigset_t[1]" )
ffi.C.sigemptyset ( mask )
ffi.C.sigaddset ( mask , signum )
if ffi.C.sigprocmask ( defines.SIG_BLOCK , mask , nil ) ~= 0 then
	error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
end
_M.signum = signum

return _M
