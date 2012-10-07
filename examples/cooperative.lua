local co_create = coroutine.create
local co_yield = coroutine.yield
local co_resume = coroutine.resume
local co_status = coroutine.status

local ffi = require "ffi"

local function handle_resume ( self , ok , ... )
	if not ok then
		local err = ...
		error ( err )
	elseif (...) then
		local sock , want = ...
		self.dispatcher:add_fd ( sock , {
				oneshot = true ;
				edge = true ;
				close = self.cb_handler ;
				error = self.cb_handler ;
				[ want ] = self.cb_handler ;
			} )
	elseif co_status ( self.co ) == "dead" then -- Finished
		return
	else
		error ( "bad yield" )
	end
end

local methods = { }
local mt = {
	__call = function ( self , ... )
		return handle_resume ( self , co_resume ( self.co , self , ... ) )
	end ;
	__index = methods ;
}

function methods:send ( sock , buff , len )
	if not ffi.istype ( "char*" , buff ) then
		len = len or #buff
		buff = ffi.cast ( "const char*" , buff )
	end
	local sent = 0
	while true do
		local n , err = sock:send ( buff+sent , len-sent )
		if not n then
			return n , err
		end
		sent = sent + n
		if sent >= len then break end
		local sock , ev = co_yield ( sock , "write" )
		if ev ~= "write" then
			return nil , ev , sent
		end
	end
	return sent
end

function methods:recv ( sock , buff , len )
	local got = 0
	while true do
		local n , err = sock:recv ( buff+got , len-got )
		if not n then
			return n , err
		end
		got = got + n
		if got >= len then break end
		local sock , ev = co_yield ( sock , "read" )
		if ev ~= "read" then
			return nil , ev , got
		end
	end
	return got
end
methods.receive = methods.recv

-- The function retuns an object with methods `recv` and `send`
-- These methods yield until they have completed; if an error occurs they return nil , err
-- Calling the returned value will raise an error inside of send/recv
local function wrap ( dispatcher , func )
	local self
	self = setmetatable ( {
			co = co_create ( func ) ;
			dispatcher = dispatcher ;
			cb_handler = function ( sock , cbs , evtype )
				return self ( evtype )
			end ;
		} , mt )
	return self
end

return {
	wrap = wrap ;
}
