local setmetatable = setmetatable
local tonumber = tonumber
local floor = math.floor

local ffi = require "ffi"
local bit = require "bit"
local new_file = require "fend.file"
require "fend.common"
include "stdio"
include "string"
include "sys/timerfd"
include "time"

local file_to_timer = setmetatable ( { } , { __mode = "k" ; } )
local timerspec = ffi.new ( "struct itimerspec[1]" )
local timer_cbs = {
	read = function ( file , cbs )
		local timer = file_to_timer [ file ]
		local expired = ffi.new ( "uint64_t[1]" )
		local c = tonumber ( ffi.C.read ( file:getfd() , expired , ffi.sizeof ( expired ) ) )
		if c == -1 then
			timer.cb ( nil , ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
		end
		--assert ( c == ffi.sizeof ( expired ) )
		local start , interval = timer.cb ( timer , expired[0] )
		if start then
			timer:set ( start , interval )
		elseif start == false then
			timer:disarm ( )
		end
	end ;
	close = function ( file , cbs )
		error ( "timerfd closed" )
	end ;
	error = function ( file , cbs )
		error ( "timerfd error" )
	end ;
	edge = true ;
}
local timer_mt = {
	__index = {
		set = function ( timer , value , interval , flags )
			flags = flags or 0
			interval = interval or 0
			timerspec[0].it_interval.tv_sec = floor ( interval )
			timerspec[0].it_interval.tv_nsec = ( interval % 1 )*1e9
			timerspec[0].it_value.tv_sec = floor ( value )
			timerspec[0].it_value.tv_nsec = ( value % 1 )*1e9
			if ffi.C.timerfd_settime ( timer.file:getfd() , flags , timerspec , nil ) == -1 then
				error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
			end
			timer.dispatcher:add_fd ( timer.file , timer_cbs )
		end ;
		disarm = function ( timer )
			timer:set ( 0 , 0 )
			timer.dispatcher:del_fd ( timer.file )
		end ;
		status = function ( timer )
			if ffi.C.timerfd_gettime ( timer.file:getfd() , timerspec ) == -1 then
				error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
			end
			return tonumber ( timerspec[0].it_value.tv_sec ) + tonumber ( timerspec[0].it_value.tv_nsec ) / 1e9 ,
				tonumber ( timerspec[0].it_interval.tv_sec ) + tonumber ( timerspec[0].it_interval.tv_nsec ) / 1e9
		end ;
	} ;
}

--- Create a timer that creates events.
-- start is how long from now to fire the timer; 0 is a disarmed timer
-- interval (optional) is the period of the timer. Defaults to never (0)
-- cb is the callback to call when the timer fires; it will receive the timer object and the interval; return values from callback change the timer's start and interval
-- returns a timer object that has methods `set`, `disarm` and `status`
local function add_timer ( dispatcher , start , interval , cb )
	local timerfd = ffi.C.timerfd_create ( defines.CLOCK_MONOTONIC , bit.bor ( ffi.C.TFD_NONBLOCK ) )
	if timerfd == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	timerfd = new_file ( timerfd )
	local timer = setmetatable ( {
			file = timerfd ;
			dispatcher = dispatcher ;
			cb = cb ;
		} , timer_mt )
	file_to_timer [ timerfd ] = timer

	timer:set ( start , interval )

	return timer
end

return {
	add = add_timer ;
}
