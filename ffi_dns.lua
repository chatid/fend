local ffi = require "ffi"
local bit = require "bit"
local epoll = require "ffi"

local anl = ffi.load ( "anl" )

local netdb = include "netdb"
local signal = include "signal"
include "strings"
include "arpa.inet"


local function addrinfo_to_string ( addrinfo )
	local host_len = netdb.NI_MAXHOST or 1025
	local host = ffi.new ( "char[?]" , host_len )
	local serv_len = netdb.NI_MAXSERV or 32
	local serv = ffi.new ( "char[?]" , serv_len )
	local flags = bit.bor ( netdb.NI_NUMERICHOST , netdb.NI_NUMERICSERV )
	if ffi.C.getnameinfo ( addrinfo.ai_addr , addrinfo.ai_addrlen , host , host_len , serv , serv_len , flags ) ~= 0 then
		error ( ffi.string ( ffi.C.gai_strerror ( err ) ) )
	end
	return ffi.string ( host ) , ffi.string ( serv )
end

local function lookup ( hostname , port )
	local service
	if port then
		service = tostring ( port )
	end
	local res = ffi.new ( "struct addrinfo*[1]" )
	local err = ffi.C.getaddrinfo ( hostname , service , nil , res )
	if err ~= 0 then
		error ( ffi.string ( ffi.C.gai_strerror ( err ) ) )
	end
	return ffi.gc ( res[0] , ffi.C.freeaddrinfo )
end

local counter_i = 0
local function counter ( )
	counter_i = counter_i + 1
	return counter_i
end

-- Select a signal to use, and block it
local signum = ffi.C.__libc_current_sigrtmin()
local mask = ffi.new ( "sigset_t[1]" )
ffi.C.sigemptyset ( mask )
ffi.C.sigaddset ( mask , signum )
if ffi.C.sigprocmask ( signal.SIG_BLOCK , mask , nil ) ~= 0 then
	error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
end

local function lookup_async ( hostname , port , epoll_ob , cb )
	local items = 1
	local list = ffi.new ( "struct gaicb[?]" , items )
	list[0].ar_name = hostname
	if port then
		list[0].ar_service = tostring ( port )
	end

	local id = counter()
	local sigevent = ffi.new ( "struct sigevent" )
	sigevent.sigev_notify = ffi.C.SIGEV_SIGNAL
	sigevent.sigev_signo = signum
	sigevent.sigev_value.sival_int = id

	epoll_ob:add_signal ( signum , id , function ( sig_info )
			--[[if ffi.C.sigprocmask ( signal.SIG_UNBLOCK , mask , nil ) ~= 0 then
				error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
			end--]]
			local err = anl.gai_error ( list[0] )
			if err ~= 0 then
				error ( ffi.string ( anl.gai_strerror ( err ) ) )
			end
			cb ( list[0].ar_result )
		end )

	local err = anl.getaddrinfo_a ( netdb.GAI_NOWAIT , ffi.new ( "struct gaicb*[1]" , {list} ) , items , sigevent )
	if err ~= 0 then
		error ( ffi.string ( ffi.C.strerror ( err ) ) )
	end
end

return {
	addrinfo_to_string = addrinfo_to_string ;
	lookup = lookup ;
	lookup_async = lookup_async ;
}
