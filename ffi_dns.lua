local ffi = require "ffi"
local epoll = require "ffi"

local anl = ffi.load ( "anl" )

local netinet_in = require "include.netinet.in"
local netdb = require "include.netdb"
require "include.strings"
local signal = require "include.signal"
require "include.arpa.inet"


local function addrinfo_to_string ( addr )
	if addr.ai_family == 2 then -- IPv4
		local sock_addr = ffi.cast ( "struct sockaddr_in*" , addr.ai_addr )
		return ffi.string(ffi.C.inet_ntoa(sock_addr.sin_addr))..":"..ffi.C.ntohs(sock_addr.sin_port)
	else
		error ( "NYI" )
	end
end

local function lookup ( hostname , port )
	local service
	if port then
		service = tostring ( port )
	end
	local res = ffi.new ( "struct addrinfo*[1]" )
	ffi.C.getaddrinfo ( hostname , service , nil , res )
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
	-- Hints
	--list[0].ar_request.ai_family = netinet_in.AF_UNSPEC

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

	local err = anl.getaddrinfo_a ( netdb.GAI_NOWAIT , ffi.new ( "struct gaicb*[1]" , list ) , items , sigevent )
	if err ~= 0 then
		error ( ffi.string ( ffi.C.strerror ( err ) ) )
	end
end

return {
	addrinfo_to_string = addrinfo_to_string ;
	lookup = lookup ;
	lookup_async = lookup_async ;
}
