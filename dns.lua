local ffi = require "ffi"
local bit = require "bit"

local anl = ffi.load ( "anl" )
require "fend.common"
local netdb = include "netdb"
local signal = include "signal"
include "strings"
include "arpa.inet"

local function addrinfo_to_string ( sockaddr , addr_len )
	local host_len = netdb.NI_MAXHOST or 1025
	local host = ffi.new ( "char[?]" , host_len )
	local serv_len = netdb.NI_MAXSERV or 32
	local serv = ffi.new ( "char[?]" , serv_len )
	local flags = bit.bor ( netdb.NI_NUMERICHOST , netdb.NI_NUMERICSERV )
	if ffi.C.getnameinfo ( sockaddr , addr_len , host , host_len , serv , serv_len , flags ) ~= 0 then
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

-- Select a signal to use, and block it
local signum = ffi.C.__libc_current_sigrtmin()
local mask = ffi.new ( "sigset_t[1]" )
ffi.C.sigemptyset ( mask )
ffi.C.sigaddset ( mask , signum )
if ffi.C.sigprocmask ( signal.SIG_BLOCK , mask , nil ) ~= 0 then
	error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
end

--- Lookup the given hostname and port
-- Adds a watch for completion to `epoll_ob`, and when done calls
-- `cb` is called when done, gets argument of an `addrinfo`, or `nil , err` on failure
-- returns a table with methods:
--	`wait`: blocks until the lookup is completed (or until `timeout`). returns boolean indicating success/failure
local function lookup_async ( hostname , port , epoll_ob , cb )
	local items = 1
	local list = ffi.new ( "struct gaicb[?]" , items )
	list[0].ar_name = hostname
	if port then
		list[0].ar_service = tostring ( port )
	end

	local sigevent = ffi.new ( "struct sigevent" )
	sigevent.sigev_notify = ffi.C.SIGEV_SIGNAL
	sigevent.sigev_signo = signum
	sigevent.sigev_value.sival_ptr = list

	local cb_id = epoll_ob:add_signal ( signum , function ( sig_info , cb_id )
			local retlist = ffi.cast ( "struct gaicb*" , sig_info[0].ssi_ptr )
			if retlist == list then
				local err = anl.gai_error ( retlist+0 )
				if err == 0 then
					cb ( retlist[0].ar_result )
				else
					cb ( nil , ffi.string ( anl.gai_strerror ( err ) ) )
				end
				epoll_ob:del_signal ( signum , cb_id )
			end
		end )

	local err = anl.getaddrinfo_a ( netdb.GAI_NOWAIT , ffi.new ( "struct gaicb*[1]" , {list} ) , items , sigevent )
	if err ~= 0 then
		error ( ffi.string ( ffi.C.strerror ( err ) ) )
	end

	return {
		wait = function ( t , timeout )
			local timespec = ffi.NULL
			if timeout then
				timespec = ffi.new ( "struct timespec[1]" )
				timespec[0].tv_sec = math.floor ( timeout )
				timespec[0].tv_nsec = ( timeout % 1 ) * 1e9
			end
			local err = anl.gai_suspend ( ffi.new ( "const struct gaicb*[1]" , {list} ) , items , timespec )
			if err == 0 then
				local err = anl.gai_error ( list[0] )
				if err == 0 then
					cb ( list[0].ar_result )
				else
					cb ( nil , ffi.string ( anl.gai_strerror ( err ) ) )
				end
				epoll_ob:del_signal ( signum , cb_id )
				return true
			elseif err == netdb.EAI_AGAIN or err == netdb.EAI_INTR then
				return false
			else
				error ( ffi.string ( anl.gai_strerror ( err ) ) )
			end
		end ;
	}
end

return {
	addrinfo_to_string = addrinfo_to_string ;
	lookup = lookup ;
	lookup_async = lookup_async ;
}
