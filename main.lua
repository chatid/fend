require"common"

local ffi = require "ffi"
include "stdio"
include "unistd"
include "strings" -- For strerror

local epoll = require "epoll"
local dns = require "ffi_dns"
local socket = require "ffi_socket"

local dontquit = true

local e = epoll()

local stdin = ffi.new ( "fd_t" , ffi.C.stdin._fileno )
e:add_fd ( stdin , {
	read = function ( fd )
		local len = 80
		local buff = ffi.new("char[?]",len)
		local c = ffi.C.read ( fd , buff , len )
		if c == -1 then
			error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
		end
		local str = ffi.string(buff,c)
		if str:match("^quit%s") then dontquit = false end
	end ;
	close = function ( fd )
		e:del_fd ( fd )
	end ;
} )

require"examples.http_client".request ( "http://google.com" , e , function ( b ) print(b) end )

local t1 = e:add_timer ( 1 , 1 , function ( timer , n )
		print("timer1")
	end )
local t2 = e:add_timer ( 1 , 0.1 , function ( timer , n )
		print("timer2",t1:status())
	end )


local echo_serv = require"examples.echo"(e,dns.lookup("*",assert(arg[1],"No port given")),16)
do -- Capture ^C
	local signal = include "signal"
	local mask = ffi.new ( "__sigset_t[1]" )
	e:add_signal ( signal.SIGINT , 0 , function ( siginfo )
			if dontquit then
				dontquit = false
			else
				os.exit ( 1 )
			end
		end )
	ffi.C.sigemptyset ( mask )
	ffi.C.sigaddset ( mask , signal.SIGINT )
	if ffi.C.sigprocmask ( signal.SIG_BLOCK , mask , nil ) ~= 0 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
end

while dontquit do
	e:dispatch ( 16 )
end
