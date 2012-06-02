require"common"

local ffi = require "ffi"
include "stdio"
include "unistd"
include "strings" -- For strerror
local new_fd = require "fd"
local epoll = require "epoll"
local dns = require "ffi_dns"
local socket = require "ffi_socket"

local dontquit = true

local e = epoll()

local stdin = new_fd ( ffi.C.stdin._fileno )
e:add_fd ( stdin , {
	read = function ( fd )
		local len = 80
		local buff = ffi.new("char[?]",len)
		local c = tonumber ( ffi.C.read ( fd:getfd() , buff , len ) )
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

local port = math.random(49192,65535)
local addrinfo = dns.lookup("*",port)
local echo_serv = require"examples.echo"(e,addrinfo,16)
print("Listening on " .. port )
-- Connect to the echo server
local str = "hi"
local sock = socket.new_tcp ( addrinfo.ai_family )
sock:connect ( addrinfo , e , function ( sock , err )
		assert ( sock , err )
		sock:write(str,#str,e,function(sock,err)
				assert ( sock , err )
				sock:read ( nil , #str , e , function ( sock , buff , len )
						local str2 = ffi.string(buff,len)
						assert ( str==str2)
						print("CONFIRMED ECHO",str2)
					end )
			end )
	end )

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
