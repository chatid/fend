local ffi = require "ffi"
require "fend.common"
include "stdio"
include "unistd"
include "strings" -- For strerror
local new_file = require "fend.file"
local epoll = require "fend.epoll"
local dns = require "fend.dns"
local socket = require "fend.socket"

local dontquit = true

local e = epoll()

local stdin = new_file ( io.stdin )
e:add_fd ( stdin , {
	read = function ( file )
		local len = 80
		local buff = ffi.new("char[?]",len)
		local c = tonumber ( ffi.C.read ( file:getfd() , buff , len ) )
		if c == -1 then
			error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
		end
		local str = ffi.string(buff,c)
		if str:match("^quit%s") then dontquit = false end
	end ;
	close = function ( file )
		e:del_fd ( file )
	end ;
} )

require "fend.examples.http_client".request ( "https://mail.google.com/mail/" , e , function ( b ) print(b) end )

local t1 = e:add_timer ( 1 , 1 , function ( timer , n )
		print("timer1")
	end )
local t2 = e:add_timer ( 1 , 0.1 , function ( timer , n )
		print("timer2",t1:status())
	end )

math.randomseed ( os.time() )
local port = math.random(49192,65535)
local addrinfo = dns.lookup("*",port)
local echo_serv = require"fend.examples.echo"(e,addrinfo,16)
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
						sock:close()
					end )
			end )
	end )

do -- Capture ^C
	local signal = include "signal"
	local mask = ffi.new ( "__sigset_t[1]" )
	e:add_signal ( signal.SIGINT , function ( siginfo )
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

local id = dns.lookup_async ( "github.com" , 80 , e , function (addrinfo,err)
		assert ( addrinfo , err )
		print("DNS WORKED: " , dns.addrinfo_to_string ( addrinfo.ai_addr , addrinfo.ai_addrlen ) )
	end )
assert(id:wait(),"DNS waiting failed")

while dontquit do
	e:dispatch ( 16 )
end
