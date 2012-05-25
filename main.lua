local ffi = require "ffi"
require "include.stdio"
require "include.unistd"
require "include.strings" -- For strerror

local epoll = require "epoll"
local dns = require "ffi_dns"
local socket = require "ffi_socket"

local dontquit = true

local e = epoll()

local stdin = ffi.C.stdin._fileno
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
		print("CLOSED",fd)
		e:del_fd ( fd )
	end ;
} )

dns.lookup_async ( "duckduckgo.com" , 80 , e , function ( addrinfo )
		print ( "Connecting to " .. dns.addrinfo_to_string ( addrinfo ) )

		local sock = socket.new_IP ( 4 )
		sock:set_blocking ( false )
		sock:connect ( addrinfo.ai_addr , e , function ( sock , err )
				assert ( sock , err )
				sock:write ( "GET / HTTP/1.0\r\n\r\n" , nil , e , function ( sock , err )
						assert ( sock , err )
						local len = 2^20
						local buff = ffi.new("char[?]",len)
						e:add_fd ( sock.fd , {
								read = function ( fd )
									local c = ffi.C.read ( fd , buff , len )
									if c == -1 then
										error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
									end
									ffi.C.write ( 1 , buff , c )
								end ;
								close = function ( fd )
									e:del_fd ( fd )
								end ;
							} )
					end )
			end )
	end )

while dontquit do
	e:dispatch ( 16 )
end
