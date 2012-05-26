local ffi = require "ffi"
require "include.stdio"
require "include.unistd"
require "include.strings" -- For strerror

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

dns.lookup_async ( "duckduckgo.com" , 80 , e , function ( addrinfo )
		print ( "Connecting to " .. dns.addrinfo_to_string ( addrinfo ) )

		local sock = socket.new_tcp ( addrinfo.ai_family )
		sock:connect ( addrinfo , e , function ( sock , err )
				assert ( sock , err )
				sock:write ( "GET / HTTP/1.0\r\n\r\n" , nil , e , function ( sock , err )
						assert ( sock , err )
						local len = 2^20
						local buff = ffi.new("char[?]",len)
						e:add_fd ( sock.fd , {
								read = function ( fd )
								local c = ffi.C.read ( fd.fd , buff , len )
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

local t1 = e:add_timer ( 1 , 1 , function ( timer , n )
		print("timer1")
	end )
local t2 = e:add_timer ( 1 , 0.1 , function ( timer , n )
		print("timer2",t1:status())
	end )

-- An example server
local addrinfo = dns.lookup ( "*" , arg[1] )
local serv = socket.new_tcp ( addrinfo.ai_family )
serv:bind ( addrinfo )
serv:listen ( )
e:add_fd ( serv.fd , {
		read = function ( fd )
		local client = serv:accept ( )
			local len = 16
			local buff = ffi.new("char[?]",len)

			local append = 0
			local sent = 0

			local read , write
			local cbs = { }
			function read ( fd )
				local max = len-(append-sent)
				if max == 0 then return end -- Buffer full

				local c = ffi.C.read ( fd.fd , buff+(append%len) , max )
				if c == -1 then
					error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
				end
				append = append + c
				cbs.write = write
				if c == max then
					cbs.read = nil
				end
				e:add_fd ( client.fd , cbs )
			end
			function write ( fd )
				local max = append-sent
				if max == 0 then return end -- Buffer empty

				local c = ffi.C.write ( fd.fd , buff+(sent%len) , max )
				if c == -1 then
					error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
				end
				sent = sent + c

				cbs.read = read
				if c == max then
					cbs.write = nil
				end
				e:add_fd ( client.fd , cbs )
			end
			cbs.read = read
			e:add_fd ( client.fd , cbs )
		end ;
		close = function ( fd )
			e:del_fd ( fd )
		end ;
	} )

while dontquit do
	e:dispatch ( 16 )
end
