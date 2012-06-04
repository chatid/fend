local ffi = require "ffi"
local dns = require "fend.dns"
local socket = require "fend.socket"
local ssl = require "fend.ssl"
local urlparse = require "socket.url".parse

local function request ( url , e , cb )
	url = urlparse ( url )
	dns.lookup_async ( url.host , url.scheme or "http" , e , function ( addrinfo )
			print ( "Connecting to " ,dns.addrinfo_to_string ( addrinfo.ai_addr , addrinfo.ai_addrlen ) )

			local sock = socket.new_tcp ( addrinfo.ai_family )
			sock:connect ( addrinfo , e , function ( sock , err )
					assert ( sock , err )
					local fd = sock.fd

					local ready
 					-- Call to handshake an ssl connection
					local function handshake ( )
						local ok , err = sock:dohandshake ( )
						if ok then
							ready ( )
						elseif err == "wantread" then
							e:add_fd ( fd , {
									read = handshake ;
									oneshot = true ;
								} )
						elseif err == "wantwrite" then
							e:add_fd ( fd , {
									write = handshake ;
									oneshot = true ;
								} )
						else
							error ( err )
						end
					end ;

					function ready ( )
						local req = table.concat ( {
							"GET " .. ( url.path or "/" ) .. " HTTP/1.0" ;
							"Host: " .. url.host ;
							"\r\n" ;
						} , "\r\n" )

						local len = 2^20
						local buff = ffi.new("char[?]",len)
						local have = 0
						e:add_fd ( fd , {
								write = function ( fd , cbs )
									assert ( sock:send ( req ) )
									cbs.write = nil
									e:add_fd ( fd , cbs )
								end ;
								read = function ( fd , cbs )
									local c = assert ( sock:recv ( buff+have , len-have ) )
									have = have + c
									if have == len then
										cbs.read = nil
										e:add_fd ( fd , cbs )
									end
								end ;
								close = function ( fd )
									cb ( ffi.string ( buff , have ) )
								end ;
							} )
					end

					if url.scheme == "https" then
						sock = ssl.wrap ( sock , { mode = "client", protocol = "sslv23" } )
						handshake ( )
					else
						ready ( )
					end
				end )
		end )
end

return {
	request = request ;
}
