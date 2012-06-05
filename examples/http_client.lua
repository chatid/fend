local ffi = require "ffi"
local dns = require "fend.dns"
local socket = require "fend.socket"
local ssl = require "fend.ssl"
local urlparse = require "socket.url".parse

-- Call to handshake an ssl connection
local function handshake ( sock , e , cb )
	local ok , err = sock:dohandshake ( )
	if ok then
		cb ( sock )
	elseif err == "wantread" then
		e:add_fd ( sock:getfile() , {
				read = function ( file , cbs ) return handshake ( sock , e , cb ) end ;
				oneshot = true ;
			} )
	elseif err == "wantwrite" then
		e:add_fd ( sock:getfile() , {
				write = function ( file , cbs ) return handshake ( sock , e , cb ) end ;
				oneshot = true ;
			} )
	else
		cb ( nil , err )
	end
end ;

local function request ( url , e , cb )
	local ret = { }
	local function onincoming ( sock , buff , len )
		table.insert ( ret , ffi.string ( buff , len ) )
		return false
	end
	local function onclose ( sock )
		cb ( table.concat ( ret ) )
	end
	local function onconnect ( sock , err)
		if not sock then error ( "Connection failed: " .. err ) end

		local req = table.concat ( {
			"GET " .. ( url.path or "/" ) .. " HTTP/1.0" ;
			"Host: " .. url.host ;
			"\r\n" ;
		} , "\r\n" )

		local len = 2^20
		local buff = ffi.new("char[?]",len)
		e:add_fd ( sock:getfile() , {
				write = function ( file , cbs )
					assert ( sock:send ( req ) )
					cbs.write = nil
					e:add_fd ( file , cbs )
				end ;
				read = function ( file , cbs )
					local c = assert ( sock:recv ( buff , len ) )
					local new_buffs , new_len = onincoming ( sock , buff , c )
					if new_buffs then
						len = new_len or len
						buff = ffi.new("char[?]",len)
					end
				end ;
				close = function ( file )
					onclose ( sock )
				end ;
			} )
	end

	url = urlparse ( url )
	dns.lookup_async ( url.host , url.scheme or "http" , e , function ( addrinfo )
			print ( "Connecting to " ,dns.addrinfo_to_string ( addrinfo.ai_addr , addrinfo.ai_addrlen ) )

			local sock = socket.new_tcp ( addrinfo.ai_family )
			sock:connect ( addrinfo , e , function ( sock , err )
					if not sock then onconnect ( nil , err ) end
					if url.scheme == "https" then
						handshake ( ssl.wrap ( sock , { mode = "client", protocol = "sslv23" } ) , e , onconnect )
					else
						onconnect ( sock )
					end
				end )
		end )
end

return {
	request = request ;
}
