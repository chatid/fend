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
	local ret = { headers = { } , body = { } }
	local onincoming
	local state = "new"
	local saved = ""
	local bodylen = 0
	local function onclose ( sock )
		ret.body = table.concat(ret.body)
		cb ( ret )
	end
	function onincoming ( sock , buff , len )
		local str = ffi.string ( buff , len )
		if state == "new" or state == "headers" then
			local from = 0
			while true do
				local s , e = str:find ( "\r\n" , from+1 )
				if not s then break end
				local line = saved .. str:sub ( from+1 , s-1 )
				if #line == 0 then
					state = "body"
					from = e
					break
				end
				if state == "new" then
					ret.major , ret.minor , ret.code , ret.status = line:match("HTTP/(%d).(%d) (%d+) ?(.*)")
					state = "headers"
				elseif state == "headers" then
					local name , value = line:match ( "([^:]+): (.+)" )
					if not name then cb ( nil , "Invalid Header" ) end
					ret.headers [ name ] = value
				end
				saved = ""
				from = e
			end
			saved = saved .. str:sub ( from+1 )
			str = saved
		end
		if state == "body" then
			table.insert ( ret.body , str )
			bodylen = bodylen + #str
			if bodylen >= tonumber ( ret.headers["Content-Length"] ) then
				state = "done"
				sock:close ( )
			end
		end
		return false
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
					local sent , err = sock:send ( req )
					if sent == nil then
						if err == "wantread" then
							-- Wait till readable
							local old_read , old_write = cbs.read , cbs.write
							cbs.read , cbs.write = function ( file , cbs )
								cbs.write = old_write
								cbs.read = old_read
								e:add_fd ( file , cbs )
							end , nil
							e:add_fd ( file , cbs )
							return
						elseif err == "wantwrite" then
							return
						else
							cb ( ret , err )
							return
						end
					elseif sent < #req then
						req = req:sub ( sent+1 , -1 )
					else --Successful
						-- Remove write handler; we're done
						cbs.write = nil
						e:add_fd ( file , cbs )
					end
				end ;
				read = function ( file , cbs )
					local c , err = sock:recv ( buff , len )
					if c == nil then
						if err == "wantread" then
							return
						elseif err == "wantwrite" then
							-- Wait till writable
							local old_read , old_write = cbs.read , cbs.write
							cbs.read , cbs.write = nil , function ( file , cbs )
								cbs.write = old_write
								cbs.read = old_read
								e:add_fd ( file , cbs )
							end
							e:add_fd ( file , cbs )
							return
						elseif err == "EOF" then
							cbs.close ( file , cbs )
							return
						else
							cb ( ret , err )
							return
						end
					end
				end ;
				rdclose = function ( file , cbs )
					e:del_fd ( file , cbs )
					cbs.read ( file , cbs )
					onclose ( sock )
				end ;
				close = function ( file , cbs )
					e:del_fd ( file , cbs )
					onclose ( sock )
				end ;
			} )
	end

	url = urlparse ( url )
	dns.lookup_async ( url.host , url.scheme or "http" , e , function ( addrinfo , err )
			if not addrinfo then cb ( ret , err ) return end

			local sock = socket.new_tcp ( addrinfo.ai_family )
			sock:connect ( addrinfo , e , function ( sock , err )
					if not sock then onconnect ( nil , err ) end
					if url.scheme == "https" then
						local timer = e:add_timer ( 5 , 0 , function ( timer , n )
								e:del_fd ( sock:getfile() )
								onconnect ( nil , "handshake timeout" )
							end )
						handshake ( ssl.wrap ( sock , { mode = "client", protocol = "sslv23" } ) , e , function ( ... )
								timer:disarm ( )
								onconnect ( ... )
							end )
					else
						onconnect ( sock )
					end
				end )
		end )
end

return {
	request = request ;
}
