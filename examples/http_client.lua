local tonumber = tonumber
local pairs = pairs
local tconcat = table.concat
local tinsert = table.insert
local strformat = string.format

local ffi = require "ffi"
local bit = require "bit"
local dns        = require "fend.dns"
local socket     = require "fend.socket"
require "fend.socket_helpers"
local ssl        = require "fend.ssl"
local handshake  = require "fend.ssl_handshake".handshake
local urlparse   = require "socket.url".parse
local buff_tools = require "fend.buff_tools"
require "fend.common"
include "netdb"
include "sys/socket"
include "netinet/in"

local hints = ffi.new ( "const struct addrinfo[1]" , { {
	ai_flags    = bit.bor ( defines.AI_PASSIVE , defines.AI_V4MAPPED , defines.AI_ADDRCONFIG ) ;
	ai_family   = defines.AF_UNSPEC ;
	ai_socktype = ffi.C.SOCK_STREAM ;
	ai_protocol = 0 ;
} } )

local function request ( url , options , e , cb )
	local ret = { headers = { } , body = { } }
	local state = "new"
	local saved = ""
	local lastheader = nil
	local bodylen = 0
	local function onclose ( err )
		ret.body = tconcat(ret.body)
		if state == "done" then
			cb ( ret )
		else
			cb ( ret , err or "incomplete" )
		end
	end
	local function onincoming ( sock , buff , len )
		if state == "new" or state == "headers" then
			local from = 0
			while true do
				local s , e = buff_tools.find ( buff+from , len-from , buff_tools.new"\r\n" )
				if not s then break end
				local line = saved .. ffi.string ( buff+from , s )

				if state == "new" then
					local major , minor , code , reason = line:match("HTTP/(%d+).(%d+) (%d%d%d) (.*)")
					if not major then
						onclose ( "Invalid Response: " .. line )
						return true
					end
					ret.major , ret.minor , ret.code , ret.status = tonumber(major) , tonumber(minor) , tonumber(code) , reason
					state = "headers"
				elseif #line == 0 then
					state = "body"
					from = from+e+1
					break
				else -- state == "headers"
					local header_cont = line:match("^[ \t]+(.*)")
					if header_cont then
						if not lastheader then
							onclose ( "Header continuation in first line" )
							return true
						end
						ret.headers [ lastheader ] = ret.headers [ lastheader ] .. " " .. header_cont
					else
						local name , value = line:match ( "([^:]+):%s*(.+)" )
						if not name then
							onclose ( "Invalid Header: " .. line )
							return true
						end
						lastheader = name
						ret.headers [ name ] = value
					end
				end
				saved = ""
				from = from+e+1
			end
			saved = saved .. ffi.string ( buff+from , len-from )
			buff = ffi.NULL
			len = 0
		end

		if state == "body" then
			local str = saved .. ffi.string ( buff , len )
			local transfer_encoding = ret.headers["Transfer-Encoding"]
			local content_length = tonumber ( ret.headers["Content-Length"] )
			local content_type = ret.headers["Content-Type"]

			if transfer_encoding and transfer_encoding ~= "identity" then -- Chunked
				local cursor = 1
				while true do
					local s , e , chunk_size , chunk_extension = str:find("(%x+)(.-)\r\n",cursor)
					if not s then
						saved = str:sub ( cursor )
						return false
					end
					chunk_size = tonumber ( chunk_size , 16 )
					if chunk_size == 0 then break end
					if #str-e-2 < chunk_size then
						saved = str:sub ( cursor )
						return false
					end
					tinsert ( ret.body , str:sub(e+1,e+chunk_size) )
					if str:sub(e+1+chunk_size,e+1+chunk_size+1) ~= "\r\n" then
						onclose ( "Malformed chunked data" )
						return true
					end
					cursor = e+1+chunk_size+2
				end
				state = "done"
			elseif content_length then
				tinsert ( ret.body , str )
				bodylen = bodylen + #str
				if bodylen >= content_length then
					state = "done"
				end
				saved = ""
			elseif content_type and content_type:match("^multipart/byteranges") then
				onclose ( "Byte ranges unsupported" )
				return true
			else
				onclose ( "Unknown message length" )
				return true
			end
		end
		if state == "done" then
			onclose ( nil )
			return true
		end
		return false
	end

	local function onconnect ( sock , err)
		if not sock then onclose ( "Connection failed: " .. err ) return end

		local headers = {
			Host = url.host ;
			["User-Agent"] = "fend" ;
		}
		-- Copy headers from requester
		if options.headers then
			for name , value in pairs ( options.headers ) do
				headers [ name ] = value
			end
		end
		local path = url.path or "/"
		if url.query then
			path = path .. "?" .. url.query
		end
		local req , n = {
			strformat ( "%s %s HTTP/%d.%d\r\n" , options.method or "GET" , path , 1 , 1 ) ;
		} , 2
		for name , value in pairs ( headers ) do
			req [ n ] = name
			req [ n+1 ] = ": "
			req [ n+2 ] = value
			req [ n+3 ] = "\r\n"
			n = n + 4
		end
		req [ n ] = "\r\n"
		req = tconcat ( req )

		local len = 2^20
		local buff = ffi.new("char[?]",len)
		e:add_fd ( sock , {
				write = function ( sock , cbs )
					local sent , err = sock:send ( req )
					if sent == nil then
						if err == "wantread" then
							-- Wait till readable
							local old_read , old_write = cbs.read , cbs.write
							cbs.read , cbs.write = function ( sock , cbs )
								cbs.write = old_write
								cbs.read = old_read
								e:add_fd ( sock , cbs )
							end , nil
							e:add_fd ( sock , cbs )
							return
						elseif err == "wantwrite" then
							return
						else
							onclose ( err )
							e:del_fd ( sock , cbs )
							sock:close ( )
							return
						end
					elseif sent < #req then
						req = req:sub ( sent+1 , -1 )
					else --Successful
						-- Remove write handler; we're done
						cbs.write = nil
						e:add_fd ( sock , cbs )
					end
				end ;
				read = function ( sock , cbs )
					local c , err = sock:recv ( buff , len )
					if c == nil then
						if err == "wantread" then
							return
						elseif err == "wantwrite" then
							-- Wait till writable
							local old_read , old_write = cbs.read , cbs.write
							cbs.read , cbs.write = nil , function ( sock , cbs )
								cbs.write = old_write
								cbs.read = old_read
								e:add_fd ( sock , cbs )
							end
							e:add_fd ( sock , cbs )
							return
						else
							onclose ( err )
							e:del_fd ( sock , cbs )
							sock:close ( )
							return
						end
					end
					if onincoming ( sock , buff , c ) then
						e:del_fd ( sock , cbs )
						sock:close ( )
						return
					end
					if c ~= 0 then
						return cbs.read ( sock , cbs )
					end
				end ;
				close = function ( sock , cbs )
					onclose ( "HUP" )
					e:del_fd ( sock , cbs )
					sock:close ( )
				end ;
				error = function ( sock , cbs )
					error ( "error in http client" )
				end ;
				edge = true ;
			} )
	end

	url = urlparse ( url )
	local orig_addrinfo -- Gotta keep it around so it doesn't get collected
	local function addrinfo_callback ( addrinfo , err )
		if not addrinfo then onconnect ( err ) return end
		if not orig_addrinfo then orig_addrinfo = addrinfo end

		local sock = socket.new_tcp ( addrinfo.ai_family )
		sock:connect ( addrinfo , e , function ( sock , err )
				if not sock then
					if addrinfo.ai_next ~= ffi.NULL then
						addrinfo_callback ( addrinfo.ai_next )
					else
						onconnect ( nil , "Unable to connect to server" )
					end
					return
				end
				if url.scheme == "https" then
					local timer = e:add_timer ( 5 , 0 , function ( timer , n )
							e:del_fd ( sock )
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
	end
	dns.lookup_async ( url.host , url.port or url.scheme or "http" , hints , e , addrinfo_callback )
end

return {
	request = request ;
}
