---An echo server
-- Uses a circular buffer of the given length

local ffi = require "ffi"
local socket = require "fend.socket"
local dns = require "fend.dns"

return function ( e , addrinfo , len )
	len = len or 2048

	local serv = socket.new_tcp ( addrinfo.ai_family )
	serv:bind ( addrinfo )
	serv:listen ( )

	e:add_fd ( serv , {
			read = function ( serv )
				local client , sockaddr , sockaddr_len = serv:accept ( true )
				if not client then return end
				print("ECHO CLIENT CONNECTED",dns.sockaddr_to_string ( sockaddr , sockaddr_len ))
				local buff = ffi.new("char[?]",len)

				local append = 0
				local sent = 0

				local read , write , close
				function read ( client , cbs )
					local max = len-(append-sent)
					if max == 0 then return end -- Buffer full

					local c , err = client:recv ( buff+(append%len) , max )
					if c == nil then
						if err == "EOF" then
							cbs.close ( client , cbs )
						end
						return
					end

					if c == 0 then return end

					append = append + c
					cbs.write = write
					if c == max then
						cbs.read = nil
					end
					e:add_fd ( client , cbs )
				end
				function write ( client , cbs )
					local max = append-sent
					if max == 0 then return end -- Buffer empty

					local c = assert ( client:send ( buff+(sent%len) , max ) )
					sent = sent + c

					cbs.read = read
					if c == max then
						cbs.write = nil
					end
					e:add_fd ( client , cbs )
				end
				function close ( client , cbs )
					e:del_fd ( client , cbs )
					client:close ( )
				end

				e:add_fd ( client , {
						read  = read ;
						close = close ;
						error = function ( client , cbs )
							error ( "error in echo connection" )
						end
					} )
			end ;
			error = function ( serv , cbs )
				error ( "echo server failure" )
			end ;
		} )

	return serv
end
