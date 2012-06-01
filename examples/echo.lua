---An echo server
-- Uses a circular buffer of the given length

local ffi = require "ffi"
local socket = require "ffi_socket"

return function ( e , addrinfo , len )
	len = len or 2048

	local serv = socket.new_tcp ( addrinfo.ai_family )
	serv:bind ( addrinfo )
	serv:listen ( )

	e:add_fd ( serv.fd , {
			read = function ( fd )
				local client = serv:accept ( )
				local buff = ffi.new("char[?]",len)

				local append = 0
				local sent = 0

				local cbs = { }
				local read , write
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
					e:add_fd ( fd , cbs )
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
					e:add_fd ( fd , cbs )
				end
				cbs.read = read
				e:add_fd ( client.fd , cbs )
			end ;
		} )

	return serv
end
