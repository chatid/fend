local epoll_ob = require "ffi_ev.epoll"()
local addrinfo = require "ffi_ev.dns".lookup ( "google.com" , 443 )
local sock = require "ffi_ev.socket".new_tcp(2)
sock:connect ( addrinfo , epoll_ob , function ( sock , err )
		assert ( sock , err )
		local wrap_sock = wrap ( sock , { mode="client" , protocol="tlsv1" } )
		local len = 2048
		local buff = ffi.new ( "char[?]",len)

		ssl.wrap_sock:recv ( buff , len )
	end )

while true do epoll_ob:dispatch() end
