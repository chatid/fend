local ffi = require "ffi"

local fend_socket = require "fend.socket"
require "fend.common"
local socket = include "sys/socket"
local errors = include "errno"


local sock_methods = fend_socket.socket_mt.__index
local getsockerr   = fend_socket.getsockerr

function sock_methods:connect ( ... )
	local sockaddr , sockaddr_len , epoll_ob , cb
	if ffi.istype ( "struct addrinfo*" , (...) ) then
		local addrinfo
		addrinfo , epoll_ob , cb = ...
		sockaddr , sockaddr_len = addrinfo.ai_addr , addrinfo.ai_addrlen
	else
		sockaddr , sockaddr_len , epoll_ob , cb = ...
	end

	if ffi.C.connect ( self:getfd() , sockaddr , sockaddr_len ) == -1 then
		local err = ffi.errno ( )
		if err ~= errors.EINPROGRESS then
			cb ( nil , ffi.string ( ffi.C.strerror ( err ) ) )
			return
		end
	end
	epoll_ob:add_fd ( self.file , {
			write = function ( file )
				local err = getsockerr ( file )
				if err ~= 0 then
					cb ( nil , ffi.string ( ffi.C.strerror ( err ) ) )
					return
				end
				self.connected = true
				cb ( self )
			end ;
			oneshot = true
		} )
end

function sock_methods:read ( buff , len , epoll_ob , cb )
	if not buff then
		buff = ffi.new ( "char[?]" , len )
	end
	local have = 0
	epoll_ob:add_fd ( self.file , {
			read = function ( file )
				local c , err = self:recv ( buff+have , len-have )
				if not c then
					epoll_ob:del_fd ( file )
					cb ( self , nil , err , buff , have ) -- Partial result
					return
				end
				have = have + c
				if have == len then
					epoll_ob:del_fd ( file )
					cb ( self , buff , c )
					return
				end
			end ;
			close = function ( file )
				cb ( self , nil , "closed" , buff , have ) -- Partial result
			end ;
			error = function ( file , err )
				cb ( self , nil , err , buff , have ) -- Partial result
			end
		} )
end

function sock_methods:write ( buff , len , epoll_ob , cb )
	if type ( buff ) == "string" then
		len = #buff
		buff = ffi.cast ( "const char *" , buff )
	end
	local bytes_written = 0
	epoll_ob:add_fd ( self.file , {
			write = function ( file )
				local c , err = self:send ( buff+bytes_written , len-bytes_written )
				if not c then
					epoll_ob:del_fd ( file )
					cb ( self , nil , err , bytes_written )
					return
				end
				bytes_written = bytes_written + c
				if bytes_written < len then
					buff = buff + c
				else
					epoll_ob:del_fd ( file )
					cb ( self , bytes_written )
					return
				end
			end ;
			error = function ( file , err )
				cb ( self , nil , err , bytes_written )
			end
		} )
end
