local ffi = require "ffi"
local new_fd = require "fd"

require "include.stdio"
local errors = require "include.errno"
local socket = require "include.sys.socket"
local netinet_in = require "include.netinet.in"
require "include.arpa.inet"

local sock_methods = { }
local sock_mt = { __index = sock_methods ; }

local function new_sock ( fd , type )
	return setmetatable ( {
			fd = fd ;
			type = type ;
		} , sock_mt )
end

function sock_methods:getfd ( )
	return self.fd:getfd ( )
end

function sock_methods:close ( )
	if ffi.C.shutdown ( self.fd:getfd() , ffi.C.SHUT_RDWR ) ~= 0 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	return self.fd:close ( )
end

local function getsockerr ( fd  )
	local err = ffi.new ( "int[1]" )
	local err_len = ffi.new ( "int[1]" , ffi.sizeof ( err ) )
	if ffi.C.getsockopt ( fd.fd , socket.SOL_SOCKET , socket.SO_ERROR , err , err_len ) ~= 0 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	return err[0]
end

function sock_methods:connect ( addrinfo , epoll_ob , cb )
	if ffi.C.connect ( self:getfd() , addrinfo.ai_addr , addrinfo.ai_addrlen ) == -1 then
		local err = ffi.errno ( )
		if err ~= errors.EINPROGRESS then
			cb ( nil , ffi.string ( ffi.C.strerror ( err ) ) )
		end
	end
	epoll_ob:add_fd ( self.fd , { write = function ( fd )
			local err = getsockerr ( fd )
			if err ~= 0 then
				cb ( nil , ffi.string ( ffi.C.strerror ( err ) ) )
			end
			self.connected = true
			cb ( self )
		end , oneshot = true } )
	self.connected = false
end

function sock_methods:bind ( addrinfo )
	if ffi.C.bind ( self:getfd() , addrinfo.ai_addr , addrinfo.ai_addrlen ) == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	self.bound = true
end

function sock_methods:listen ( backlog )
	backlog = backlog or 128
	if ffi.C.listen ( self:getfd() , backlog ) == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	self.listening = true
end

function sock_methods:accept ( )
	local clientfd = ffi.C.accept ( self:getfd() , nil , nil )
	if clientfd == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	local client = new_sock ( new_fd ( clientfd ) , self.type )
	client.connected = true
	client.fd:set_blocking ( false )
	return client
end

function sock_methods:read ( buff , len , epoll_ob , cb )
	if not buff then
		buff = ffi.new ( "char[?]" , len )
	end
	local have = 0
	epoll_ob:add_fd ( self.fd , {
			read = function ( fd )
				local c = ffi.C.read ( fd:getfd() , buff+have , len-have )
				if c == -1 then
					epoll_ob:del_fd ( fd )
					cb ( self , nil , ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) , buff , have ) -- Partial result
					return
				end
				have = have + c
				if have == len then
					epoll_ob:del_fd ( fd )
					cb ( self , buff , c )
					return
				end
			end ;
			close = function ( fd )
				cb ( self , nil , "closed" , buff , have ) -- Partial result
			end ;
			error = function ( fd , err )
				cb ( self , nil , err , buff , have ) -- Partial result
			end
		} )
end

function sock_methods:write ( buff , len , epoll_ob , cb )
	if type ( buff ) == "string" then
		len = #buff
	end
	local bytes_written = 0
	epoll_ob:add_fd ( self.fd , {
			write = function ( fd )
				local c = ffi.C.write ( fd:getfd() , buff , len-bytes_written )
				if c == -1 then
					epoll_ob:del_fd ( fd )
					cb ( self , nil , ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) , bytes_written )
					return
				end
				bytes_written = bytes_written + c
				if bytes_written < len then
					buff = buff + c
				else
					epoll_ob:del_fd ( fd )
					cb ( self , bytes_written )
				end
			end ;
			error = function ( fd , err )
				cb ( self , nil , err , bytes_written )
			end
		} )
end

-- Create tcp/ipv? streaming socket
local function new_tcp ( domain )
	local fd = ffi.C.socket ( domain , ffi.C.SOCK_STREAM , ffi.C.IPPROTO_TCP )
	if fd == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	local sock = new_sock ( new_fd ( fd ) , "TCP" )
	sock.fd:set_blocking ( false )
	return sock
end


return {
	new_tcp = new_tcp ;
}
