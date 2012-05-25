local ffi = require "ffi"
local bit = require "bit"

require "include.stdio"
local errors = require "include.errno"
local socket = require "include.sys.socket"
local netinet_in = require "include.netinet.in"
require "include.arpa.inet"
local fcntl = require "include.fcntl"

local sock_methods = { }
local sock_mt = {
	__index = sock_methods ;
	__gc = function ( sock )
		ffi.C.close ( sock.fd )
	end ;
}

local function new_sock ( fd , type )
	return setmetatable ( {
			fd = fd ;
			type = type ;
		} , sock_mt )
end

local function getsockerr ( fd  )
	local err = ffi.new ( "int[1]" )
	local err_len = ffi.new ( "int[1]" , ffi.sizeof ( err ) )
	if ffi.C.getsockopt ( fd , socket.SOL_SOCKET , socket.SO_ERROR , err , err_len ) ~= 0 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	return err[0]
end

function sock_methods:connect ( sockaddr , size , epoll_ob , cb )
	local sockaddr_p = ffi.new ( "struct sockaddr*" , sockaddr )
	if ffi.C.connect ( self.fd , sockaddr_p , size ) == -1 then
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
			cb ( self )
		end , oneshot = true } )
end

function sock_methods:set_blocking ( bool )
	local flags = ffi.C.fcntl ( self.fd , fcntl.F_GETFL )
	if not bool then
		flags = bit.bor ( flags , fcntl.O_NONBLOCK )
	else
		flags = bit.band ( flags , bit.bnot ( fcntl.O_NONBLOCK ) )
	end
	ffi.C.fcntl ( self.fd , fcntl.F_SETFL , ffi.cast ( "int" , flags ) )
end

function sock_methods:getfd ( )
	return self.fd
end

function sock_methods:read ( buff , len , epoll_ob , cb )
	if not buff then
		buff = ffi.new ( "char[?]" , len )
	end
	epoll_ob:add_fd ( self.fd , { read = function ( fd )
				local c = ffi.C.read ( fd , buff , len )
				if c == -1 then
					error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
				end
				cb ( self , buff , c )
			end ;
			oneshot = true ;
		} )
end

function sock_methods:write ( buff , len , epoll_ob , cb )
	if type ( buff ) == "string" then
		len = #buff
	end
	local bytes_written = 0
	epoll_ob:add_fd ( self.fd , { write = function ( fd )
				local c = ffi.C.write ( fd , buff , len-bytes_written )
				if c == -1 then
					cb ( nil , ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
				end
				bytes_written = bytes_written + c
				if bytes_written < len then
					buff = buff + c
				else
					epoll_ob:del_fd ( fd )
					cb ( self )
				end
			end ;
		} )
end

-- Create tcp/ipv? streaming socket
local function new_tcp ( domain )
	local fd = ffi.C.socket ( domain , ffi.C.SOCK_STREAM , ffi.C.IPPROTO_TCP )
	if fd == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	return new_sock ( fd , "TCP" )
end

function sock_methods:ipv4_connect ( ip , port , ... )
	local r = ffi.new ( "struct sockaddr_in" )
	r.sin_family = netinet_in.AF_INET
	r.sin_port = ffi.C.htons ( port )
	if ffi.C.inet_aton ( ip , r.sin_addr ) ~= 1 then
		error ( "Unable to parse ip" )
	end
	return sock_methods.connect ( self , r , ffi.sizeof ( "struct sockaddr_in" ) , ... )
end


return {
	new_tcp = new_tcp ;
}
