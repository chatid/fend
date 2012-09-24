local ffi = require "ffi"
local new_file = require "fend.file"
require "fend.common"
include "stdio"
local errors = include "errno"
local socket = include "sys/socket"
local netinet_in = include "netinet/in"
include "arpa/inet"

local sock_methods = { }
local sock_mt = {
	__index = sock_methods ;
	__tostring = function ( self )
		return "socket{file=" .. tostring(self.file) .. ";type=\"" .. self.type .. "\"}"
	end ;
}

local function new_sock ( file , type )
	return setmetatable ( {
			file = file ;
			type = type ; -- A string describing the socket
		} , sock_mt )
end

function sock_methods:getfile ( )
	return self.file
end

function sock_methods:getfd ( )
	return self.file:getfd ( )
end

function sock_methods:close ( )
	self.file:close ( )
end

local function getsockerr ( file  )
	local err , err_len = ffi.new ( "int[1]" ) , ffi.new ( "socklen_t[1]" )
	err_len[0] = ffi.sizeof ( err )
	if ffi.C.getsockopt ( file:getfd() , socket.SOL_SOCKET , socket.SO_ERROR , err , err_len ) ~= 0 then
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
	epoll_ob:add_fd ( self.file , {
			write = function ( file )
				local err = getsockerr ( file )
				if err ~= 0 then
					cb ( nil , ffi.string ( ffi.C.strerror ( err ) ) )
				end
				self.connected = true
				cb ( self )
			end ;
			oneshot = true
		} )
end

function sock_methods:set_option ( option , val )
	option = assert ( socket["SO_"..option:upper()] , "Unknown option" )
	val = ffi.new("int[1]",val)
	if ffi.C.setsockopt ( self:getfd() , socket.SOL_SOCKET , option , val , ffi.sizeof(val) ) == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
end

function sock_methods:bind ( addrinfo )
	if ffi.C.bind ( self:getfd() , addrinfo.ai_addr , addrinfo.ai_addrlen ) == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
end

function sock_methods:listen ( backlog )
	backlog = backlog or 128
	if ffi.C.listen ( self:getfd() , backlog ) == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
end

function sock_methods:accept ( with_sockaddr )
	local sockaddr , sockaddr_len
	if with_sockaddr then
	 	sockaddr , sockaddr_len = ffi.new ( "struct sockaddr[1]" ) , ffi.new ( "socklen_t[1]" )
		sockaddr_len[0] = ffi.sizeof ( sockaddr )
	end
	local clientfd = ffi.C.accept ( self:getfd() , sockaddr , sockaddr_len )
	if clientfd == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	local client = new_sock ( new_file ( clientfd ) , self.type )
	client.connected = true
	client.file:set_blocking ( false )
	if with_sockaddr then
		return client , sockaddr , sockaddr_len[0]
	else
		return client
	end
end

function sock_methods:shutdown ( )
	if ffi.C.shutdown ( self:getfd() , ffi.C.SHUT_RDWR ) ~= 0 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
end
sock_methods._shutdown = sock_methods.shutdown

function sock_methods:recv ( buff , len , flags )
	flags = flags or 0
	local c = tonumber ( ffi.C.recv ( self:getfd() , buff , len , flags ) )
	if c == 0 then
		return nil , "EOF"
	elseif c == -1 then
		local err = ffi.errno ( )
		if err == errors.EAGAIN or err == errors.EWOULDBLOCK then
			return 0
		else
			return nil , ffi.string ( ffi.C.strerror ( err ) )
		end
	end
	return c
end
sock_methods.receive = sock_methods.recv

function sock_methods:send ( buff , len , flags )
	if not ffi.istype("char*",buff) then
		buff = tostring ( buff )
	end
	len = len or #buff
	flags = flags or ffi.C.MSG_NOSIGNAL
	local c = tonumber ( ffi.C.send ( self:getfd() , buff , len , flags ) )
	if c == -1 then
		return nil , ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) )
	end
	return c
end

function sock_methods:sendto ( buff , len , flags , dest_addr , dest_addr_len )
	if not ffi.istype("char*",buff) then
		buff = tostring ( buff )
	end
	len = len or #buff
	flags = flags or 0
	local c = ffi.C.sendto ( self:getfd() , buff , len , flags , dest_addr , dest_addr_len )
	if c == -1 then
		return nil , ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) )
	end
	return c
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
				end
			end ;
			error = function ( file , err )
				cb ( self , nil , err , bytes_written )
			end
		} )
end

function sock_methods:getpeername ( )
	local sockaddr , sockaddr_len = ffi.new ( "struct sockaddr[1]" ) , ffi.new ( "socklen_t[1]" )
	sockaddr_len[0] = ffi.sizeof ( sockaddr )
	if ffi.C.getpeername ( sock:getfd() , sockaddr , sockaddr_len ) == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	return sockaddr , sockaddr_len[0]
end

local function new ( ... )
	local domain , sock_type , protocol
	-- If domain is an addrinfo then extract params from that
	if ffi.istype ( "struct addrinfo*" , (...) ) then
		local addrinfo = (...)
		domain , sock_type , protocol = addrinfo.ai_family , addrinfo.ai_socktype , addrinfo.ai_protocol
	else
		domain , sock_type , protocol = ...
	end
	local fd = ffi.C.socket ( domain , sock_type , protocol )
	if fd == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	local proto = ffi.C.getprotobynumber ( protocol )
	assert ( proto ~= ffi.NULL , "Unable to look up protocol" )
	local sock = new_sock ( new_file ( fd ) , ffi.string ( proto.p_name ) )
	sock.file:set_blocking ( false )
	return sock
end

local function new_tcp ( domain )
	return new ( domain , ffi.C.SOCK_STREAM , ffi.C.IPPROTO_TCP )
end

local function new_udp ( domain )
	return new ( domain , ffi.C.SOCK_DGRAM  , ffi.C.IPPROTO_UDP )
end


return {
	new = new ;
	new_tcp = new_tcp ;
	new_udp = new_udp ;
	socket_mt = sock_mt ;
}
