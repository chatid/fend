local ffi = require "ffi"
local new_file = require "fend.file"
require "fend.common"
include "errno"
include "stdio"
include "sys/socket"
include "sys/un"
include "netinet/in"
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
	return self:getfile ( ):getfd ( )
end

function sock_methods:close ( )
	return self:getfile ( ):close ( )
end

local function getsockerr ( file  )
	local err , err_len = ffi.new ( "int[1]" ) , ffi.new ( "socklen_t[1]" )
	err_len[0] = ffi.sizeof ( err )
	if ffi.C.getsockopt ( file:getfd() , defines.SOL_SOCKET , defines.SO_ERROR , err , err_len ) ~= 0 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
	return err[0]
end

function sock_methods:set_option ( level , option , val , size )
	if type ( val ) == "boolean" or type ( val ) == "number" then
		val  = ffi.new ( "int[1]" ,val )
		size = ffi.sizeof ( val )
	else
		assert ( val ~= nil , "Invalid value" )
		size = size or ffi.sizeof ( val )
	end
	if ffi.C.setsockopt ( self:getfd() , level , option , val , size ) == -1 then
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end
end

function sock_methods:set_socket_option ( option , ... )
	option = assert ( defines["SO_"..option:upper()] , "Unknown option" )
	return self:set_option ( defines.SOL_SOCKET , option , ... )
end

function sock_methods:bind ( ... )
	local sockaddr , sockaddr_len
	if ffi.istype ( "struct addrinfo*" , (...) ) then
		local addrinfo = (...)
		sockaddr , sockaddr_len = addrinfo.ai_addr , addrinfo.ai_addrlen
	else
		sockaddr , sockaddr_len = ...
	end
	if ffi.C.bind ( self:getfd() , sockaddr , sockaddr_len ) == -1 then
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
	client:getfile ( ):set_blocking ( false )
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
		if err == defines.EAGAIN or err == defines.EWOULDBLOCK then
			return 0
		else
			return nil , ffi.string ( ffi.C.strerror ( err ) )
		end
	end
	return c
end
sock_methods.receive = sock_methods.recv

function sock_methods:recvfrom ( buff , len , flags , address , address_len )
	flags = flags or 0
	address     = address or ffi.new ( "struct sockaddr" )
	address_len = address_len or ffi.sizeof ( address )
    local address_len_box = ffi.new ( "socklen_t[1]" , address_len )
	local c = tonumber ( ffi.C.recvfrom ( self:getfd() , buff , len , flags ,
			ffi.new ( "struct sockaddr*" , address ) , address_len_box ) )
	if c == 0 then
		return nil , "EOF"
	elseif c == -1 then
		local err = ffi.errno ( )
		if err == defines.EAGAIN or err == defines.EWOULDBLOCK then
			return 0
		else
			return nil , ffi.string ( ffi.C.strerror ( err ) )
		end
	end
	return c , address , address_len_box[0]
end

function sock_methods:peek ( buff , len , flags )
	return self:recv ( buff , len , bit.bor ( flags , ffi.C.MSG_PEEK ) )
end

function sock_methods:send ( buff , len , flags )
	if not ffi.istype("char*",buff) then
		buff = tostring ( buff )
	end
	len = len or #buff
	flags = flags or ffi.C.MSG_NOSIGNAL
	local c = tonumber ( ffi.C.send ( self:getfd() , buff , len , flags ) )
	if c == -1 then
		local err = ffi.errno ( )
		if err == defines.EAGAIN or err == defines.EWOULDBLOCK then
			return 0
		else
			return nil , ffi.string ( ffi.C.strerror ( err ) )
		end
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
	sock:getfile ( ):set_blocking ( false )
	return sock
end

local function new_tcp ( domain )
	return new ( domain , ffi.C.SOCK_STREAM , ffi.C.IPPROTO_TCP )
end

local function new_udp ( domain )
	return new ( domain , ffi.C.SOCK_DGRAM  , ffi.C.IPPROTO_UDP )
end

local function new_unix ( dgram )
	return new ( defines.AF_UNIX , dgram and ffi.C.SOCK_DGRAM or ffi.C.SOCK_STREAM , 0 )
end

return {
	new        = new ;
	new_tcp    = new_tcp ;
	new_udp    = new_udp ;
	new_unix   = new_unix ;

	socket_mt  = sock_mt ;
	getsockerr = getsockerr ;
}
