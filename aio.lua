local ffi = require "ffi"

local common = require "fend.common"
include "errno"
include "string"
include "aiocb"
include "signal"
include "fcntl" -- For O_(D)SYNC
local aio_lib = ffi.load "rt"

local fend_file = require "fend.file"
local file_methods = fend_file.file_mt.__index

local aiocbp_t = ffi.typeof ( "struct aiocb" )
local aiocbp_mt = { }
function aiocbp_mt:__new ( file , buff , len , offset , priority )
	local rawfd = file:getfd ( )

	return ffi.new ( self , {
			aio_fildes   = rawfd ;
			aio_offset   = offset ;
			aio_buf      = buff ;
			aio_nbytes   = len ;
			aio_reqprio  = priority ;
			aio_sigevent = {
				sigev_notify = ffi.C.SIGEV_SIGNAL ;
				sigev_signo  = common.signum ;
				sigev_value  = {
					sival_int = rawfd ;
				} ;
			} ;
		} )
end
ffi.metatype ( aiocbp_t , aiocbp_mt )

local function setup_callback ( epoll_ob , aiocbp , cb )
	return epoll_ob:add_signal ( common.signum , function ( sig_info , cb_id )
			if sig_info[0].ssi_code == ffi.C.SI_ASYNCIO then
				local retfd = ffi.cast ( "int" , sig_info[0].ssi_int )
				if retfd == aiocbp.aio_fildes then
					if cb then
						local err = aio_lib.aio_error ( aiocbp )
						if err ~= 0 then
							cb ( aiocbp , nil , err )
						else
							cb ( aiocbp , aio_lib.aio_return ( aiocbp ) )
						end
					end
					epoll_ob:del_signal ( common.signum , cb_id )
				end
			end
		end )
end

function file_methods:aio_read ( buff , len , offset , priority , epoll_ob , cb )
	local aiocbp = aiocbp_t ( self , buff , len , offset , priority )

	local cb_id = setup_callback ( epoll_ob , aiocbp , function ( aiocbp , ret , errno )
			if ret == nil then
				cb ( self , nil , ffi.string ( ffi.C.strerror ( errno ) ) )
			else
				cb ( self , ffi.cast ( "char*" , aiocbp.aio_buf ) , ret )
			end
		end )

	if aio_lib.aio_read ( aiocbp ) ~= 0 then
		epoll_ob:del_signal ( common.signum , cb_id )
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end

	return aiocbp
end

function file_methods:aio_write ( buff , len , offset , priority , epoll_ob , cb )
	local aiocbp = aiocbp_t ( self , buff , len , offset , priority )

	local cb_id = setup_callback ( epoll_ob , aiocbp , cb and function ( aiocbp , ret , errno )
			if ret == nil then
				cb ( self , nil , ffi.string ( ffi.C.strerror ( errno ) ) )
			else
				cb ( self , ret )
			end
		end )

	if aio_lib.aio_write ( aiocbp ) ~= 0 then
		epoll_ob:del_signal ( common.signum , cb_id )
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end

	return aiocbp
end

function file_methods:aio_fsync ( dsync )
	local aiocbp = aiocbp_t ( self )

	local cb_id = setup_callback ( epoll_ob , aiocbp , cb and function ( aiocbp , ret , errno )
			if ret == nil then
				cb ( self , nil , ffi.string ( ffi.C.strerror ( errno ) ) )
			else
				cb ( self , ret )
			end
		end )

	if aio_lib.aio_fsync ( dsync and defines.O_DSYNC or defines.O_SYNC , aiocbp ) ~= 0 then
		epoll_ob:del_signal ( common.signum , cb_id )
		error ( ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) ) )
	end

	return aiocbp
end
