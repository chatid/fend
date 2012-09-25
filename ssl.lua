local ffi = require "ffi"
local ssl = ffi.load ( "ssl" )
require "fend.common"
include "openssl/ssl"
include "openssl/err"

-- From LuaSec
ffi.cdef [[
typedef struct t_context_ {
  SSL_CTX *context;
  char mode;
} t_context;
typedef t_context* p_context;
]]

local MD_CTX_INVALID = 0 ;
local MD_CTX_SERVER = 1 ;
local MD_CTX_CLIENT = 2 ;
local modes = {
	client = MD_CTX_CLIENT ;
	server = MD_CTX_SERVER ;
}


ssl.SSL_load_error_strings()
ssl.SSL_library_init()

local function geterr()
	local err = ssl.ERR_get_error ( )
	if err == 0 then
		return nil
	else
		return ffi.string ( ssl.ERR_reason_error_string ( err ) )
	end
end

local context_methods = { }
local context_mt = {
	__index = context_methods ;
	__gc = function ( self )
		ssl.SSL_CTX_free ( self.context )
	end ;
}

function context_methods:loadkey ( filename , password )
	local passwd_callback = ffi.cast ( "pem_password_cb*" , function ( out_buff , max_size , rw , userdata )
			if password == nil then
				return 0
			elseif type(password) == "function" then
				password = password ( )
			end
			assert ( type(password) == "string" )
			ffi.copy ( out_buff , password , math.max ( max_size , #password ) )
			return #password
		end )

	ssl.SSL_CTX_set_default_passwd_cb ( self.context , passwd_callback )
	if ssl.SSL_CTX_use_PrivateKey_file ( self.context , filename , defines.SSL_FILETYPE_PEM ) ~= 1 then
		error ( geterr() )
	end
	ssl.SSL_CTX_set_default_passwd_cb ( self.context , nil )
	passwd_callback:free()
end

function context_methods:loadcert ( filename )
	if ssl.SSL_CTX_use_certificate_chain_file ( self.context , filename ) ~= 1 then
		error ( geterr() )
	end
end

function context_methods:locations ( file , dir )
	if ssl.SSL_CTX_load_verify_locations ( self.context , file , dir ) ~= 1 then
		error ( geterr() )
	end
end

local verifys = {
	none                 = defines.SSL_VERIFY_NONE ;
	peer                 = defines.SSL_VERIFY_PEER ;
	client_once          = defines.SSL_VERIFY_CLIENT_ONCE ;
	fail_if_no_peer_cert = defines.SSL_VERIFY_FAIL_IF_NO_PEER_CERT ;
}
function context_methods:set_verify ( flag )
	if type ( flag ) == "string" then
		flag = verifys [ flag ]
	elseif type ( flag ) == "table" then
		local tbl = flag
		flag = 0
		for i , v in ipairs ( tbl ) do
			flag = bit.bor ( flag , verifys [ v ] )
		end
	end
	ssl.SSL_CTX_set_verify ( self.context , flag , ffi.NULL )
end

local options = {
	all                                    = defines.SSL_OP_ALL ;
	cipher_server_preference               = defines.SSL_OP_CIPHER_SERVER_PREFERENCE ;
	dont_insert_empty_fragments            = defines.SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS ;
	ephemeral_rsa                          = defines.SSL_OP_EPHEMERAL_RSA ;
	netscape_ca_dn_bug                     = defines.SSL_OP_NETSCAPE_CA_DN_BUG ;
	netscape_challenge_bug                 = defines.SSL_OP_NETSCAPE_CHALLENGE_BUG ;
	microsoft_big_sslv3_buffer             = defines.SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER ;
	microsoft_sess_id_bug                  = defines.SSL_OP_MICROSOFT_SESS_ID_BUG ;
	msie_sslv2_rsa_padding                 = defines.SSL_OP_MSIE_SSLV2_RSA_PADDING ;
	netscape_demo_cipher_change_bug        = defines.SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG ;
	netscape_reuse_cipher_change_bug       = defines.SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG ;
	no_session_resumption_on_renegotiation = defines.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION ;
	no_sslv2                               = defines.SSL_OP_NO_SSLv2 ;
	no_sslv3                               = defines.SSL_OP_NO_SSLv3 ;
	no_tlsv1                               = defines.SSL_OP_NO_TLSv1 ;
	pkcs1_check_1                          = defines.SSL_OP_PKCS1_CHECK_1 ;
	pkcs1_check_2                          = defines.SSL_OP_PKCS1_CHECK_2 ;
	single_dh_use                          = defines.SSL_OP_SINGLE_DH_USE ;
	ssleay_080_client_dh_bug               = defines.SSL_OP_SSLEAY_080_CLIENT_DH_BUG ;
	sslref2_reuse_cert_type_bug            = defines.SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG ;
	tls_block_padding_bug                  = defines.SSL_OP_TLS_BLOCK_PADDING_BUG ;
	tls_d5_bug                             = defines.SSL_OP_TLS_D5_BUG ;
	tls_rollback_bug                       = defines.SSL_OP_TLS_ROLLBACK_BUG ;
}
if defines.OPENSSL_VERSION_NUMBER > 0x00908000 then -- OpenSSL 0.9.8 only
	options.cookie_exchange = defines.SSL_OP_COOKIE_EXCHANGE ;
	options.no_query_mtu    = defines.SSL_OP_NO_QUERY_MTU ;
	options.single_ecdh_use = defines.SSL_OP_SINGLE_ECDH_USE ;
end
if defines.SSL_OP_NO_TICKET then -- OpenSSL 0.9.8f and above
	options.no_ticket = defines.SSL_OP_NO_TICKET ;
end
function context_methods:set_options ( flag )
	if type ( flag ) == "string" then
		flag = options [ tbl ]
	elseif type ( flag ) == "table" then
		local tbl = flag
		flag = 0
		for i , v in ipairs ( tbl ) do
			flag = bit.bor ( flag , options [ v ] )
		end
	end
	ssl.SSL_CTX_set_options ( self.context , flag , ffi.NULL )
end

function context_methods:set_cipher ( list )
	if ssl.SSL_CTX_set_cipher_list ( self.context , list ) ~= 1 then
		error ( geterr() )
	end
end

function context_methods:set_depth ( depth )
	ssl.SSL_CTX_set_verify_depth ( self.context , depth )
end

ffi.metatype ( "t_context" , context_mt )

local protocol_to_method = {
	tlsv1 = ssl.TLSv1_method() ;
	sslv3 = ssl.SSLv3_method() ;
	sslv23 = ssl.SSLv23_method() ;
}

local function new_context ( params )
	local context = ssl.SSL_CTX_new ( protocol_to_method [ params.protocol ] )
	if context == ffi.NULL then
		error ( geterr() )
	end
	local self = ffi.new ( "t_context" , {
			context = context ;
			mode = assert ( modes [ params.mode ] , "Invalid mode" ) ;
		} )
	ssl.SSL_CTX_ctrl ( context , defines.SSL_CTRL_SET_SESS_CACHE_MODE , defines.SSL_SESS_CACHE_OFF , ffi.NULL )
	ssl.SSL_CTX_ctrl ( context , defines.SSL_CTRL_MODE , bit.bor ( defines.SSL_MODE_ENABLE_PARTIAL_WRITE , defines.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER ) , ffi.NULL )
	if params.key then
		self:loadkey ( params.key , params.password )
	end
	if params.certificate then
		self:loadcert ( params.certificate )
	end
	if params.cafile or params.capath then
		self:locations ( params.cafile , params.capath )
	end
	if params.verify then
		self:set_verify ( params.verify )
	end
	if params.options then
		self:set_options ( params.options )
	end
	if params.ciphers then
		self:set_cipher ( params.ciphers )
	end
	if params.depth then
		self:set_depth ( params.depth )
	end
	return self
end

local original_socks = { } -- We have to keep the originals around to stop them getting closed on collection
local ssl_methods = { }

function ssl_methods:getfile ( )
	return original_socks [ self ].file
end

function ssl_methods:getfd ( )
	return original_socks [ self ].file:getfd ( )
end

local function handle_err ( err , c )
	if err == defines.SSL_ERROR_WANT_READ then
		return nil , "wantread"
	elseif err == defines.SSL_ERROR_WANT_WRITE then
		return nil , "wantwrite"
	end
	local ssl_err = geterr()
	if ssl_err then
		return nil , ssl_err
	end
	if err == defines.SSL_ERROR_SYSCALL then
		if c == 0 then
			return nil , "EOF"
		elseif c == -1 then
			return nil , ffi.string ( ffi.C.strerror ( ffi.errno ( ) ) )
		end
		return nil , "syscall"
	end
	return nil , "Unknown error"
end

function ssl_methods:recv ( buff , len )
	local c = ssl.SSL_read ( self , buff , len )
	if c <= 0 then
		return handle_err ( ssl.SSL_get_error ( self , c ) , c )
	end
	return c
end
ssl_methods.receive = ssl_methods.recv

function ssl_methods:send ( buff , len )
	len = len or #buff
	local c = ssl.SSL_write ( self , buff , len )
	if c <= 0 then
		return handle_err ( ssl.SSL_get_error ( self , c ) , c )
	end
	return c
end

function ssl_methods:dohandshake ( )
	local c = ssl.SSL_do_handshake ( self )
	if c ~= 1 then
		return handle_err ( ssl.SSL_get_error ( self , c ) , c )
	end
	return true
end

-- This method cannot be called as the SSL structure has a field 'shutdown'
function ssl_methods:shutdown ( )
	local c = ssl.SSL_shutdown ( self )
	if c <= 0 then
		return handle_err ( ssl.SSL_get_error ( self , c ) , c )
	end
	return true
end
ssl_methods._shutdown = ssl_methods.shutdown

function ssl_methods:close ( )
	original_socks [ self ]:close ( )
end

ffi.metatype ( "SSL" , {
	__index = ssl_methods ;
	__gc = function ( self )
		ssl.SSL_free ( self )
		original_socks [ self ] = nil
	end ;
	__tostring = function ( self )
		return "SSL_wrapped:" .. tostring ( original_socks [ self ] )
	end ;
} )

local function wrap ( sock , ctx )
	if type ( ctx ) == "table" then
		ctx = new_context ( ctx )
	elseif type ( ctx ) == "userdata" then -- Is probably from LuaSec.....
		ctx = ffi.cast ( "p_context" , ctx )
	end

	local self = ssl.SSL_new ( ctx.context )
	if self == ffi.NULL then
		error ( geterr() )
	end
	original_socks [ self ] = sock
	if ssl.SSL_set_fd ( self , sock:getfd() ) ~= 1 then
		error ( geterr() )
	end
	if ctx.mode == MD_CTX_SERVER then
		ssl.SSL_set_accept_state ( self )
	else
		ssl.SSL_set_connect_state ( self )
	end

	return self
end

return {
	new_context = new_context ;
	wrap = wrap ;
}
