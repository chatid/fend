local ffi = require "ffi"
require "ffi_ev.common"
local ssl = ffi.load ( "ssl" )
local ssl_defs = include "openssl/ssl"
local err = include "openssl/err"

ssl.SSL_load_error_strings()
ssl.SSL_library_init()

local function geterr()
	return ffi.string ( ssl.ERR_reason_error_string ( ssl.ERR_get_error ( ) ) )
end

local context_methods = { }
local context_mt = { __index = context_methods ; }

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

	ssl.SSL_CTX_set_default_passwd_cb ( self , passwd_callback )
	if ssl.SSL_CTX_use_PrivateKey_file ( self , filename , ssl_defs.SSL_FILETYPE_PEM ) ~= 1 then
		error ( geterr() )
	end
	ssl.SSL_CTX_set_default_passwd_cb ( self , nil )
	passwd_callback:free()
end

function context_methods:loadcert ( filename )
	if ssl.SSL_CTX_use_certificate_chain_file ( self , filename ) ~= 1 then
		error ( geterr() )
	end
end

function context_methods:locations ( file , dir )
	if ssl.SSL_CTX_load_verify_locations ( self , file , dir ) ~= 1 then
		error ( geterr() )
	end
end

local verifys = {
	none = ssl_defs.SSL_VERIFY_NONE ;
	peer = ssl_defs.SSL_VERIFY_PEER ;
	client_once = ssl_defs.SSL_VERIFY_CLIENT_ONCE ;
	fail_if_no_peer_cert = ssl_defs.SSL_VERIFY_FAIL_IF_NO_PEER_CERT ;
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
	ssl.SSL_CTX_set_verify ( self , flag , ffi.NULL )
end

local options = {
	all = ssl_defs.SSL_OP_ALL ;
	cipher_server_preference = ssl_defs.SSL_OP_CIPHER_SERVER_PREFERENCE ;
	dont_insert_empty_fragments = ssl_defs.SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS ;
	ephemeral_rsa = ssl_defs.SSL_OP_EPHEMERAL_RSA ;
	netscape_ca_dn_bug = ssl_defs.SSL_OP_NETSCAPE_CA_DN_BUG ;
	netscape_challenge_bug = ssl_defs.SSL_OP_NETSCAPE_CHALLENGE_BUG ;
	microsoft_big_sslv3_buffer = ssl_defs.SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER ;
	microsoft_sess_id_bug = ssl_defs.SSL_OP_MICROSOFT_SESS_ID_BUG ;
	msie_sslv2_rsa_padding = ssl_defs.SSL_OP_MSIE_SSLV2_RSA_PADDING ;
	netscape_demo_cipher_change_bug = ssl_defs.SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG ;
	netscape_reuse_cipher_change_bug = ssl_defs.SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG ;
	no_session_resumption_on_renegotiation = ssl_defs.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION ;
	no_sslv2 = ssl_defs.SSL_OP_NO_SSLv2 ;
	no_sslv3 = ssl_defs.SSL_OP_NO_SSLv3 ;
	no_tlsv1 = ssl_defs.SSL_OP_NO_TLSv1 ;
	pkcs1_check_1 = ssl_defs.SSL_OP_PKCS1_CHECK_1 ;
	pkcs1_check_2 = ssl_defs.SSL_OP_PKCS1_CHECK_2 ;
	single_dh_use = ssl_defs.SSL_OP_SINGLE_DH_USE ;
	ssleay_080_client_dh_bug = ssl_defs.SSL_OP_SSLEAY_080_CLIENT_DH_BUG ;
	sslref2_reuse_cert_type_bug = ssl_defs.SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG ;
	tls_block_padding_bug = ssl_defs.SSL_OP_TLS_BLOCK_PADDING_BUG ;
	tls_d5_bug = ssl_defs.SSL_OP_TLS_D5_BUG ;
	tls_rollback_bug = ssl_defs.SSL_OP_TLS_ROLLBACK_BUG ;
}
if ssl_defs.OPENSSL_VERSION_NUMBER > 0x00908000 then -- OpenSSL 0.9.8 only
	options.cookie_exchange = ssl_defs.SSL_OP_COOKIE_EXCHANGE ;
	options.no_query_mtu = ssl_defs.SSL_OP_NO_QUERY_MTU ;
	options.single_ecdh_use = ssl_defs.SSL_OP_SINGLE_ECDH_USE ;
end
if ssl_defs.SSL_OP_NO_TICKET then -- OpenSSL 0.9.8f and above
	options.no_ticket = ssl_defs.SSL_OP_NO_TICKET ;
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
	ssl.SSL_CTX_set_options ( self , flag , ffi.NULL )
end

function context_methods:set_cipher ( list )
	if ssl.SSL_CTX_set_cipher_list ( self , list ) ~= 1 then
		error ( geterr() )
	end
end

function context_methods:set_depth ( depth )
	ssl.SSL_CTX_set_verify_depth ( self , depth )
end

ffi.metatype ( "SSL_CTX" , context_mt )

local protocol_to_method = {
	tlsv1 = ssl.TLSv1_method() ;
	sslv2 = ssl.SSLv2_method() ;
	sslv3 = ssl.SSLv3_method() ;
	sslv23 = ssl.SSLv23_method() ;
}

local function new_context ( params )
	local context = ssl.SSL_CTX_new ( protocol_to_method [ params.protocol ] )
	if context == ffi.NULL then
		error ( geterr() )
	end
	ffi.gc ( context , ssl.SSL_CTX_free )

	if params.key then
		context:loadkey ( params.key , params.password )
	end
	if params.certificate then
    	context:loadcert ( params.certificate )
   	end
	if params.cafile or params.capath then
    	context:locations ( params.cafile , params.capath )
    end
    if params.verify then
    	context:set_verify ( params.verify )
    end
    if params.options then
    	context:set_options ( params.options )
    end
    if params.ciphers then
    	context:set_cipher ( params.ciphers )
    end
    if params.depth then
    	context:set_depth ( params.depth )
    end
    ssl.SSL_CTX_ctrl ( context , ssl_defs.SSL_CTRL_MODE , bit.bor ( ssl_defs.SSL_MODE_ENABLE_PARTIAL_WRITE , ssl_defs.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER ) , ffi.NULL )

	return context
end

local ssl_methods = { }
local ssl_mt = { __index =  ssl_methods ; }

function ssl_methods:recv ( buff , len )
	local c = ssl.SSL_read ( self , buff , len )
	if c <= 0 then
		local err = ssl.SSL_get_error ( self , c )
		return nil , ffi.string ( ssl.ERR_reason_error_string ( err ) )
	end
	return c
end
ssl_methods.receive = ssl_methods.recv

function ssl_methods:send ( buff , len )
	local c = ssl.SSL_write ( self , buff , len )
	if c <= 0 then
		local err = ssl.SSL_get_error ( self , c )
		return nil , ffi.string ( ssl.ERR_reason_error_string ( err ) )
	end
	return c
end

ffi.metatype ( "SSL" , ssl_mt )

local function wrap ( sock , context , mode )
	if type ( context ) == "table" then
		context = new_context ( context )
	end

	local self = ssl.SSL_new ( context )
	if self == ffi.NULL then
		error ( geterr() )
	end
	ffi.gc ( self , ssl.SSL_free )

	if ssl.SSL_set_fd ( self , sock:getfd() ) ~= 1 then
		error ( geterr() )
	end
	if mode == "server" then
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
