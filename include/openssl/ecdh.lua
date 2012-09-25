local ffi = require "ffi"

include "openssl/ec"
include "openssl/ossl_typ"
include "openssl/bn"

ffi.cdef [[
const ECDH_METHOD *ECDH_OpenSSL(void);
void ECDH_set_default_method(const ECDH_METHOD *);
const ECDH_METHOD *ECDH_get_default_method(void);
int ECDH_set_method(EC_KEY *, const ECDH_METHOD *);
int ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key, EC_KEY *ecdh,
                     void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));
int ECDH_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new
  *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int ECDH_set_ex_data(EC_KEY *d, int idx, void *arg);
void *ECDH_get_ex_data(EC_KEY *d, int idx);
void ERR_load_ECDH_strings(void);
]]

module ( ... )

ECDH_F_ECDH_CHECK = 102
ECDH_F_ECDH_COMPUTE_KEY = 100
ECDH_F_ECDH_DATA_NEW_METHOD = 101
ECDH_R_KDF_FAILED = 102
ECDH_R_NO_PRIVATE_VALUE = 100
ECDH_R_NON_FIPS_METHOD = 103
ECDH_R_POINT_ARITHMETIC_FAILURE = 101

return _M
