include "openssl/e_os2"
include "openssl/bio"
include "openssl/ossl_typ"
include "openssl/bn"

ffi.cdef [[
struct dh_method
 {
 const char *name;
 int (*generate_key)(DH *dh);
 int (*compute_key)(unsigned char *key,const BIGNUM *pub_key,DH *dh);
 int (*bn_mod_exp)(const DH *dh, BIGNUM *r, const BIGNUM *a,
    const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
    BN_MONT_CTX *m_ctx);
 int (*init)(DH *dh);
 int (*finish)(DH *dh);
 int flags;
 char *app_data;
 int (*generate_params)(DH *dh, int prime_len, int generator, BN_GENCB *cb);
 };
struct dh_st
 {
 int pad;
 int version;
 BIGNUM *p;
 BIGNUM *g;
 long length;
 BIGNUM *pub_key;
 BIGNUM *priv_key;
 int flags;
 BN_MONT_CTX *method_mont_p;
 BIGNUM *q;
 BIGNUM *j;
 unsigned char *seed;
 int seedlen;
 BIGNUM *counter;
 int references;
 CRYPTO_EX_DATA ex_data;
 const DH_METHOD *meth;
 ENGINE *engine;
 };
DH *DHparams_dup(DH *);
const DH_METHOD *DH_OpenSSL(void);
void DH_set_default_method(const DH_METHOD *meth);
const DH_METHOD *DH_get_default_method(void);
int DH_set_method(DH *dh, const DH_METHOD *meth);
DH *DH_new_method(ENGINE *engine);
DH * DH_new(void);
void DH_free(DH *dh);
int DH_up_ref(DH *dh);
int DH_size(const DH *dh);
int DH_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
      CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int DH_set_ex_data(DH *d, int idx, void *arg);
void *DH_get_ex_data(DH *d, int idx);
DH * DH_generate_parameters(int prime_len,int generator,
  void (*callback)(int,int,void *),void *cb_arg);
int DH_generate_parameters_ex(DH *dh, int prime_len,int generator, BN_GENCB *cb);
int DH_check(const DH *dh,int *codes);
int DH_check_pub_key(const DH *dh,const BIGNUM *pub_key, int *codes);
int DH_generate_key(DH *dh);
int DH_compute_key(unsigned char *key,const BIGNUM *pub_key,DH *dh);
DH * d2i_DHparams(DH **a,const unsigned char **pp, long length);
int i2d_DHparams(const DH *a,unsigned char **pp);
int DHparams_print_fp(FILE *fp, const DH *x);
int DHparams_print(BIO *bp, const DH *x);
void ERR_load_DH_strings(void);
]]

DH_CHECK_P_NOT_PRIME           = 0x01
DH_CHECK_P_NOT_SAFE_PRIME      = 0x02
DH_CHECK_P_NOT_STRONG_PRIME    = DH_CHECK_P_NOT_SAFE_PRIME
DH_CHECK_PUBKEY_TOO_LARGE      = 0x02
DH_CHECK_PUBKEY_TOO_SMALL      = 0x01
DH_F_COMPUTE_KEY               = 102
DH_F_DH_BUILTIN_GENPARAMS      = 106
DH_F_DH_COMPUTE_KEY            = 114
DH_F_DH_GENERATE_KEY           = 115
DH_F_DH_GENERATE_PARAMETERS_EX = 116
DH_F_DH_NEW_METHOD             = 105
DH_F_DH_PARAM_DECODE           = 107
DH_F_DH_PRIV_DECODE            = 110
DH_F_DH_PRIV_ENCODE            = 111
DH_F_DH_PUB_DECODE             = 108
DH_F_DH_PUB_ENCODE             = 109
DH_F_DHPARAMS_PRINT_FP         = 101
DH_F_DO_DH_PRINT               = 100
DH_F_GENERATE_KEY              = 103
DH_F_GENERATE_PARAMETERS       = 104
DH_F_PKEY_DH_DERIVE            = 112
DH_F_PKEY_DH_KEYGEN            = 113
DH_FLAG_CACHE_MONT_P           = 0x01
DH_FLAG_FIPS_METHOD            = 0x0400
DH_FLAG_NO_EXP_CONSTTIME       = 0x02
DH_FLAG_NON_FIPS_ALLOW         = 0x0400
DH_GENERATOR_2                 = 2
DH_GENERATOR_5                 = 5
DH_NOT_SUITABLE_GENERATOR      = 0x08
DH_R_BAD_GENERATOR             = 101
DH_R_BN_DECODE_ERROR           = 109
DH_R_BN_ERROR                  = 106
DH_R_DECODE_ERROR              = 104
DH_R_INVALID_PUBKEY            = 102
DH_R_KEY_SIZE_TOO_SMALL        = 110
DH_R_KEYS_NOT_SET              = 108
DH_R_MODULUS_TOO_LARGE         = 103
DH_R_NO_PARAMETERS_SET         = 107
DH_R_NO_PRIVATE_VALUE          = 100
DH_R_NON_FIPS_METHOD           = 111
DH_R_PARAMETER_ENCODING_ERROR  = 105
DH_UNABLE_TO_CHECK_GENERATOR   = 0x04
