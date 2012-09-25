include "openssl/e_os2"
include "openssl/bio"
include "openssl/crypto"
include "openssl/ossl_typ"
include "openssl/bn"
include "openssl/dh"

ffi.cdef [[
typedef struct DSA_SIG_st
 {
 BIGNUM *r;
 BIGNUM *s;
 } DSA_SIG;
struct dsa_method
 {
 const char *name;
 DSA_SIG * (*dsa_do_sign)(const unsigned char *dgst, int dlen, DSA *dsa);
 int (*dsa_sign_setup)(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp,
        BIGNUM **rp);
 int (*dsa_do_verify)(const unsigned char *dgst, int dgst_len,
        DSA_SIG *sig, DSA *dsa);
 int (*dsa_mod_exp)(DSA *dsa, BIGNUM *rr, BIGNUM *a1, BIGNUM *p1,
   BIGNUM *a2, BIGNUM *p2, BIGNUM *m, BN_CTX *ctx,
   BN_MONT_CTX *in_mont);
 int (*bn_mod_exp)(DSA *dsa, BIGNUM *r, BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx,
    BN_MONT_CTX *m_ctx);
 int (*init)(DSA *dsa);
 int (*finish)(DSA *dsa);
 int flags;
 char *app_data;
 int (*dsa_paramgen)(DSA *dsa, int bits,
   const unsigned char *seed, int seed_len,
   int *counter_ret, unsigned long *h_ret,
   BN_GENCB *cb);
 int (*dsa_keygen)(DSA *dsa);
 };
struct dsa_st
 {
 int pad;
 long version;
 int write_params;
 BIGNUM *p;
 BIGNUM *q;
 BIGNUM *g;
 BIGNUM *pub_key;
 BIGNUM *priv_key;
 BIGNUM *kinv;
 BIGNUM *r;
 int flags;
 BN_MONT_CTX *method_mont_p;
 int references;
 CRYPTO_EX_DATA ex_data;
 const DSA_METHOD *meth;
 ENGINE *engine;
 };
DSA *DSAparams_dup(DSA *x);
DSA_SIG * DSA_SIG_new(void);
void DSA_SIG_free(DSA_SIG *a);
int i2d_DSA_SIG(const DSA_SIG *a, unsigned char **pp);
DSA_SIG * d2i_DSA_SIG(DSA_SIG **v, const unsigned char **pp, long length);
DSA_SIG * DSA_do_sign(const unsigned char *dgst,int dlen,DSA *dsa);
int DSA_do_verify(const unsigned char *dgst,int dgst_len,
        DSA_SIG *sig,DSA *dsa);
const DSA_METHOD *DSA_OpenSSL(void);
void DSA_set_default_method(const DSA_METHOD *);
const DSA_METHOD *DSA_get_default_method(void);
int DSA_set_method(DSA *dsa, const DSA_METHOD *);
DSA * DSA_new(void);
DSA * DSA_new_method(ENGINE *engine);
void DSA_free (DSA *r);
int DSA_up_ref(DSA *r);
int DSA_size(const DSA *);
int DSA_sign_setup( DSA *dsa,BN_CTX *ctx_in,BIGNUM **kinvp,BIGNUM **rp);
int DSA_sign(int type,const unsigned char *dgst,int dlen,
  unsigned char *sig, unsigned int *siglen, DSA *dsa);
int DSA_verify(int type,const unsigned char *dgst,int dgst_len,
  const unsigned char *sigbuf, int siglen, DSA *dsa);
int DSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
      CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int DSA_set_ex_data(DSA *d, int idx, void *arg);
void *DSA_get_ex_data(DSA *d, int idx);
DSA * d2i_DSAPublicKey(DSA **a, const unsigned char **pp, long length);
DSA * d2i_DSAPrivateKey(DSA **a, const unsigned char **pp, long length);
DSA * d2i_DSAparams(DSA **a, const unsigned char **pp, long length);
DSA * DSA_generate_parameters(int bits,
  unsigned char *seed,int seed_len,
  int *counter_ret, unsigned long *h_ret,void
  (*callback)(int, int, void *),void *cb_arg);
int DSA_generate_parameters_ex(DSA *dsa, int bits,
  const unsigned char *seed,int seed_len,
  int *counter_ret, unsigned long *h_ret, BN_GENCB *cb);
int DSA_generate_key(DSA *a);
int i2d_DSAPublicKey(const DSA *a, unsigned char **pp);
int i2d_DSAPrivateKey(const DSA *a, unsigned char **pp);
int i2d_DSAparams(const DSA *a,unsigned char **pp);
int DSAparams_print(BIO *bp, const DSA *x);
int DSA_print(BIO *bp, const DSA *x, int off);
int DSAparams_print_fp(FILE *fp, const DSA *x);
int DSA_print_fp(FILE *bp, const DSA *x, int off);
DH *DSA_dup_DH(const DSA *r);
void ERR_load_DSA_strings(void);
]]

DSA_F_D2I_DSA_SIG = 110
DSA_F_DO_DSA_PRINT = 104
DSA_F_DSA_DO_SIGN = 112
DSA_F_DSA_DO_VERIFY = 113
DSA_F_DSA_GENERATE_KEY = 124
DSA_F_DSA_GENERATE_PARAMETERS_EX = 123
DSA_F_DSA_NEW_METHOD = 103
DSA_F_DSA_PARAM_DECODE = 119
DSA_F_DSA_PRINT_FP = 105
DSA_F_DSA_PRIV_DECODE = 115
DSA_F_DSA_PRIV_ENCODE = 116
DSA_F_DSA_PUB_DECODE = 117
DSA_F_DSA_PUB_ENCODE = 118
DSA_F_DSA_SIG_NEW = 109
DSA_F_DSA_SIG_PRINT = 125
DSA_F_DSA_SIGN = 106
DSA_F_DSA_SIGN_SETUP = 107
DSA_F_DSA_VERIFY = 108
DSA_F_DSAPARAMS_PRINT = 100
DSA_F_DSAPARAMS_PRINT_FP = 101
DSA_F_I2D_DSA_SIG = 111
DSA_F_OLD_DSA_PRIV_DECODE = 122
DSA_F_PKEY_DSA_CTRL = 120
DSA_F_PKEY_DSA_KEYGEN = 121
DSA_F_SIG_CB = 114
DSA_FLAG_CACHE_MONT_P = 0x01
DSA_FLAG_FIPS_METHOD = 0x0400
DSA_FLAG_NO_EXP_CONSTTIME = 0x02
DSA_FLAG_NON_FIPS_ALLOW = 0x0400
DSA_R_BAD_Q_VALUE = 102
DSA_R_BN_DECODE_ERROR = 108
DSA_R_BN_ERROR = 109
DSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE = 100
DSA_R_DECODE_ERROR = 104
DSA_R_INVALID_DIGEST_TYPE = 106
DSA_R_MISSING_PARAMETERS = 101
DSA_R_MODULUS_TOO_LARGE = 103
DSA_R_NEED_NEW_SETUP_VALUES = 110
DSA_R_NO_PARAMETERS_SET = 107
DSA_R_NON_FIPS_DSA_METHOD = 111
DSA_R_PARAMETER_ENCODING_ERROR = 105
