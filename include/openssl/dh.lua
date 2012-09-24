local ffi = require "ffi"

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
