local ffi = require "ffi"

include "openssl/asn1"
include "openssl/bio"
include "openssl/crypto"
include "openssl/ossl_typ"
include "openssl/bn"

ffi.cdef [[
struct rsa_meth_st
 {
 const char *name;
 int (*rsa_pub_enc)(int flen,const unsigned char *from,
      unsigned char *to,
      RSA *rsa,int padding);
 int (*rsa_pub_dec)(int flen,const unsigned char *from,
      unsigned char *to,
      RSA *rsa,int padding);
 int (*rsa_priv_enc)(int flen,const unsigned char *from,
       unsigned char *to,
       RSA *rsa,int padding);
 int (*rsa_priv_dec)(int flen,const unsigned char *from,
       unsigned char *to,
       RSA *rsa,int padding);
 int (*rsa_mod_exp)(BIGNUM *r0,const BIGNUM *I,RSA *rsa,BN_CTX *ctx);
 int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
     const BIGNUM *m, BN_CTX *ctx,
     BN_MONT_CTX *m_ctx);
 int (*init)(RSA *rsa);
 int (*finish)(RSA *rsa);
 int flags;
 char *app_data;
 int (*rsa_sign)(int type,
  const unsigned char *m, unsigned int m_length,
  unsigned char *sigret, unsigned int *siglen, const RSA *rsa);
 int (*rsa_verify)(int dtype,
  const unsigned char *m, unsigned int m_length,
  const unsigned char *sigbuf, unsigned int siglen,
        const RSA *rsa);
 int (*rsa_keygen)(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
 };
struct rsa_st
 {
 int pad;
 long version;
 const RSA_METHOD *meth;
 ENGINE *engine;
 BIGNUM *n;
 BIGNUM *e;
 BIGNUM *d;
 BIGNUM *p;
 BIGNUM *q;
 BIGNUM *dmp1;
 BIGNUM *dmq1;
 BIGNUM *iqmp;
 CRYPTO_EX_DATA ex_data;
 int references;
 int flags;
 BN_MONT_CTX *_method_mod_n;
 BN_MONT_CTX *_method_mod_p;
 BN_MONT_CTX *_method_mod_q;
 char *bignum_data;
 BN_BLINDING *blinding;
 BN_BLINDING *mt_blinding;
 };
RSA * RSA_new(void);
RSA * RSA_new_method(ENGINE *engine);
int RSA_size(const RSA *);
RSA * RSA_generate_key(int bits, unsigned long e,void
  (*callback)(int,int,void *),void *cb_arg);
int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
int RSA_check_key(const RSA *);
int RSA_public_encrypt(int flen, const unsigned char *from,
  unsigned char *to, RSA *rsa,int padding);
int RSA_private_encrypt(int flen, const unsigned char *from,
  unsigned char *to, RSA *rsa,int padding);
int RSA_public_decrypt(int flen, const unsigned char *from,
  unsigned char *to, RSA *rsa,int padding);
int RSA_private_decrypt(int flen, const unsigned char *from,
  unsigned char *to, RSA *rsa,int padding);
void RSA_free (RSA *r);
int RSA_up_ref(RSA *r);
int RSA_flags(const RSA *r);
void RSA_set_default_method(const RSA_METHOD *meth);
const RSA_METHOD *RSA_get_default_method(void);
const RSA_METHOD *RSA_get_method(const RSA *rsa);
int RSA_set_method(RSA *rsa, const RSA_METHOD *meth);
int RSA_memory_lock(RSA *r);
const RSA_METHOD *RSA_PKCS1_SSLeay(void);
const RSA_METHOD *RSA_null_method(void);
RSA *d2i_RSAPublicKey(RSA **a, const unsigned char **in, long len); int i2d_RSAPublicKey(const RSA *a, unsigned char **out); extern const ASN1_ITEM RSAPublicKey_it;
RSA *d2i_RSAPrivateKey(RSA **a, const unsigned char **in, long len); int i2d_RSAPrivateKey(const RSA *a, unsigned char **out); extern const ASN1_ITEM RSAPrivateKey_it;
typedef struct rsa_pss_params_st
 {
 X509_ALGOR *hashAlgorithm;
 X509_ALGOR *maskGenAlgorithm;
 ASN1_INTEGER *saltLength;
 ASN1_INTEGER *trailerField;
 } RSA_PSS_PARAMS;
RSA_PSS_PARAMS *RSA_PSS_PARAMS_new(void); void RSA_PSS_PARAMS_free(RSA_PSS_PARAMS *a); RSA_PSS_PARAMS *d2i_RSA_PSS_PARAMS(RSA_PSS_PARAMS **a, const unsigned char **in, long len); int i2d_RSA_PSS_PARAMS(RSA_PSS_PARAMS *a, unsigned char **out); extern const ASN1_ITEM RSA_PSS_PARAMS_it;
int RSA_print_fp(FILE *fp, const RSA *r,int offset);
int RSA_print(BIO *bp, const RSA *r,int offset);
int i2d_RSA_NET(const RSA *a, unsigned char **pp,
  int (*cb)(char *buf, int len, const char *prompt, int verify),
  int sgckey);
RSA *d2i_RSA_NET(RSA **a, const unsigned char **pp, long length,
   int (*cb)(char *buf, int len, const char *prompt, int verify),
   int sgckey);
int i2d_Netscape_RSA(const RSA *a, unsigned char **pp,
       int (*cb)(char *buf, int len, const char *prompt,
          int verify));
RSA *d2i_Netscape_RSA(RSA **a, const unsigned char **pp, long length,
        int (*cb)(char *buf, int len, const char *prompt,
    int verify));
int RSA_sign(int type, const unsigned char *m, unsigned int m_length,
 unsigned char *sigret, unsigned int *siglen, RSA *rsa);
int RSA_verify(int type, const unsigned char *m, unsigned int m_length,
 const unsigned char *sigbuf, unsigned int siglen, RSA *rsa);
int RSA_sign_ASN1_OCTET_STRING(int type,
 const unsigned char *m, unsigned int m_length,
 unsigned char *sigret, unsigned int *siglen, RSA *rsa);
int RSA_verify_ASN1_OCTET_STRING(int type,
 const unsigned char *m, unsigned int m_length,
 unsigned char *sigbuf, unsigned int siglen, RSA *rsa);
int RSA_blinding_on(RSA *rsa, BN_CTX *ctx);
void RSA_blinding_off(RSA *rsa);
BN_BLINDING *RSA_setup_blinding(RSA *rsa, BN_CTX *ctx);
int RSA_padding_add_PKCS1_type_1(unsigned char *to,int tlen,
 const unsigned char *f,int fl);
int RSA_padding_check_PKCS1_type_1(unsigned char *to,int tlen,
 const unsigned char *f,int fl,int rsa_len);
int RSA_padding_add_PKCS1_type_2(unsigned char *to,int tlen,
 const unsigned char *f,int fl);
int RSA_padding_check_PKCS1_type_2(unsigned char *to,int tlen,
 const unsigned char *f,int fl,int rsa_len);
int PKCS1_MGF1(unsigned char *mask, long len,
 const unsigned char *seed, long seedlen, const EVP_MD *dgst);
int RSA_padding_add_PKCS1_OAEP(unsigned char *to,int tlen,
 const unsigned char *f,int fl,
 const unsigned char *p,int pl);
int RSA_padding_check_PKCS1_OAEP(unsigned char *to,int tlen,
 const unsigned char *f,int fl,int rsa_len,
 const unsigned char *p,int pl);
int RSA_padding_add_SSLv23(unsigned char *to,int tlen,
 const unsigned char *f,int fl);
int RSA_padding_check_SSLv23(unsigned char *to,int tlen,
 const unsigned char *f,int fl,int rsa_len);
int RSA_padding_add_none(unsigned char *to,int tlen,
 const unsigned char *f,int fl);
int RSA_padding_check_none(unsigned char *to,int tlen,
 const unsigned char *f,int fl,int rsa_len);
int RSA_padding_add_X931(unsigned char *to,int tlen,
 const unsigned char *f,int fl);
int RSA_padding_check_X931(unsigned char *to,int tlen,
 const unsigned char *f,int fl,int rsa_len);
int RSA_X931_hash_id(int nid);
int RSA_verify_PKCS1_PSS(RSA *rsa, const unsigned char *mHash,
   const EVP_MD *Hash, const unsigned char *EM, int sLen);
int RSA_padding_add_PKCS1_PSS(RSA *rsa, unsigned char *EM,
   const unsigned char *mHash,
   const EVP_MD *Hash, int sLen);
int RSA_verify_PKCS1_PSS_mgf1(RSA *rsa, const unsigned char *mHash,
   const EVP_MD *Hash, const EVP_MD *mgf1Hash,
   const unsigned char *EM, int sLen);
int RSA_padding_add_PKCS1_PSS_mgf1(RSA *rsa, unsigned char *EM,
   const unsigned char *mHash,
   const EVP_MD *Hash, const EVP_MD *mgf1Hash, int sLen);
int RSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
 CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int RSA_set_ex_data(RSA *r,int idx,void *arg);
void *RSA_get_ex_data(const RSA *r, int idx);
RSA *RSAPublicKey_dup(RSA *rsa);
RSA *RSAPrivateKey_dup(RSA *rsa);
void ERR_load_RSA_strings(void);
]]
