local ffi = require "ffi"
local bit = require "bit"

include "openssl/ossl_typ"
include "openssl/symhacks"
include "openssl/bio"
include "openssl/objects"

ffi.cdef [[
struct evp_pkey_st
 {
 int type;
 int save_type;
 int references;
 const EVP_PKEY_ASN1_METHOD *ameth;
 ENGINE *engine;
 union {
  char *ptr;
  struct rsa_st *rsa;
  struct dsa_st *dsa;
  struct dh_st *dh;
  struct ec_key_st *ec;
  } pkey;
 int save_parameters;
 struct stack_st_X509_ATTRIBUTE *attributes;
 } ;
struct env_md_st
 {
 int type;
 int pkey_type;
 int md_size;
 unsigned long flags;
 int (*init)(EVP_MD_CTX *ctx);
 int (*update)(EVP_MD_CTX *ctx,const void *data,size_t count);
 int (*final)(EVP_MD_CTX *ctx,unsigned char *md);
 int (*copy)(EVP_MD_CTX *to,const EVP_MD_CTX *from);
 int (*cleanup)(EVP_MD_CTX *ctx);
 int (*sign)(int type, const unsigned char *m, unsigned int m_length,
      unsigned char *sigret, unsigned int *siglen, void *key);
 int (*verify)(int type, const unsigned char *m, unsigned int m_length,
        const unsigned char *sigbuf, unsigned int siglen,
        void *key);
 int required_pkey_type[5];
 int block_size;
 int ctx_size;
 int (*md_ctrl)(EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
 } ;
typedef int evp_sign_method(int type,const unsigned char *m,
       unsigned int m_length,unsigned char *sigret,
       unsigned int *siglen, void *key);
typedef int evp_verify_method(int type,const unsigned char *m,
       unsigned int m_length,const unsigned char *sigbuf,
       unsigned int siglen, void *key);
struct env_md_ctx_st
 {
 const EVP_MD *digest;
 ENGINE *engine;
 unsigned long flags;
 void *md_data;
 EVP_PKEY_CTX *pctx;
 int (*update)(EVP_MD_CTX *ctx,const void *data,size_t count);
 } ;
struct evp_cipher_st
 {
 int nid;
 int block_size;
 int key_len;
 int iv_len;
 unsigned long flags;
 int (*init)(EVP_CIPHER_CTX *ctx, const unsigned char *key,
      const unsigned char *iv, int enc);
 int (*do_cipher)(EVP_CIPHER_CTX *ctx, unsigned char *out,
    const unsigned char *in, size_t inl);
 int (*cleanup)(EVP_CIPHER_CTX *);
 int ctx_size;
 int (*set_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *);
 int (*get_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *);
 int (*ctrl)(EVP_CIPHER_CTX *, int type, int arg, void *ptr);
 void *app_data;
 } ;
typedef struct evp_cipher_info_st
 {
 const EVP_CIPHER *cipher;
 unsigned char iv[16];
 } EVP_CIPHER_INFO;
struct evp_cipher_ctx_st
 {
 const EVP_CIPHER *cipher;
 ENGINE *engine;
 int encrypt;
 int buf_len;
 unsigned char oiv[16];
 unsigned char iv[16];
 unsigned char buf[32];
 int num;
 void *app_data;
 int key_len;
 unsigned long flags;
 void *cipher_data;
 int final_used;
 int block_mask;
 unsigned char final[32];
 } ;
typedef struct evp_Encode_Ctx_st
 {
 int num;
 int length;
 unsigned char enc_data[80];
 int line_num;
 int expect_nl;
 } EVP_ENCODE_CTX;
typedef int (EVP_PBE_KEYGEN)(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
  ASN1_TYPE *param, const EVP_CIPHER *cipher,
                const EVP_MD *md, int en_de);
int EVP_MD_type(const EVP_MD *md);
int EVP_MD_pkey_type(const EVP_MD *md);
int EVP_MD_size(const EVP_MD *md);
int EVP_MD_block_size(const EVP_MD *md);
unsigned long EVP_MD_flags(const EVP_MD *md);
const EVP_MD *EVP_MD_CTX_md(const EVP_MD_CTX *ctx);
int EVP_CIPHER_nid(const EVP_CIPHER *cipher);
int EVP_CIPHER_block_size(const EVP_CIPHER *cipher);
int EVP_CIPHER_key_length(const EVP_CIPHER *cipher);
int EVP_CIPHER_iv_length(const EVP_CIPHER *cipher);
unsigned long EVP_CIPHER_flags(const EVP_CIPHER *cipher);
const EVP_CIPHER * EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_nid(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in);
void * EVP_CIPHER_CTX_get_app_data(const EVP_CIPHER_CTX *ctx);
void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX *ctx, void *data);
unsigned long EVP_CIPHER_CTX_flags(const EVP_CIPHER_CTX *ctx);
int EVP_Cipher(EVP_CIPHER_CTX *c,
  unsigned char *out,
  const unsigned char *in,
  unsigned int inl);
void EVP_MD_CTX_init(EVP_MD_CTX *ctx);
int EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx);
EVP_MD_CTX *EVP_MD_CTX_create(void);
void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx);
int EVP_MD_CTX_copy_ex(EVP_MD_CTX *out,const EVP_MD_CTX *in);
void EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags);
void EVP_MD_CTX_clear_flags(EVP_MD_CTX *ctx, int flags);
int EVP_MD_CTX_test_flags(const EVP_MD_CTX *ctx,int flags);
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
int EVP_DigestUpdate(EVP_MD_CTX *ctx,const void *d,
    size_t cnt);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s);
int EVP_Digest(const void *data, size_t count,
  unsigned char *md, unsigned int *size, const EVP_MD *type, ENGINE *impl);
int EVP_MD_CTX_copy(EVP_MD_CTX *out,const EVP_MD_CTX *in);
int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
int EVP_DigestFinal(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s);
int EVP_read_pw_string(char *buf,int length,const char *prompt,int verify);
int EVP_read_pw_string_min(char *buf,int minlen,int maxlen,const char *prompt,int verify);
void EVP_set_pw_prompt(const char *prompt);
char * EVP_get_pw_prompt(void);
int EVP_BytesToKey(const EVP_CIPHER *type,const EVP_MD *md,
  const unsigned char *salt, const unsigned char *data,
  int datal, int count, unsigned char *key,unsigned char *iv);
void EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags);
void EVP_CIPHER_CTX_clear_flags(EVP_CIPHER_CTX *ctx, int flags);
int EVP_CIPHER_CTX_test_flags(const EVP_CIPHER_CTX *ctx,int flags);
int EVP_EncryptInit(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher,
  const unsigned char *key, const unsigned char *iv);
int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl,
  const unsigned char *key, const unsigned char *iv);
int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
  int *outl, const unsigned char *in, int inl);
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int EVP_DecryptInit(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher,
  const unsigned char *key, const unsigned char *iv);
int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl,
  const unsigned char *key, const unsigned char *iv);
int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
  int *outl, const unsigned char *in, int inl);
int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
int EVP_CipherInit(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher,
         const unsigned char *key,const unsigned char *iv,
         int enc);
int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl,
         const unsigned char *key,const unsigned char *iv,
         int enc);
int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
  int *outl, const unsigned char *in, int inl);
int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
int EVP_SignFinal(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s,
  EVP_PKEY *pkey);
int EVP_VerifyFinal(EVP_MD_CTX *ctx,const unsigned char *sigbuf,
  unsigned int siglen,EVP_PKEY *pkey);
int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
   const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int EVP_DigestSignFinal(EVP_MD_CTX *ctx,
   unsigned char *sigret, size_t *siglen);
int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
   const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx,
   unsigned char *sig, size_t siglen);
int EVP_OpenInit(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *type,
  const unsigned char *ek, int ekl, const unsigned char *iv,
  EVP_PKEY *priv);
int EVP_OpenFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
   unsigned char **ek, int *ekl, unsigned char *iv,
  EVP_PKEY **pubk, int npubk);
int EVP_SealFinal(EVP_CIPHER_CTX *ctx,unsigned char *out,int *outl);
void EVP_EncodeInit(EVP_ENCODE_CTX *ctx);
void EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx,unsigned char *out,int *outl,
  const unsigned char *in,int inl);
void EVP_EncodeFinal(EVP_ENCODE_CTX *ctx,unsigned char *out,int *outl);
int EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int n);
void EVP_DecodeInit(EVP_ENCODE_CTX *ctx);
int EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx,unsigned char *out,int *outl,
  const unsigned char *in, int inl);
int EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned
  char *out, int *outl);
int EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n);
void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a);
int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *a);
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *a);
int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key);
BIO_METHOD *BIO_f_md(void);
BIO_METHOD *BIO_f_base64(void);
BIO_METHOD *BIO_f_cipher(void);
BIO_METHOD *BIO_f_reliable(void);
void BIO_set_cipher(BIO *b,const EVP_CIPHER *c,const unsigned char *k,
  const unsigned char *i, int enc);
const EVP_MD *EVP_md_null(void);
const EVP_MD *EVP_md2(void);
const EVP_MD *EVP_md4(void);
const EVP_MD *EVP_md5(void);
const EVP_MD *EVP_sha(void);
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_dss(void);
const EVP_MD *EVP_dss1(void);
const EVP_MD *EVP_ecdsa(void);
const EVP_MD *EVP_sha224(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);
const EVP_MD *EVP_mdc2(void);
const EVP_MD *EVP_ripemd160(void);
const EVP_MD *EVP_whirlpool(void);
const EVP_CIPHER *EVP_enc_null(void);
const EVP_CIPHER *EVP_des_ecb(void);
const EVP_CIPHER *EVP_des_ede(void);
const EVP_CIPHER *EVP_des_ede3(void);
const EVP_CIPHER *EVP_des_ede_ecb(void);
const EVP_CIPHER *EVP_des_ede3_ecb(void);
const EVP_CIPHER *EVP_des_cfb64(void);
const EVP_CIPHER *EVP_des_cfb1(void);
const EVP_CIPHER *EVP_des_cfb8(void);
const EVP_CIPHER *EVP_des_ede_cfb64(void);
const EVP_CIPHER *EVP_des_ede3_cfb64(void);
const EVP_CIPHER *EVP_des_ede3_cfb1(void);
const EVP_CIPHER *EVP_des_ede3_cfb8(void);
const EVP_CIPHER *EVP_des_ofb(void);
const EVP_CIPHER *EVP_des_ede_ofb(void);
const EVP_CIPHER *EVP_des_ede3_ofb(void);
const EVP_CIPHER *EVP_des_cbc(void);
const EVP_CIPHER *EVP_des_ede_cbc(void);
const EVP_CIPHER *EVP_des_ede3_cbc(void);
const EVP_CIPHER *EVP_desx_cbc(void);
const EVP_CIPHER *EVP_rc4(void);
const EVP_CIPHER *EVP_rc4_40(void);
const EVP_CIPHER *EVP_rc4_hmac_md5(void);
const EVP_CIPHER *EVP_idea_ecb(void);
const EVP_CIPHER *EVP_idea_cfb64(void);
const EVP_CIPHER *EVP_idea_ofb(void);
const EVP_CIPHER *EVP_idea_cbc(void);
const EVP_CIPHER *EVP_rc2_ecb(void);
const EVP_CIPHER *EVP_rc2_cbc(void);
const EVP_CIPHER *EVP_rc2_40_cbc(void);
const EVP_CIPHER *EVP_rc2_64_cbc(void);
const EVP_CIPHER *EVP_rc2_cfb64(void);
const EVP_CIPHER *EVP_rc2_ofb(void);
const EVP_CIPHER *EVP_bf_ecb(void);
const EVP_CIPHER *EVP_bf_cbc(void);
const EVP_CIPHER *EVP_bf_cfb64(void);
const EVP_CIPHER *EVP_bf_ofb(void);
const EVP_CIPHER *EVP_cast5_ecb(void);
const EVP_CIPHER *EVP_cast5_cbc(void);
const EVP_CIPHER *EVP_cast5_cfb64(void);
const EVP_CIPHER *EVP_cast5_ofb(void);
const EVP_CIPHER *EVP_aes_128_ecb(void);
const EVP_CIPHER *EVP_aes_128_cbc(void);
const EVP_CIPHER *EVP_aes_128_cfb1(void);
const EVP_CIPHER *EVP_aes_128_cfb8(void);
const EVP_CIPHER *EVP_aes_128_cfb128(void);
const EVP_CIPHER *EVP_aes_128_ofb(void);
const EVP_CIPHER *EVP_aes_128_ctr(void);
const EVP_CIPHER *EVP_aes_128_gcm(void);
const EVP_CIPHER *EVP_aes_128_ccm(void);
const EVP_CIPHER *EVP_aes_128_xts(void);
const EVP_CIPHER *EVP_aes_192_ecb(void);
const EVP_CIPHER *EVP_aes_192_cbc(void);
const EVP_CIPHER *EVP_aes_192_cfb1(void);
const EVP_CIPHER *EVP_aes_192_cfb8(void);
const EVP_CIPHER *EVP_aes_192_cfb128(void);
const EVP_CIPHER *EVP_aes_192_ofb(void);
const EVP_CIPHER *EVP_aes_192_ctr(void);
const EVP_CIPHER *EVP_aes_192_gcm(void);
const EVP_CIPHER *EVP_aes_192_ccm(void);
const EVP_CIPHER *EVP_aes_256_ecb(void);
const EVP_CIPHER *EVP_aes_256_cbc(void);
const EVP_CIPHER *EVP_aes_256_cfb1(void);
const EVP_CIPHER *EVP_aes_256_cfb8(void);
const EVP_CIPHER *EVP_aes_256_cfb128(void);
const EVP_CIPHER *EVP_aes_256_ofb(void);
const EVP_CIPHER *EVP_aes_256_ctr(void);
const EVP_CIPHER *EVP_aes_256_gcm(void);
const EVP_CIPHER *EVP_aes_256_ccm(void);
const EVP_CIPHER *EVP_aes_256_xts(void);
const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha1(void);
const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha1(void);
const EVP_CIPHER *EVP_camellia_128_ecb(void);
const EVP_CIPHER *EVP_camellia_128_cbc(void);
const EVP_CIPHER *EVP_camellia_128_cfb1(void);
const EVP_CIPHER *EVP_camellia_128_cfb8(void);
const EVP_CIPHER *EVP_camellia_128_cfb128(void);
const EVP_CIPHER *EVP_camellia_128_ofb(void);
const EVP_CIPHER *EVP_camellia_192_ecb(void);
const EVP_CIPHER *EVP_camellia_192_cbc(void);
const EVP_CIPHER *EVP_camellia_192_cfb1(void);
const EVP_CIPHER *EVP_camellia_192_cfb8(void);
const EVP_CIPHER *EVP_camellia_192_cfb128(void);
const EVP_CIPHER *EVP_camellia_192_ofb(void);
const EVP_CIPHER *EVP_camellia_256_ecb(void);
const EVP_CIPHER *EVP_camellia_256_cbc(void);
const EVP_CIPHER *EVP_camellia_256_cfb1(void);
const EVP_CIPHER *EVP_camellia_256_cfb8(void);
const EVP_CIPHER *EVP_camellia_256_cfb128(void);
const EVP_CIPHER *EVP_camellia_256_ofb(void);
const EVP_CIPHER *EVP_seed_ecb(void);
const EVP_CIPHER *EVP_seed_cbc(void);
const EVP_CIPHER *EVP_seed_cfb128(void);
const EVP_CIPHER *EVP_seed_ofb(void);
void OPENSSL_add_all_algorithms_noconf(void);
void OPENSSL_add_all_algorithms_conf(void);
void OpenSSL_add_all_ciphers(void);
void OpenSSL_add_all_digests(void);
int EVP_add_cipher(const EVP_CIPHER *cipher);
int EVP_add_digest(const EVP_MD *digest);
const EVP_CIPHER *EVP_get_cipherbyname(const char *name);
const EVP_MD *EVP_get_digestbyname(const char *name);
void EVP_cleanup(void);
void EVP_CIPHER_do_all(void (*fn)(const EVP_CIPHER *ciph,
  const char *from, const char *to, void *x), void *arg);
void EVP_CIPHER_do_all_sorted(void (*fn)(const EVP_CIPHER *ciph,
  const char *from, const char *to, void *x), void *arg);
void EVP_MD_do_all(void (*fn)(const EVP_MD *ciph,
  const char *from, const char *to, void *x), void *arg);
void EVP_MD_do_all_sorted(void (*fn)(const EVP_MD *ciph,
  const char *from, const char *to, void *x), void *arg);
int EVP_PKEY_decrypt_old(unsigned char *dec_key,
   const unsigned char *enc_key,int enc_key_len,
   EVP_PKEY *private_key);
int EVP_PKEY_encrypt_old(unsigned char *enc_key,
   const unsigned char *key,int key_len,
   EVP_PKEY *pub_key);
int EVP_PKEY_type(int type);
int EVP_PKEY_id(const EVP_PKEY *pkey);
int EVP_PKEY_base_id(const EVP_PKEY *pkey);
int EVP_PKEY_bits(EVP_PKEY *pkey);
int EVP_PKEY_size(EVP_PKEY *pkey);
int EVP_PKEY_set_type(EVP_PKEY *pkey,int type);
int EVP_PKEY_set_type_str(EVP_PKEY *pkey, const char *str, int len);
int EVP_PKEY_assign(EVP_PKEY *pkey,int type,void *key);
void * EVP_PKEY_get0(EVP_PKEY *pkey);
struct rsa_st;
int EVP_PKEY_set1_RSA(EVP_PKEY *pkey,struct rsa_st *key);
struct rsa_st *EVP_PKEY_get1_RSA(EVP_PKEY *pkey);
struct dsa_st;
int EVP_PKEY_set1_DSA(EVP_PKEY *pkey,struct dsa_st *key);
struct dsa_st *EVP_PKEY_get1_DSA(EVP_PKEY *pkey);
struct dh_st;
int EVP_PKEY_set1_DH(EVP_PKEY *pkey,struct dh_st *key);
struct dh_st *EVP_PKEY_get1_DH(EVP_PKEY *pkey);
struct ec_key_st;
int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey,struct ec_key_st *key);
struct ec_key_st *EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey);
EVP_PKEY * EVP_PKEY_new(void);
void EVP_PKEY_free(EVP_PKEY *pkey);
EVP_PKEY * d2i_PublicKey(int type,EVP_PKEY **a, const unsigned char **pp,
   long length);
int i2d_PublicKey(EVP_PKEY *a, unsigned char **pp);
EVP_PKEY * d2i_PrivateKey(int type,EVP_PKEY **a, const unsigned char **pp,
   long length);
EVP_PKEY * d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp,
   long length);
int i2d_PrivateKey(EVP_PKEY *a, unsigned char **pp);
int EVP_PKEY_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from);
int EVP_PKEY_missing_parameters(const EVP_PKEY *pkey);
int EVP_PKEY_save_parameters(EVP_PKEY *pkey,int mode);
int EVP_PKEY_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b);
int EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b);
int EVP_PKEY_print_public(BIO *out, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);
int EVP_PKEY_print_private(BIO *out, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);
int EVP_PKEY_print_params(BIO *out, const EVP_PKEY *pkey,
    int indent, ASN1_PCTX *pctx);
int EVP_PKEY_get_default_digest_nid(EVP_PKEY *pkey, int *pnid);
int EVP_CIPHER_type(const EVP_CIPHER *ctx);
int EVP_CIPHER_param_to_asn1(EVP_CIPHER_CTX *c, ASN1_TYPE *type);
int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX *c, ASN1_TYPE *type);
int EVP_CIPHER_set_asn1_iv(EVP_CIPHER_CTX *c,ASN1_TYPE *type);
int EVP_CIPHER_get_asn1_iv(EVP_CIPHER_CTX *c,ASN1_TYPE *type);
int PKCS5_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
    ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md,
    int en_de);
int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,
      const unsigned char *salt, int saltlen, int iter,
      int keylen, unsigned char *out);
int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
      const unsigned char *salt, int saltlen, int iter,
      const EVP_MD *digest,
        int keylen, unsigned char *out);
int PKCS5_v2_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
    ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md,
    int en_de);
void PKCS5_PBE_add(void);
int EVP_PBE_CipherInit (ASN1_OBJECT *pbe_obj, const char *pass, int passlen,
      ASN1_TYPE *param, EVP_CIPHER_CTX *ctx, int en_de);
int EVP_PBE_alg_add_type(int pbe_type, int pbe_nid, int cipher_nid, int md_nid,
      EVP_PBE_KEYGEN *keygen);
int EVP_PBE_alg_add(int nid, const EVP_CIPHER *cipher, const EVP_MD *md,
      EVP_PBE_KEYGEN *keygen);
int EVP_PBE_find(int type, int pbe_nid,
   int *pcnid, int *pmnid, EVP_PBE_KEYGEN **pkeygen);
void EVP_PBE_cleanup(void);
int EVP_PKEY_asn1_get_count(void);
const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_get0(int idx);
const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_find(ENGINE **pe, int type);
const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_find_str(ENGINE **pe,
     const char *str, int len);
int EVP_PKEY_asn1_add0(const EVP_PKEY_ASN1_METHOD *ameth);
int EVP_PKEY_asn1_add_alias(int to, int from);
int EVP_PKEY_asn1_get0_info(int *ppkey_id, int *pkey_base_id, int *ppkey_flags,
    const char **pinfo, const char **ppem_str,
     const EVP_PKEY_ASN1_METHOD *ameth);
const EVP_PKEY_ASN1_METHOD* EVP_PKEY_get0_asn1(EVP_PKEY *pkey);
EVP_PKEY_ASN1_METHOD* EVP_PKEY_asn1_new(int id, int flags,
     const char *pem_str, const char *info);
void EVP_PKEY_asn1_copy(EVP_PKEY_ASN1_METHOD *dst,
   const EVP_PKEY_ASN1_METHOD *src);
void EVP_PKEY_asn1_free(EVP_PKEY_ASN1_METHOD *ameth);
void EVP_PKEY_asn1_set_public(EVP_PKEY_ASN1_METHOD *ameth,
  int (*pub_decode)(EVP_PKEY *pk, X509_PUBKEY *pub),
  int (*pub_encode)(X509_PUBKEY *pub, const EVP_PKEY *pk),
  int (*pub_cmp)(const EVP_PKEY *a, const EVP_PKEY *b),
  int (*pub_print)(BIO *out, const EVP_PKEY *pkey, int indent,
       ASN1_PCTX *pctx),
  int (*pkey_size)(const EVP_PKEY *pk),
  int (*pkey_bits)(const EVP_PKEY *pk));
void EVP_PKEY_asn1_set_private(EVP_PKEY_ASN1_METHOD *ameth,
  int (*priv_decode)(EVP_PKEY *pk, PKCS8_PRIV_KEY_INFO *p8inf),
  int (*priv_encode)(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pk),
  int (*priv_print)(BIO *out, const EVP_PKEY *pkey, int indent,
       ASN1_PCTX *pctx));
void EVP_PKEY_asn1_set_param(EVP_PKEY_ASN1_METHOD *ameth,
  int (*param_decode)(EVP_PKEY *pkey,
    const unsigned char **pder, int derlen),
  int (*param_encode)(const EVP_PKEY *pkey, unsigned char **pder),
  int (*param_missing)(const EVP_PKEY *pk),
  int (*param_copy)(EVP_PKEY *to, const EVP_PKEY *from),
  int (*param_cmp)(const EVP_PKEY *a, const EVP_PKEY *b),
  int (*param_print)(BIO *out, const EVP_PKEY *pkey, int indent,
       ASN1_PCTX *pctx));
void EVP_PKEY_asn1_set_free(EVP_PKEY_ASN1_METHOD *ameth,
  void (*pkey_free)(EVP_PKEY *pkey));
void EVP_PKEY_asn1_set_ctrl(EVP_PKEY_ASN1_METHOD *ameth,
  int (*pkey_ctrl)(EVP_PKEY *pkey, int op,
       long arg1, void *arg2));
const EVP_PKEY_METHOD *EVP_PKEY_meth_find(int type);
EVP_PKEY_METHOD* EVP_PKEY_meth_new(int id, int flags);
void EVP_PKEY_meth_get0_info(int *ppkey_id, int *pflags,
    const EVP_PKEY_METHOD *meth);
void EVP_PKEY_meth_copy(EVP_PKEY_METHOD *dst, const EVP_PKEY_METHOD *src);
void EVP_PKEY_meth_free(EVP_PKEY_METHOD *pmeth);
int EVP_PKEY_meth_add0(const EVP_PKEY_METHOD *pmeth);
EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);
EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, ENGINE *e);
EVP_PKEY_CTX *EVP_PKEY_CTX_dup(EVP_PKEY_CTX *ctx);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
    int cmd, int p1, void *p2);
int EVP_PKEY_CTX_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
      const char *value);
int EVP_PKEY_CTX_get_operation(EVP_PKEY_CTX *ctx);
void EVP_PKEY_CTX_set0_keygen_info(EVP_PKEY_CTX *ctx, int *dat, int datlen);
EVP_PKEY *EVP_PKEY_new_mac_key(int type, ENGINE *e,
    const unsigned char *key, int keylen);
void EVP_PKEY_CTX_set_data(EVP_PKEY_CTX *ctx, void *data);
void *EVP_PKEY_CTX_get_data(EVP_PKEY_CTX *ctx);
EVP_PKEY *EVP_PKEY_CTX_get0_pkey(EVP_PKEY_CTX *ctx);
EVP_PKEY *EVP_PKEY_CTX_get0_peerkey(EVP_PKEY_CTX *ctx);
void EVP_PKEY_CTX_set_app_data(EVP_PKEY_CTX *ctx, void *data);
void *EVP_PKEY_CTX_get_app_data(EVP_PKEY_CTX *ctx);
int EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_sign(EVP_PKEY_CTX *ctx,
   unsigned char *sig, size_t *siglen,
   const unsigned char *tbs, size_t tbslen);
int EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_verify(EVP_PKEY_CTX *ctx,
   const unsigned char *sig, size_t siglen,
   const unsigned char *tbs, size_t tbslen);
int EVP_PKEY_verify_recover_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_verify_recover(EVP_PKEY_CTX *ctx,
   unsigned char *rout, size_t *routlen,
   const unsigned char *sig, size_t siglen);
int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx,
   unsigned char *out, size_t *outlen,
   const unsigned char *in, size_t inlen);
int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx,
   unsigned char *out, size_t *outlen,
   const unsigned char *in, size_t inlen);
int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer);
int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
typedef int EVP_PKEY_gen_cb(EVP_PKEY_CTX *ctx);
int EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
void EVP_PKEY_CTX_set_cb(EVP_PKEY_CTX *ctx, EVP_PKEY_gen_cb *cb);
EVP_PKEY_gen_cb *EVP_PKEY_CTX_get_cb(EVP_PKEY_CTX *ctx);
int EVP_PKEY_CTX_get_keygen_info(EVP_PKEY_CTX *ctx, int idx);
void EVP_PKEY_meth_set_init(EVP_PKEY_METHOD *pmeth,
 int (*init)(EVP_PKEY_CTX *ctx));
void EVP_PKEY_meth_set_copy(EVP_PKEY_METHOD *pmeth,
 int (*copy)(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src));
void EVP_PKEY_meth_set_cleanup(EVP_PKEY_METHOD *pmeth,
 void (*cleanup)(EVP_PKEY_CTX *ctx));
void EVP_PKEY_meth_set_paramgen(EVP_PKEY_METHOD *pmeth,
 int (*paramgen_init)(EVP_PKEY_CTX *ctx),
 int (*paramgen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey));
void EVP_PKEY_meth_set_keygen(EVP_PKEY_METHOD *pmeth,
 int (*keygen_init)(EVP_PKEY_CTX *ctx),
 int (*keygen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey));
void EVP_PKEY_meth_set_sign(EVP_PKEY_METHOD *pmeth,
 int (*sign_init)(EVP_PKEY_CTX *ctx),
 int (*sign)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
     const unsigned char *tbs, size_t tbslen));
void EVP_PKEY_meth_set_verify(EVP_PKEY_METHOD *pmeth,
 int (*verify_init)(EVP_PKEY_CTX *ctx),
 int (*verify)(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen,
     const unsigned char *tbs, size_t tbslen));
void EVP_PKEY_meth_set_verify_recover(EVP_PKEY_METHOD *pmeth,
 int (*verify_recover_init)(EVP_PKEY_CTX *ctx),
 int (*verify_recover)(EVP_PKEY_CTX *ctx,
     unsigned char *sig, size_t *siglen,
     const unsigned char *tbs, size_t tbslen));
void EVP_PKEY_meth_set_signctx(EVP_PKEY_METHOD *pmeth,
 int (*signctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx),
 int (*signctx)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
     EVP_MD_CTX *mctx));
void EVP_PKEY_meth_set_verifyctx(EVP_PKEY_METHOD *pmeth,
 int (*verifyctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx),
 int (*verifyctx)(EVP_PKEY_CTX *ctx, const unsigned char *sig,int siglen,
     EVP_MD_CTX *mctx));
void EVP_PKEY_meth_set_encrypt(EVP_PKEY_METHOD *pmeth,
 int (*encrypt_init)(EVP_PKEY_CTX *ctx),
 int (*encryptfn)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
     const unsigned char *in, size_t inlen));
void EVP_PKEY_meth_set_decrypt(EVP_PKEY_METHOD *pmeth,
 int (*decrypt_init)(EVP_PKEY_CTX *ctx),
 int (*decrypt)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
     const unsigned char *in, size_t inlen));
void EVP_PKEY_meth_set_derive(EVP_PKEY_METHOD *pmeth,
 int (*derive_init)(EVP_PKEY_CTX *ctx),
 int (*derive)(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen));
void EVP_PKEY_meth_set_ctrl(EVP_PKEY_METHOD *pmeth,
 int (*ctrl)(EVP_PKEY_CTX *ctx, int type, int p1, void *p2),
 int (*ctrl_str)(EVP_PKEY_CTX *ctx,
     const char *type, const char *value));
void ERR_load_EVP_strings(void);
]]

module ( ... )

EVP_aes_128_cfb = EVP_aes_128_cfb128
EVP_aes_192_cfb = EVP_aes_192_cfb128
EVP_aes_256_cfb = EVP_aes_256_cfb128
EVP_bf_cfb = EVP_bf_cfb64
EVP_camellia_128_cfb = EVP_camellia_128_cfb128
EVP_camellia_192_cfb = EVP_camellia_192_cfb128
EVP_camellia_256_cfb = EVP_camellia_256_cfb128
EVP_cast5_cfb = EVP_cast5_cfb64
EVP_CIPH_ALWAYS_CALL_INIT = 0x20
EVP_CIPH_CBC_MODE = 0x2
EVP_CIPH_CCM_MODE = 0x7
EVP_CIPH_CFB_MODE = 0x3
EVP_CIPH_CTR_MODE = 0x5
EVP_CIPH_CTRL_INIT = 0x40
EVP_CIPH_CUSTOM_COPY = 0x400
EVP_CIPH_CUSTOM_IV = 0x10
EVP_CIPH_CUSTOM_KEY_LENGTH = 0x80
EVP_CIPH_ECB_MODE = 0x1
EVP_CIPH_FLAG_AEAD_CIPHER = 0x200000
EVP_CIPH_FLAG_CUSTOM_CIPHER = 0x100000
EVP_CIPH_FLAG_DEFAULT_ASN1 = 0x1000
EVP_CIPH_FLAG_FIPS = 0x4000
EVP_CIPH_FLAG_LENGTH_BITS = 0x2000
EVP_CIPH_FLAG_NON_FIPS_ALLOW = 0x8000
EVP_CIPH_GCM_MODE = 0x6
EVP_CIPH_MODE = 0xF0007
EVP_CIPH_NO_PADDING = 0x100
EVP_CIPH_OFB_MODE = 0x4
EVP_CIPH_RAND_KEY = 0x200
EVP_CIPH_STREAM_CIPHER = 0x0
EVP_CIPH_VARIABLE_LENGTH = 0x8
EVP_CIPH_XTS_MODE = 0x10001
EVP_CTRL_AEAD_SET_MAC_KEY = 0x17
EVP_CTRL_AEAD_TLS1_AAD = 0x16
EVP_CTRL_CCM_GET_TAG = EVP_CTRL_GCM_GET_TAG
EVP_CTRL_CCM_SET_IVLEN = EVP_CTRL_GCM_SET_IVLEN
EVP_CTRL_CCM_SET_L = 0x14
EVP_CTRL_CCM_SET_MSGLEN = 0x15
EVP_CTRL_CCM_SET_TAG = EVP_CTRL_GCM_SET_TAG
EVP_CTRL_COPY = 0x8
EVP_CTRL_GCM_GET_TAG = 0x10
EVP_CTRL_GCM_IV_GEN = 0x13
EVP_CTRL_GCM_SET_IV_FIXED = 0x12
EVP_CTRL_GCM_SET_IV_INV = 0x18
EVP_CTRL_GCM_SET_IVLEN = 0x9
EVP_CTRL_GCM_SET_TAG = 0x11
EVP_CTRL_GET_RC2_KEY_BITS = 0x2
EVP_CTRL_GET_RC5_ROUNDS = 0x4
EVP_CTRL_INIT = 0x0
EVP_CTRL_PBE_PRF_NID = 0x7
EVP_CTRL_RAND_KEY = 0x6
EVP_CTRL_SET_KEY_LENGTH = 0x1
EVP_CTRL_SET_RC2_KEY_BITS = 0x3
EVP_CTRL_SET_RC5_ROUNDS = 0x5
EVP_des_cfb = EVP_des_cfb64
EVP_des_ede3_cfb = EVP_des_ede3_cfb64
EVP_des_ede_cfb = EVP_des_ede_cfb64
EVP_F_AES_INIT_KEY = 133
EVP_F_AES_XTS = 172
EVP_F_AES_XTS_CIPHER = 175
EVP_F_AESNI_INIT_KEY = 165
EVP_F_AESNI_XTS_CIPHER = 176
EVP_F_CAMELLIA_INIT_KEY = 159
EVP_F_CMAC_INIT = 173
EVP_F_D2I_PKEY = 100
EVP_F_DO_SIGVER_INIT = 161
EVP_F_DSA_PKEY2PKCS8 = 135
EVP_F_DSAPKEY2PKCS8 = 134
EVP_F_ECDSA_PKEY2PKCS8 = 129
EVP_F_ECKEY_PKEY2PKCS8 = 132
EVP_F_EVP_CIPHER_CTX_COPY = 163
EVP_F_EVP_CIPHER_CTX_CTRL = 124
EVP_F_EVP_CIPHER_CTX_SET_KEY_LENGTH = 122
EVP_F_EVP_CIPHERINIT_EX = 123
EVP_F_EVP_DECRYPTFINAL_EX = 101
EVP_F_EVP_DIGESTINIT_EX = 128
EVP_F_EVP_ENCRYPTFINAL_EX = 127
EVP_F_EVP_MD_CTX_COPY_EX = 110
EVP_F_EVP_MD_SIZE = 162
EVP_F_EVP_OPENINIT = 102
EVP_F_EVP_PBE_ALG_ADD = 115
EVP_F_EVP_PBE_ALG_ADD_TYPE = 160
EVP_F_EVP_PBE_CIPHERINIT = 116
EVP_F_EVP_PKCS82PKEY = 111
EVP_F_EVP_PKCS82PKEY_BROKEN = 136
EVP_F_EVP_PKEY2PKCS8_BROKEN = 113
EVP_F_EVP_PKEY_COPY_PARAMETERS = 103
EVP_F_EVP_PKEY_CTX_CTRL = 137
EVP_F_EVP_PKEY_CTX_CTRL_STR = 150
EVP_F_EVP_PKEY_CTX_DUP = 156
EVP_F_EVP_PKEY_DECRYPT = 104
EVP_F_EVP_PKEY_DECRYPT_INIT = 138
EVP_F_EVP_PKEY_DECRYPT_OLD = 151
EVP_F_EVP_PKEY_DERIVE = 153
EVP_F_EVP_PKEY_DERIVE_INIT = 154
EVP_F_EVP_PKEY_DERIVE_SET_PEER = 155
EVP_F_EVP_PKEY_ENCRYPT = 105
EVP_F_EVP_PKEY_ENCRYPT_INIT = 139
EVP_F_EVP_PKEY_ENCRYPT_OLD = 152
EVP_F_EVP_PKEY_GET1_DH = 119
EVP_F_EVP_PKEY_GET1_DSA = 120
EVP_F_EVP_PKEY_GET1_EC_KEY = 131
EVP_F_EVP_PKEY_GET1_ECDSA = 130
EVP_F_EVP_PKEY_GET1_RSA = 121
EVP_F_EVP_PKEY_KEYGEN = 146
EVP_F_EVP_PKEY_KEYGEN_INIT = 147
EVP_F_EVP_PKEY_NEW = 106
EVP_F_EVP_PKEY_PARAMGEN = 148
EVP_F_EVP_PKEY_PARAMGEN_INIT = 149
EVP_F_EVP_PKEY_SIGN = 140
EVP_F_EVP_PKEY_SIGN_INIT = 141
EVP_F_EVP_PKEY_VERIFY = 142
EVP_F_EVP_PKEY_VERIFY_INIT = 143
EVP_F_EVP_PKEY_VERIFY_RECOVER = 144
EVP_F_EVP_PKEY_VERIFY_RECOVER_INIT = 145
EVP_F_EVP_RIJNDAEL = 126
EVP_F_EVP_SIGNFINAL = 107
EVP_F_EVP_VERIFYFINAL = 108
EVP_F_FIPS_CIPHER_CTX_COPY = 170
EVP_F_FIPS_CIPHER_CTX_CTRL = 167
EVP_F_FIPS_CIPHER_CTX_SET_KEY_LENGTH = 171
EVP_F_FIPS_CIPHERINIT = 166
EVP_F_FIPS_DIGESTINIT = 168
EVP_F_FIPS_MD_CTX_COPY = 169
EVP_F_HMAC_INIT_EX = 174
EVP_F_INT_CTX_NEW = 157
EVP_F_PKCS5_PBE_KEYIVGEN = 117
EVP_F_PKCS5_V2_PBE_KEYIVGEN = 118
EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN = 164
EVP_F_PKCS8_SET_BROKEN = 112
EVP_F_PKEY_SET_TYPE = 158
EVP_F_RC2_MAGIC_TO_METH = 109
EVP_F_RC5_CTRL = 125
EVP_GCM_TLS_EXPLICIT_IV_LEN = 8
EVP_GCM_TLS_FIXED_IV_LEN = 4
EVP_GCM_TLS_TAG_LEN = 16
EVP_idea_cfb = EVP_idea_cfb64
EVP_MAX_BLOCK_LENGTH = 32
EVP_MAX_IV_LENGTH = 16
EVP_MAX_KEY_LENGTH = 64
EVP_MAX_MD_SIZE = 64
EVP_MD_CTRL_ALG_CTRL = 0x1000
EVP_MD_CTRL_DIGALGID = 0x1
EVP_MD_CTRL_MICALG = 0x2
EVP_MD_CTX_FLAG_CLEANED = 0x0002
EVP_MD_CTX_FLAG_NO_INIT = 0x0100
EVP_MD_CTX_FLAG_NON_FIPS_ALLOW = 0x0008
EVP_MD_CTX_FLAG_ONESHOT = 0x0001
EVP_MD_CTX_FLAG_PAD_MASK = 0xF0
EVP_MD_CTX_FLAG_PAD_PKCS1 = 0x00
EVP_MD_CTX_FLAG_PAD_PSS = 0x20
EVP_MD_CTX_FLAG_PAD_X931 = 0x10
EVP_MD_CTX_FLAG_REUSE = 0x0004
EVP_MD_FLAG_DIGALGID_ABSENT = 0x0008
EVP_MD_FLAG_DIGALGID_CUSTOM = 0x0018
EVP_MD_FLAG_DIGALGID_MASK = 0x0018
EVP_MD_FLAG_DIGALGID_NULL = 0x0000
EVP_MD_FLAG_FIPS = 0x0400
EVP_MD_FLAG_ONESHOT = 0x0001
EVP_MD_FLAG_PKEY_DIGEST = 0x0002
EVP_MD_FLAG_PKEY_METHOD_SIGNATURE = 0x0004
EVP_PBE_TYPE_OUTER = 0x0
EVP_PBE_TYPE_PRF = 0x1
EVP_PK_DH = 0x0004
EVP_PK_DSA = 0x0002
EVP_PK_EC = 0x0008
EVP_PK_RSA = 0x0001
EVP_PKEY_ALG_CTRL = 0x1000
EVP_PKEY_CMAC = NID_cmac
EVP_PKEY_CTRL_CIPHER = 12
EVP_PKEY_CTRL_CMS_DECRYPT = 10
EVP_PKEY_CTRL_CMS_ENCRYPT = 9
EVP_PKEY_CTRL_CMS_SIGN = 11
EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR = (EVP_PKEY_ALG_CTRL + 2)
EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN = (EVP_PKEY_ALG_CTRL + 1)
EVP_PKEY_CTRL_DIGESTINIT = 7
EVP_PKEY_CTRL_DSA_PARAMGEN_BITS = (EVP_PKEY_ALG_CTRL + 1)
EVP_PKEY_CTRL_DSA_PARAMGEN_MD = (EVP_PKEY_ALG_CTRL + 3)
EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS = (EVP_PKEY_ALG_CTRL + 2)
EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID = (EVP_PKEY_ALG_CTRL + 1)
EVP_PKEY_CTRL_GET_RSA_MGF1_MD = (EVP_PKEY_ALG_CTRL + 8)
EVP_PKEY_CTRL_GET_RSA_PADDING = (EVP_PKEY_ALG_CTRL + 6)
EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN = (EVP_PKEY_ALG_CTRL + 7)
EVP_PKEY_CTRL_MD = 1
EVP_PKEY_CTRL_PEER_KEY = 2
EVP_PKEY_CTRL_PKCS7_DECRYPT = 4
EVP_PKEY_CTRL_PKCS7_ENCRYPT = 3
EVP_PKEY_CTRL_PKCS7_SIGN = 5
EVP_PKEY_CTRL_RSA_KEYGEN_BITS = (EVP_PKEY_ALG_CTRL + 3)
EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP = (EVP_PKEY_ALG_CTRL + 4)
EVP_PKEY_CTRL_RSA_MGF1_MD = (EVP_PKEY_ALG_CTRL + 5)
EVP_PKEY_CTRL_RSA_PADDING = (EVP_PKEY_ALG_CTRL + 1)
EVP_PKEY_CTRL_RSA_PSS_SALTLEN = (EVP_PKEY_ALG_CTRL + 2)
EVP_PKEY_CTRL_SET_IV = 8
EVP_PKEY_CTRL_SET_MAC_KEY = 6
EVP_PKEY_DH = NID_dhKeyAgreement
EVP_PKEY_DSA = NID_dsa
EVP_PKEY_DSA1 = NID_dsa_2
EVP_PKEY_DSA2 = NID_dsaWithSHA
EVP_PKEY_DSA3 = NID_dsaWithSHA1
EVP_PKEY_DSA4 = NID_dsaWithSHA1_2
EVP_PKEY_EC = NID_X9_62_id_ecPublicKey
EVP_PKEY_FLAG_AUTOARGLEN = 2
EVP_PKEY_FLAG_SIGCTX_CUSTOM = 4
EVP_PKEY_HMAC = NID_hmac
EVP_PKEY_MO_DECRYPT = 0x0008
EVP_PKEY_MO_ENCRYPT = 0x0004
EVP_PKEY_MO_SIGN = 0x0001
EVP_PKEY_MO_VERIFY = 0x0002
EVP_PKEY_NONE = NID_undef
EVP_PKEY_OP_DECRYPT = (bit.lshift(1,9))
EVP_PKEY_OP_DERIVE = (bit.lshift(1,10))
EVP_PKEY_OP_ENCRYPT = (bit.lshift(1,8))
EVP_PKEY_OP_KEYGEN = (bit.lshift(1,2))
EVP_PKEY_OP_PARAMGEN = (bit.lshift(1,1))
EVP_PKEY_OP_SIGN = (bit.lshift(1,3))
EVP_PKEY_OP_SIGNCTX = (bit.lshift(1,6))
EVP_PKEY_OP_UNDEFINED = 0
EVP_PKEY_OP_VERIFY = (bit.lshift(1,4))
EVP_PKEY_OP_VERIFYCTX = (bit.lshift(1,7))
EVP_PKEY_OP_VERIFYRECOVER = (bit.lshift(1,5))
EVP_PKEY_RSA = NID_rsaEncryption
EVP_PKEY_RSA2 = NID_rsa
EVP_PKS_DSA = 0x0200
EVP_PKS_EC = 0x0400
EVP_PKS_RSA = 0x0100
EVP_PKT_ENC = 0x0020
EVP_PKT_EXCH = 0x0040
EVP_PKT_EXP = 0x1000
EVP_PKT_SIGN = 0x0010
EVP_R_AES_IV_SETUP_FAILED = 162
EVP_R_AES_KEY_SETUP_FAILED = 143
EVP_R_ASN1_LIB = 140
EVP_R_BAD_BLOCK_LENGTH = 136
EVP_R_BAD_DECRYPT = 100
EVP_R_BAD_KEY_LENGTH = 137
EVP_R_BN_DECODE_ERROR = 112
EVP_R_BN_PUBKEY_ERROR = 113
EVP_R_BUFFER_TOO_SMALL = 155
EVP_R_CAMELLIA_KEY_SETUP_FAILED = 157
EVP_R_CIPHER_PARAMETER_ERROR = 122
EVP_R_COMMAND_NOT_SUPPORTED = 147
EVP_R_CTRL_NOT_IMPLEMENTED = 132
EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED = 133
EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH = 138
EVP_R_DECODE_ERROR = 114
EVP_R_DIFFERENT_KEY_TYPES = 101
EVP_R_DIFFERENT_PARAMETERS = 153
EVP_R_DISABLED_FOR_FIPS = 163
EVP_R_ENCODE_ERROR = 115
EVP_R_EVP_PBE_CIPHERINIT_ERROR = 119
EVP_R_EXPECTING_A_DH_KEY = 128
EVP_R_EXPECTING_A_DSA_KEY = 129
EVP_R_EXPECTING_A_EC_KEY = 142
EVP_R_EXPECTING_A_ECDSA_KEY = 141
EVP_R_EXPECTING_AN_RSA_KEY = 127
EVP_R_INITIALIZATION_ERROR = 134
EVP_R_INPUT_NOT_INITIALIZED = 111
EVP_R_INVALID_DIGEST = 152
EVP_R_INVALID_KEY_LENGTH = 130
EVP_R_INVALID_OPERATION = 148
EVP_R_IV_TOO_LARGE = 102
EVP_R_KEYGEN_FAILURE = 120
EVP_R_MESSAGE_DIGEST_IS_NULL = 159
EVP_R_METHOD_NOT_SUPPORTED = 144
EVP_R_MISSING_PARAMETERS = 103
EVP_R_NO_CIPHER_SET = 131
EVP_R_NO_DEFAULT_DIGEST = 158
EVP_R_NO_DIGEST_SET = 139
EVP_R_NO_DSA_PARAMETERS = 116
EVP_R_NO_KEY_SET = 154
EVP_R_NO_OPERATION_SET = 149
EVP_R_NO_SIGN_FUNCTION_CONFIGURED = 104
EVP_R_NO_VERIFY_FUNCTION_CONFIGURED = 105
EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE = 150
EVP_R_OPERATON_NOT_INITIALIZED = 151
EVP_R_PKCS8_UNKNOWN_BROKEN_TYPE = 117
EVP_R_PRIVATE_KEY_DECODE_ERROR = 145
EVP_R_PRIVATE_KEY_ENCODE_ERROR = 146
EVP_R_PUBLIC_KEY_NOT_RSA = 106
EVP_R_TOO_LARGE = 164
EVP_R_UNKNOWN_CIPHER = 160
EVP_R_UNKNOWN_DIGEST = 161
EVP_R_UNKNOWN_PBE_ALGORITHM = 121
EVP_R_UNSUPORTED_NUMBER_OF_ROUNDS = 135
EVP_R_UNSUPPORTED_ALGORITHM = 156
EVP_R_UNSUPPORTED_CIPHER = 107
EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION = 124
EVP_R_UNSUPPORTED_KEY_SIZE = 108
EVP_R_UNSUPPORTED_KEYLENGTH = 123
EVP_R_UNSUPPORTED_PRF = 125
EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM = 118
EVP_R_UNSUPPORTED_SALT_TYPE = 126
EVP_R_WRONG_FINAL_BLOCK_LENGTH = 109
EVP_R_WRONG_PUBLIC_KEY_TYPE = 110
EVP_rc2_cfb = EVP_rc2_cfb64
EVP_seed_cfb = EVP_seed_cfb128

return _M
