local ffi = require "ffi"

include "openssl/e_os2"
include "openssl/bio"
include "openssl/stack"
include "openssl/evp"
include "openssl/x509"
include "openssl/pem2"
include "openssl/symhacks"

ffi.cdef [[
typedef struct PEM_Encode_Seal_st
 {
 EVP_ENCODE_CTX encode;
 EVP_MD_CTX md;
 EVP_CIPHER_CTX cipher;
 } PEM_ENCODE_SEAL_CTX;
typedef struct pem_recip_st
 {
 char *name;
 X509_NAME *dn;
 int cipher;
 int key_enc;
 } PEM_USER;
typedef struct pem_ctx_st
 {
 int type;
 struct {
  int version;
  int mode;
  } proc_type;
 char *domain;
 struct {
  int cipher;
  } DEK_info;
 PEM_USER *originator;
 int num_recipient;
 PEM_USER **recipient;
 EVP_MD *md;
 int md_enc;
 int md_len;
 char *md_data;
 EVP_CIPHER *dec;
 int key_len;
 unsigned char *key;
 int data_enc;
 int data_len;
 unsigned char *data;
 } PEM_CTX;
typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);
int PEM_get_EVP_CIPHER_INFO(char *header, EVP_CIPHER_INFO *cipher);
int PEM_do_header (EVP_CIPHER_INFO *cipher, unsigned char *data,long *len,
 pem_password_cb *callback,void *u);
int PEM_read_bio(BIO *bp, char **name, char **header,
  unsigned char **data,long *len);
int PEM_write_bio(BIO *bp,const char *name,char *hdr,unsigned char *data,
  long len);
int PEM_bytes_read_bio(unsigned char **pdata, long *plen, char **pnm, const char *name, BIO *bp,
      pem_password_cb *cb, void *u);
void * PEM_ASN1_read_bio(d2i_of_void *d2i, const char *name, BIO *bp,
     void **x, pem_password_cb *cb, void *u);
int PEM_ASN1_write_bio(i2d_of_void *i2d,const char *name,BIO *bp, void *x,
      const EVP_CIPHER *enc,unsigned char *kstr,int klen,
      pem_password_cb *cb, void *u);
struct stack_st_X509_INFO * PEM_X509_INFO_read_bio(BIO *bp, struct stack_st_X509_INFO *sk, pem_password_cb *cb, void *u);
int PEM_X509_INFO_write_bio(BIO *bp,X509_INFO *xi, EVP_CIPHER *enc,
  unsigned char *kstr, int klen, pem_password_cb *cd, void *u);
int PEM_read(FILE *fp, char **name, char **header,
  unsigned char **data,long *len);
int PEM_write(FILE *fp,char *name,char *hdr,unsigned char *data,long len);
void * PEM_ASN1_read(d2i_of_void *d2i, const char *name, FILE *fp, void **x,
        pem_password_cb *cb, void *u);
int PEM_ASN1_write(i2d_of_void *i2d,const char *name,FILE *fp,
         void *x,const EVP_CIPHER *enc,unsigned char *kstr,
         int klen,pem_password_cb *callback, void *u);
struct stack_st_X509_INFO * PEM_X509_INFO_read(FILE *fp, struct stack_st_X509_INFO *sk,
 pem_password_cb *cb, void *u);
int PEM_SealInit(PEM_ENCODE_SEAL_CTX *ctx, EVP_CIPHER *type,
  EVP_MD *md_type, unsigned char **ek, int *ekl,
  unsigned char *iv, EVP_PKEY **pubk, int npubk);
void PEM_SealUpdate(PEM_ENCODE_SEAL_CTX *ctx, unsigned char *out, int *outl,
  unsigned char *in, int inl);
int PEM_SealFinal(PEM_ENCODE_SEAL_CTX *ctx, unsigned char *sig,int *sigl,
  unsigned char *out, int *outl, EVP_PKEY *priv);
void PEM_SignInit(EVP_MD_CTX *ctx, EVP_MD *type);
void PEM_SignUpdate(EVP_MD_CTX *ctx,unsigned char *d,unsigned int cnt);
int PEM_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
  unsigned int *siglen, EVP_PKEY *pkey);
int PEM_def_callback(char *buf, int num, int w, void *key);
void PEM_proc_type(char *buf, int type);
void PEM_dek_info(char *buf, const char *type, int len, char *str);
X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u); X509 *PEM_read_X509(FILE *fp, X509 **x, pem_password_cb *cb, void *u); int PEM_write_bio_X509(BIO *bp, X509 *x); int PEM_write_X509(FILE *fp, X509 *x);
X509 *PEM_read_bio_X509_AUX(BIO *bp, X509 **x, pem_password_cb *cb, void *u); X509 *PEM_read_X509_AUX(FILE *fp, X509 **x, pem_password_cb *cb, void *u); int PEM_write_bio_X509_AUX(BIO *bp, X509 *x); int PEM_write_X509_AUX(FILE *fp, X509 *x);
X509_CERT_PAIR *PEM_read_bio_X509_CERT_PAIR(BIO *bp, X509_CERT_PAIR **x, pem_password_cb *cb, void *u); X509_CERT_PAIR *PEM_read_X509_CERT_PAIR(FILE *fp, X509_CERT_PAIR **x, pem_password_cb *cb, void *u); int PEM_write_bio_X509_CERT_PAIR(BIO *bp, X509_CERT_PAIR *x); int PEM_write_X509_CERT_PAIR(FILE *fp, X509_CERT_PAIR *x);
X509_REQ *PEM_read_bio_X509_REQ(BIO *bp, X509_REQ **x, pem_password_cb *cb, void *u); X509_REQ *PEM_read_X509_REQ(FILE *fp, X509_REQ **x, pem_password_cb *cb, void *u); int PEM_write_bio_X509_REQ(BIO *bp, X509_REQ *x); int PEM_write_X509_REQ(FILE *fp, X509_REQ *x);
int PEM_write_bio_X509_REQ_NEW(BIO *bp, X509_REQ *x); int PEM_write_X509_REQ_NEW(FILE *fp, X509_REQ *x);
X509_CRL *PEM_read_bio_X509_CRL(BIO *bp, X509_CRL **x, pem_password_cb *cb, void *u); X509_CRL *PEM_read_X509_CRL(FILE *fp, X509_CRL **x, pem_password_cb *cb, void *u); int PEM_write_bio_X509_CRL(BIO *bp, X509_CRL *x); int PEM_write_X509_CRL(FILE *fp, X509_CRL *x);
PKCS7 *PEM_read_bio_PKCS7(BIO *bp, PKCS7 **x, pem_password_cb *cb, void *u); PKCS7 *PEM_read_PKCS7(FILE *fp, PKCS7 **x, pem_password_cb *cb, void *u); int PEM_write_bio_PKCS7(BIO *bp, PKCS7 *x); int PEM_write_PKCS7(FILE *fp, PKCS7 *x);
NETSCAPE_CERT_SEQUENCE *PEM_read_bio_NETSCAPE_CERT_SEQUENCE(BIO *bp, NETSCAPE_CERT_SEQUENCE **x, pem_password_cb *cb, void *u); NETSCAPE_CERT_SEQUENCE *PEM_read_NETSCAPE_CERT_SEQUENCE(FILE *fp, NETSCAPE_CERT_SEQUENCE **x, pem_password_cb *cb, void *u); int PEM_write_bio_NETSCAPE_CERT_SEQUENCE(BIO *bp, NETSCAPE_CERT_SEQUENCE *x); int PEM_write_NETSCAPE_CERT_SEQUENCE(FILE *fp, NETSCAPE_CERT_SEQUENCE *x);
X509_SIG *PEM_read_bio_PKCS8(BIO *bp, X509_SIG **x, pem_password_cb *cb, void *u); X509_SIG *PEM_read_PKCS8(FILE *fp, X509_SIG **x, pem_password_cb *cb, void *u); int PEM_write_bio_PKCS8(BIO *bp, X509_SIG *x); int PEM_write_PKCS8(FILE *fp, X509_SIG *x);
PKCS8_PRIV_KEY_INFO *PEM_read_bio_PKCS8_PRIV_KEY_INFO(BIO *bp, PKCS8_PRIV_KEY_INFO **x, pem_password_cb *cb, void *u); PKCS8_PRIV_KEY_INFO *PEM_read_PKCS8_PRIV_KEY_INFO(FILE *fp, PKCS8_PRIV_KEY_INFO **x, pem_password_cb *cb, void *u); int PEM_write_bio_PKCS8_PRIV_KEY_INFO(BIO *bp, PKCS8_PRIV_KEY_INFO *x); int PEM_write_PKCS8_PRIV_KEY_INFO(FILE *fp, PKCS8_PRIV_KEY_INFO *x);
RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **x, pem_password_cb *cb, void *u); RSA *PEM_read_RSAPrivateKey(FILE *fp, RSA **x, pem_password_cb *cb, void *u); int PEM_write_bio_RSAPrivateKey(BIO *bp, RSA *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u); int PEM_write_RSAPrivateKey(FILE *fp, RSA *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u);
RSA *PEM_read_bio_RSAPublicKey(BIO *bp, RSA **x, pem_password_cb *cb, void *u); RSA *PEM_read_RSAPublicKey(FILE *fp, RSA **x, pem_password_cb *cb, void *u); int PEM_write_bio_RSAPublicKey(BIO *bp, const RSA *x); int PEM_write_RSAPublicKey(FILE *fp, const RSA *x);
RSA *PEM_read_bio_RSA_PUBKEY(BIO *bp, RSA **x, pem_password_cb *cb, void *u); RSA *PEM_read_RSA_PUBKEY(FILE *fp, RSA **x, pem_password_cb *cb, void *u); int PEM_write_bio_RSA_PUBKEY(BIO *bp, RSA *x); int PEM_write_RSA_PUBKEY(FILE *fp, RSA *x);
DSA *PEM_read_bio_DSAPrivateKey(BIO *bp, DSA **x, pem_password_cb *cb, void *u); DSA *PEM_read_DSAPrivateKey(FILE *fp, DSA **x, pem_password_cb *cb, void *u); int PEM_write_bio_DSAPrivateKey(BIO *bp, DSA *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u); int PEM_write_DSAPrivateKey(FILE *fp, DSA *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u);
DSA *PEM_read_bio_DSA_PUBKEY(BIO *bp, DSA **x, pem_password_cb *cb, void *u); DSA *PEM_read_DSA_PUBKEY(FILE *fp, DSA **x, pem_password_cb *cb, void *u); int PEM_write_bio_DSA_PUBKEY(BIO *bp, DSA *x); int PEM_write_DSA_PUBKEY(FILE *fp, DSA *x);
DSA *PEM_read_bio_DSAparams(BIO *bp, DSA **x, pem_password_cb *cb, void *u); DSA *PEM_read_DSAparams(FILE *fp, DSA **x, pem_password_cb *cb, void *u); int PEM_write_bio_DSAparams(BIO *bp, const DSA *x); int PEM_write_DSAparams(FILE *fp, const DSA *x);
EC_GROUP *PEM_read_bio_ECPKParameters(BIO *bp, EC_GROUP **x, pem_password_cb *cb, void *u); EC_GROUP *PEM_read_ECPKParameters(FILE *fp, EC_GROUP **x, pem_password_cb *cb, void *u); int PEM_write_bio_ECPKParameters(BIO *bp, const EC_GROUP *x); int PEM_write_ECPKParameters(FILE *fp, const EC_GROUP *x);
EC_KEY *PEM_read_bio_ECPrivateKey(BIO *bp, EC_KEY **x, pem_password_cb *cb, void *u); EC_KEY *PEM_read_ECPrivateKey(FILE *fp, EC_KEY **x, pem_password_cb *cb, void *u); int PEM_write_bio_ECPrivateKey(BIO *bp, EC_KEY *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u); int PEM_write_ECPrivateKey(FILE *fp, EC_KEY *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u);
EC_KEY *PEM_read_bio_EC_PUBKEY(BIO *bp, EC_KEY **x, pem_password_cb *cb, void *u); EC_KEY *PEM_read_EC_PUBKEY(FILE *fp, EC_KEY **x, pem_password_cb *cb, void *u); int PEM_write_bio_EC_PUBKEY(BIO *bp, EC_KEY *x); int PEM_write_EC_PUBKEY(FILE *fp, EC_KEY *x);
DH *PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u); DH *PEM_read_DHparams(FILE *fp, DH **x, pem_password_cb *cb, void *u); int PEM_write_bio_DHparams(BIO *bp, const DH *x); int PEM_write_DHparams(FILE *fp, const DH *x);
EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u); EVP_PKEY *PEM_read_PrivateKey(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u); int PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u); int PEM_write_PrivateKey(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u);
EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u); EVP_PKEY *PEM_read_PUBKEY(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u); int PEM_write_bio_PUBKEY(BIO *bp, EVP_PKEY *x); int PEM_write_PUBKEY(FILE *fp, EVP_PKEY *x);
int PEM_write_bio_PKCS8PrivateKey_nid(BIO *bp, EVP_PKEY *x, int nid,
      char *kstr, int klen,
      pem_password_cb *cb, void *u);
int PEM_write_bio_PKCS8PrivateKey(BIO *, EVP_PKEY *, const EVP_CIPHER *,
                                  char *, int, pem_password_cb *, void *);
int i2d_PKCS8PrivateKey_bio(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
      char *kstr, int klen,
      pem_password_cb *cb, void *u);
int i2d_PKCS8PrivateKey_nid_bio(BIO *bp, EVP_PKEY *x, int nid,
      char *kstr, int klen,
      pem_password_cb *cb, void *u);
EVP_PKEY *d2i_PKCS8PrivateKey_bio(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);
int i2d_PKCS8PrivateKey_fp(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc,
      char *kstr, int klen,
      pem_password_cb *cb, void *u);
int i2d_PKCS8PrivateKey_nid_fp(FILE *fp, EVP_PKEY *x, int nid,
      char *kstr, int klen,
      pem_password_cb *cb, void *u);
int PEM_write_PKCS8PrivateKey_nid(FILE *fp, EVP_PKEY *x, int nid,
      char *kstr, int klen,
      pem_password_cb *cb, void *u);
EVP_PKEY *d2i_PKCS8PrivateKey_fp(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u);
int PEM_write_PKCS8PrivateKey(FILE *fp,EVP_PKEY *x,const EVP_CIPHER *enc,
         char *kstr,int klen, pem_password_cb *cd, void *u);
EVP_PKEY *PEM_read_bio_Parameters(BIO *bp, EVP_PKEY **x);
int PEM_write_bio_Parameters(BIO *bp, EVP_PKEY *x);
EVP_PKEY *b2i_PrivateKey(const unsigned char **in, long length);
EVP_PKEY *b2i_PublicKey(const unsigned char **in, long length);
EVP_PKEY *b2i_PrivateKey_bio(BIO *in);
EVP_PKEY *b2i_PublicKey_bio(BIO *in);
int i2b_PrivateKey_bio(BIO *out, EVP_PKEY *pk);
int i2b_PublicKey_bio(BIO *out, EVP_PKEY *pk);
EVP_PKEY *b2i_PVK_bio(BIO *in, pem_password_cb *cb, void *u);
int i2b_PVK_bio(BIO *out, EVP_PKEY *pk, int enclevel,
  pem_password_cb *cb, void *u);
void ERR_load_PEM_strings(void);
]]
