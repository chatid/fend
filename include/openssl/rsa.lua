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

module ( ... )

RSA_3 = 0x3
RSA_F4 = 0x10001
RSA_F_CHECK_PADDING_MD = 140
RSA_F_DO_RSA_PRINT = 146
RSA_F_INT_RSA_VERIFY = 145
RSA_F_MEMORY_LOCK = 100
RSA_F_OLD_RSA_PRIV_DECODE = 147
RSA_F_PKEY_RSA_CTRL = 143
RSA_F_PKEY_RSA_CTRL_STR = 144
RSA_F_PKEY_RSA_SIGN = 142
RSA_F_PKEY_RSA_VERIFY = 154
RSA_F_PKEY_RSA_VERIFYRECOVER = 141
RSA_F_RSA_BUILTIN_KEYGEN = 129
RSA_F_RSA_CHECK_KEY = 123
RSA_F_RSA_EAY_PRIVATE_DECRYPT = 101
RSA_F_RSA_EAY_PRIVATE_ENCRYPT = 102
RSA_F_RSA_EAY_PUBLIC_DECRYPT = 103
RSA_F_RSA_EAY_PUBLIC_ENCRYPT = 104
RSA_F_RSA_GENERATE_KEY = 105
RSA_F_RSA_GENERATE_KEY_EX = 155
RSA_F_RSA_ITEM_VERIFY = 156
RSA_F_RSA_MEMORY_LOCK = 130
RSA_F_RSA_NEW_METHOD = 106
RSA_F_RSA_NULL = 124
RSA_F_RSA_NULL_MOD_EXP = 131
RSA_F_RSA_NULL_PRIVATE_DECRYPT = 132
RSA_F_RSA_NULL_PRIVATE_ENCRYPT = 133
RSA_F_RSA_NULL_PUBLIC_DECRYPT = 134
RSA_F_RSA_NULL_PUBLIC_ENCRYPT = 135
RSA_F_RSA_PADDING_ADD_NONE = 107
RSA_F_RSA_PADDING_ADD_PKCS1_OAEP = 121
RSA_F_RSA_PADDING_ADD_PKCS1_PSS = 125
RSA_F_RSA_PADDING_ADD_PKCS1_PSS_MGF1 = 148
RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1 = 108
RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2 = 109
RSA_F_RSA_PADDING_ADD_SSLV23 = 110
RSA_F_RSA_PADDING_ADD_X931 = 127
RSA_F_RSA_PADDING_CHECK_NONE = 111
RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP = 122
RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1 = 112
RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2 = 113
RSA_F_RSA_PADDING_CHECK_SSLV23 = 114
RSA_F_RSA_PADDING_CHECK_X931 = 128
RSA_F_RSA_PRINT = 115
RSA_F_RSA_PRINT_FP = 116
RSA_F_RSA_PRIV_DECODE = 137
RSA_F_RSA_PRIV_ENCODE = 138
RSA_F_RSA_PRIVATE_DECRYPT = 150
RSA_F_RSA_PRIVATE_ENCRYPT = 151
RSA_F_RSA_PUB_DECODE = 139
RSA_F_RSA_PUBLIC_DECRYPT = 152
RSA_F_RSA_PUBLIC_ENCRYPT = 153
RSA_F_RSA_SETUP_BLINDING = 136
RSA_F_RSA_SIGN = 117
RSA_F_RSA_SIGN_ASN1_OCTET_STRING = 118
RSA_F_RSA_VERIFY = 119
RSA_F_RSA_VERIFY_ASN1_OCTET_STRING = 120
RSA_F_RSA_VERIFY_PKCS1_PSS = 126
RSA_F_RSA_VERIFY_PKCS1_PSS_MGF1 = 149
RSA_FLAG_BLINDING = 0x0008
RSA_FLAG_CACHE_PRIVATE = 0x0004
RSA_FLAG_CACHE_PUBLIC = 0x0002
RSA_FLAG_CHECKED = 0x0800
RSA_FLAG_EXT_PKEY = 0x0020
RSA_FLAG_FIPS_METHOD = 0x0400
RSA_FLAG_NO_BLINDING = 0x0080
RSA_FLAG_NO_CONSTTIME = 0x0100
RSA_FLAG_NO_EXP_CONSTTIME = RSA_FLAG_NO_CONSTTIME
RSA_FLAG_NON_FIPS_ALLOW = 0x0400
RSA_FLAG_SIGN_VER = 0x0040
RSA_FLAG_THREAD_SAFE = 0x0010
RSA_METHOD_FLAG_NO_CHECK = 0x0001
RSA_NO_PADDING = 3
RSA_PKCS1_OAEP_PADDING = 4
RSA_PKCS1_PADDING = 1
RSA_PKCS1_PADDING_SIZE = 11
RSA_PKCS1_PSS_PADDING = 6
RSA_R_ALGORITHM_MISMATCH = 100
RSA_R_BAD_E_VALUE = 101
RSA_R_BAD_FIXED_HEADER_DECRYPT = 102
RSA_R_BAD_PAD_BYTE_COUNT = 103
RSA_R_BAD_SIGNATURE = 104
RSA_R_BLOCK_TYPE_IS_NOT_01 = 106
RSA_R_BLOCK_TYPE_IS_NOT_02 = 107
RSA_R_D_E_NOT_CONGRUENT_TO_1 = 123
RSA_R_DATA_GREATER_THAN_MOD_LEN = 108
RSA_R_DATA_TOO_LARGE = 109
RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE = 110
RSA_R_DATA_TOO_LARGE_FOR_MODULUS = 132
RSA_R_DATA_TOO_SMALL = 111
RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE = 122
RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY = 112
RSA_R_DMP1_NOT_CONGRUENT_TO_D = 124
RSA_R_DMQ1_NOT_CONGRUENT_TO_D = 125
RSA_R_FIRST_OCTET_INVALID = 133
RSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE = 144
RSA_R_INVALID_DIGEST_LENGTH = 143
RSA_R_INVALID_HEADER = 137
RSA_R_INVALID_KEYBITS = 145
RSA_R_INVALID_MESSAGE_LENGTH = 131
RSA_R_INVALID_MGF1_MD = 156
RSA_R_INVALID_PADDING = 138
RSA_R_INVALID_PADDING_MODE = 141
RSA_R_INVALID_PSS_PARAMETERS = 149
RSA_R_INVALID_PSS_SALTLEN = 146
RSA_R_INVALID_SALT_LENGTH = 150
RSA_R_INVALID_TRAILER = 139
RSA_R_INVALID_X931_DIGEST = 142
RSA_R_IQMP_NOT_INVERSE_OF_Q = 126
RSA_R_KEY_SIZE_TOO_SMALL = 120
RSA_R_LAST_OCTET_INVALID = 134
RSA_R_MODULUS_TOO_LARGE = 105
RSA_R_N_DOES_NOT_EQUAL_P_Q = 127
RSA_R_NO_PUBLIC_EXPONENT = 140
RSA_R_NON_FIPS_RSA_METHOD = 157
RSA_R_NULL_BEFORE_BLOCK_MISSING = 113
RSA_R_OAEP_DECODING_ERROR = 121
RSA_R_OPERATION_NOT_ALLOWED_IN_FIPS_MODE = 158
RSA_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE = 148
RSA_R_P_NOT_PRIME = 128
RSA_R_PADDING_CHECK_FAILED = 114
RSA_R_Q_NOT_PRIME = 129
RSA_R_RSA_OPERATIONS_NOT_SUPPORTED = 130
RSA_R_SLEN_CHECK_FAILED = 136
RSA_R_SLEN_RECOVERY_FAILED = 135
RSA_R_SSLV3_ROLLBACK_ATTACK = 115
RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD = 116
RSA_R_UNKNOWN_ALGORITHM_TYPE = 117
RSA_R_UNKNOWN_MASK_DIGEST = 151
RSA_R_UNKNOWN_PADDING_TYPE = 118
RSA_R_UNKNOWN_PSS_DIGEST = 152
RSA_R_UNSUPPORTED_MASK_ALGORITHM = 153
RSA_R_UNSUPPORTED_MASK_PARAMETER = 154
RSA_R_UNSUPPORTED_SIGNATURE_TYPE = 155
RSA_R_VALUE_MISSING = 147
RSA_R_WRONG_SIGNATURE_LENGTH = 119
RSA_SSLV23_PADDING = 2
RSA_X931_PADDING = 5

return _M
