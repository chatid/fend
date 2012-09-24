local ffi = require "ffi"

include "openssl/crypto"

ffi.cdef[[
typedef struct comp_ctx_st COMP_CTX;
typedef struct comp_method_st
 {
 int type;
 const char *name;
 int (*init)(COMP_CTX *ctx);
 void (*finish)(COMP_CTX *ctx);
 int (*compress)(COMP_CTX *ctx,
   unsigned char *out, unsigned int olen,
   unsigned char *in, unsigned int ilen);
 int (*expand)(COMP_CTX *ctx,
        unsigned char *out, unsigned int olen,
        unsigned char *in, unsigned int ilen);
 long (*ctrl)(void);
 long (*callback_ctrl)(void);
 } COMP_METHOD;
struct comp_ctx_st
 {
 COMP_METHOD *meth;
 unsigned long compress_in;
 unsigned long compress_out;
 unsigned long expand_in;
 unsigned long expand_out;
 CRYPTO_EX_DATA ex_data;
 };
COMP_CTX *COMP_CTX_new(COMP_METHOD *meth);
void COMP_CTX_free(COMP_CTX *ctx);
int COMP_compress_block(COMP_CTX *ctx, unsigned char *out, int olen,
 unsigned char *in, int ilen);
int COMP_expand_block(COMP_CTX *ctx, unsigned char *out, int olen,
 unsigned char *in, int ilen);
COMP_METHOD *COMP_rle(void );
COMP_METHOD *COMP_zlib(void );
void COMP_zlib_cleanup(void);
void ERR_load_COMP_strings(void);
]]

module(...)

COMP_F_BIO_ZLIB_NEW = 100
COMP_F_BIO_ZLIB_READ = 101
COMP_F_BIO_ZLIB_WRITE = 102

COMP_R_ZLIB_DEFLATE_ERROR = 99
COMP_R_ZLIB_INFLATE_ERROR = 100
COMP_R_ZLIB_NOT_SUPPORTED = 101

return _M
