include "openssl/evp"

ffi.cdef [[
typedef struct hmac_ctx_st
 {
 const EVP_MD *md;
 EVP_MD_CTX md_ctx;
 EVP_MD_CTX i_ctx;
 EVP_MD_CTX o_ctx;
 unsigned int key_length;
 unsigned char key[128];
 } HMAC_CTX;
void HMAC_CTX_init(HMAC_CTX *ctx);
void HMAC_CTX_cleanup(HMAC_CTX *ctx);
int HMAC_Init(HMAC_CTX *ctx, const void *key, int len,
        const EVP_MD *md);
int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len,
    const EVP_MD *md, ENGINE *impl);
int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len);
int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);
unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len,
      const unsigned char *d, size_t n, unsigned char *md,
      unsigned int *md_len);
int HMAC_CTX_copy(HMAC_CTX *dctx, HMAC_CTX *sctx);
void HMAC_CTX_set_flags(HMAC_CTX *ctx, unsigned long flags);
]]

HMAC_MAX_MD_CBLOCK = 128
