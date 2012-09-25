include "openssl/ossl_typ.h"

ffi.cdef [[
struct buf_mem_st
 {
 size_t length;
 char *data;
 size_t max;
 };
BUF_MEM *BUF_MEM_new(void);
void BUF_MEM_free(BUF_MEM *a);
int BUF_MEM_grow(BUF_MEM *str, size_t len);
int BUF_MEM_grow_clean(BUF_MEM *str, size_t len);
char * BUF_strdup(const char *str);
char * BUF_strndup(const char *str, size_t siz);
void * BUF_memdup(const void *data, size_t siz);
void BUF_reverse(unsigned char *out, unsigned char *in, size_t siz);
size_t BUF_strlcpy(char *dst,const char *src,size_t siz);
size_t BUF_strlcat(char *dst,const char *src,size_t siz);
void ERR_load_BUF_strings(void);
]]

BUF_F_BUF_MEM_GROW = 100
BUF_F_BUF_MEM_GROW_CLEAN = 105
BUF_F_BUF_MEM_NEW = 101
BUF_F_BUF_MEMDUP = 103
BUF_F_BUF_STRDUP = 102
BUF_F_BUF_STRNDUP = 104
