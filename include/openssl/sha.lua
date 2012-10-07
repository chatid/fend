include "sys/types"
include "openssl/e_os2"

ffi.cdef [[
typedef struct SHAstate_st
 {
 unsigned int h0,h1,h2,h3,h4;
 unsigned int Nl,Nh;
 unsigned int data[16];
 unsigned int num;
 } SHA_CTX;
int SHA_Init(SHA_CTX *c);
int SHA_Update(SHA_CTX *c, const void *data, size_t len);
int SHA_Final(unsigned char *md, SHA_CTX *c);
unsigned char *SHA(const unsigned char *d, size_t n, unsigned char *md);
void SHA_Transform(SHA_CTX *c, const unsigned char *data);
int SHA1_Init(SHA_CTX *c);
int SHA1_Update(SHA_CTX *c, const void *data, size_t len);
int SHA1_Final(unsigned char *md, SHA_CTX *c);
unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);
void SHA1_Transform(SHA_CTX *c, const unsigned char *data);
typedef struct SHA256state_st
 {
 unsigned int h[8];
 unsigned int Nl,Nh;
 unsigned int data[16];
 unsigned int num,md_len;
 } SHA256_CTX;
int SHA224_Init(SHA256_CTX *c);
int SHA224_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA224_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA224(const unsigned char *d, size_t n,unsigned char *md);
int SHA256_Init(SHA256_CTX *c);
int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA256_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA256(const unsigned char *d, size_t n,unsigned char *md);
void SHA256_Transform(SHA256_CTX *c, const unsigned char *data);
typedef struct SHA512state_st
 {
 unsigned long long h[8];
 unsigned long long Nl,Nh;
 union {
  unsigned long long d[16];
  unsigned char p[(16*8)];
 } u;
 unsigned int num,md_len;
 } SHA512_CTX;
int SHA384_Init(SHA512_CTX *c);
int SHA384_Update(SHA512_CTX *c, const void *data, size_t len);
int SHA384_Final(unsigned char *md, SHA512_CTX *c);
unsigned char *SHA384(const unsigned char *d, size_t n,unsigned char *md);
int SHA512_Init(SHA512_CTX *c);
int SHA512_Update(SHA512_CTX *c, const void *data, size_t len);
int SHA512_Final(unsigned char *md, SHA512_CTX *c);
unsigned char *SHA512(const unsigned char *d, size_t n,unsigned char *md);
void SHA512_Transform(SHA512_CTX *c, const unsigned char *data);
]]
