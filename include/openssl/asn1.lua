local ffi = require "ffi"

include "time"
include "openssl/e_os2"
include "openssl/bio"
include "openssl/stack"
include "openssl/safestack"
include "openssl/symhacks"
include "openssl/ossl_typ"
include "openssl/bn"

ffi.cdef [[
typedef struct asn1_ctx_st
 {
 unsigned char *p;
 int eos;
 int error;
 int inf;
 int tag;
 int xclass;
 long slen;
 unsigned char *max;
 unsigned char *q;
 unsigned char **pp;
 int line;
 } ASN1_CTX;
typedef struct asn1_const_ctx_st
 {
 const unsigned char *p;
 int eos;
 int error;
 int inf;
 int tag;
 int xclass;
 long slen;
 const unsigned char *max;
 const unsigned char *q;
 const unsigned char **pp;
 int line;
 } ASN1_const_CTX;
typedef struct asn1_object_st
 {
 const char *sn,*ln;
 int nid;
 int length;
 const unsigned char *data;
 int flags;
 } ASN1_OBJECT;
struct asn1_string_st
 {
 int length;
 int type;
 unsigned char *data;
 long flags;
 };
typedef struct ASN1_ENCODING_st
 {
 unsigned char *enc;
 long len;
 int modified;
 } ASN1_ENCODING;
typedef struct asn1_string_table_st {
 int nid;
 long minsize;
 long maxsize;
 unsigned long mask;
 unsigned long flags;
} ASN1_STRING_TABLE;
struct stack_st_ASN1_STRING_TABLE { _STACK stack; };
typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE;
typedef struct ASN1_TLC_st ASN1_TLC;
typedef struct ASN1_VALUE_st ASN1_VALUE;
typedef void *d2i_of_void(void **,const unsigned char **,long); typedef int i2d_of_void(void *,unsigned char **);
typedef const ASN1_ITEM ASN1_ITEM_EXP;
struct stack_st_ASN1_INTEGER { _STACK stack; };

struct stack_st_ASN1_GENERALSTRING { _STACK stack; };
typedef struct asn1_type_st
 {
 int type;
 union {
  char *ptr;
  ASN1_BOOLEAN boolean;
  ASN1_STRING * asn1_string;
  ASN1_OBJECT * object;
  ASN1_INTEGER * integer;
  ASN1_ENUMERATED * enumerated;
  ASN1_BIT_STRING * bit_string;
  ASN1_OCTET_STRING * octet_string;
  ASN1_PRINTABLESTRING * printablestring;
  ASN1_T61STRING * t61string;
  ASN1_IA5STRING * ia5string;
  ASN1_GENERALSTRING * generalstring;
  ASN1_BMPSTRING * bmpstring;
  ASN1_UNIVERSALSTRING * universalstring;
  ASN1_UTCTIME * utctime;
  ASN1_GENERALIZEDTIME * generalizedtime;
  ASN1_VISIBLESTRING * visiblestring;
  ASN1_UTF8STRING * utf8string;
  ASN1_STRING * set;
  ASN1_STRING * sequence;
  ASN1_VALUE * asn1_value;
  } value;
 } ASN1_TYPE;
struct stack_st_ASN1_TYPE { _STACK stack; };

typedef struct stack_st_ASN1_TYPE ASN1_SEQUENCE_ANY;
ASN1_SEQUENCE_ANY *d2i_ASN1_SEQUENCE_ANY(ASN1_SEQUENCE_ANY **a, const unsigned char **in, long len); int i2d_ASN1_SEQUENCE_ANY(const ASN1_SEQUENCE_ANY *a, unsigned char **out); extern const ASN1_ITEM ASN1_SEQUENCE_ANY_it;
ASN1_SEQUENCE_ANY *d2i_ASN1_SET_ANY(ASN1_SEQUENCE_ANY **a, const unsigned char **in, long len); int i2d_ASN1_SET_ANY(const ASN1_SEQUENCE_ANY *a, unsigned char **out); extern const ASN1_ITEM ASN1_SET_ANY_it;
typedef struct NETSCAPE_X509_st
 {
 ASN1_OCTET_STRING *header;
 X509 *cert;
 } NETSCAPE_X509;
typedef struct BIT_STRING_BITNAME_st {
 int bitnum;
 const char *lname;
 const char *sname;
} BIT_STRING_BITNAME;
ASN1_TYPE *ASN1_TYPE_new(void); void ASN1_TYPE_free(ASN1_TYPE *a); ASN1_TYPE *d2i_ASN1_TYPE(ASN1_TYPE **a, const unsigned char **in, long len); int i2d_ASN1_TYPE(ASN1_TYPE *a, unsigned char **out); extern const ASN1_ITEM ASN1_ANY_it;
int ASN1_TYPE_get(ASN1_TYPE *a);
void ASN1_TYPE_set(ASN1_TYPE *a, int type, void *value);
int ASN1_TYPE_set1(ASN1_TYPE *a, int type, const void *value);
int ASN1_TYPE_cmp(ASN1_TYPE *a, ASN1_TYPE *b);
ASN1_OBJECT * ASN1_OBJECT_new(void );
void ASN1_OBJECT_free(ASN1_OBJECT *a);
int i2d_ASN1_OBJECT(ASN1_OBJECT *a,unsigned char **pp);
ASN1_OBJECT * c2i_ASN1_OBJECT(ASN1_OBJECT **a,const unsigned char **pp,
   long length);
ASN1_OBJECT * d2i_ASN1_OBJECT(ASN1_OBJECT **a,const unsigned char **pp,
   long length);
extern const ASN1_ITEM ASN1_OBJECT_it;
struct stack_st_ASN1_OBJECT { _STACK stack; };

ASN1_STRING * ASN1_STRING_new(void);
void ASN1_STRING_free(ASN1_STRING *a);
int ASN1_STRING_copy(ASN1_STRING *dst, const ASN1_STRING *str);
ASN1_STRING * ASN1_STRING_dup(const ASN1_STRING *a);
ASN1_STRING * ASN1_STRING_type_new(int type );
int ASN1_STRING_cmp(const ASN1_STRING *a, const ASN1_STRING *b);
int ASN1_STRING_set(ASN1_STRING *str, const void *data, int len);
void ASN1_STRING_set0(ASN1_STRING *str, void *data, int len);
int ASN1_STRING_length(const ASN1_STRING *x);
void ASN1_STRING_length_set(ASN1_STRING *x, int n);
int ASN1_STRING_type(ASN1_STRING *x);
unsigned char * ASN1_STRING_data(ASN1_STRING *x);
ASN1_BIT_STRING *ASN1_BIT_STRING_new(void); void ASN1_BIT_STRING_free(ASN1_BIT_STRING *a); ASN1_BIT_STRING *d2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a, const unsigned char **in, long len); int i2d_ASN1_BIT_STRING(ASN1_BIT_STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_BIT_STRING_it;
int i2c_ASN1_BIT_STRING(ASN1_BIT_STRING *a,unsigned char **pp);
ASN1_BIT_STRING *c2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a,const unsigned char **pp,
   long length);
int ASN1_BIT_STRING_set(ASN1_BIT_STRING *a, unsigned char *d,
   int length );
int ASN1_BIT_STRING_set_bit(ASN1_BIT_STRING *a, int n, int value);
int ASN1_BIT_STRING_get_bit(ASN1_BIT_STRING *a, int n);
int ASN1_BIT_STRING_check(ASN1_BIT_STRING *a,
                                     unsigned char *flags, int flags_len);
int ASN1_BIT_STRING_name_print(BIO *out, ASN1_BIT_STRING *bs,
    BIT_STRING_BITNAME *tbl, int indent);
int ASN1_BIT_STRING_num_asc(char *name, BIT_STRING_BITNAME *tbl);
int ASN1_BIT_STRING_set_asc(ASN1_BIT_STRING *bs, char *name, int value,
    BIT_STRING_BITNAME *tbl);
int i2d_ASN1_BOOLEAN(int a,unsigned char **pp);
int d2i_ASN1_BOOLEAN(int *a,const unsigned char **pp,long length);
ASN1_INTEGER *ASN1_INTEGER_new(void); void ASN1_INTEGER_free(ASN1_INTEGER *a); ASN1_INTEGER *d2i_ASN1_INTEGER(ASN1_INTEGER **a, const unsigned char **in, long len); int i2d_ASN1_INTEGER(ASN1_INTEGER *a, unsigned char **out); extern const ASN1_ITEM ASN1_INTEGER_it;
int i2c_ASN1_INTEGER(ASN1_INTEGER *a,unsigned char **pp);
ASN1_INTEGER *c2i_ASN1_INTEGER(ASN1_INTEGER **a,const unsigned char **pp,
   long length);
ASN1_INTEGER *d2i_ASN1_UINTEGER(ASN1_INTEGER **a,const unsigned char **pp,
   long length);
ASN1_INTEGER * ASN1_INTEGER_dup(const ASN1_INTEGER *x);
int ASN1_INTEGER_cmp(const ASN1_INTEGER *x, const ASN1_INTEGER *y);
ASN1_ENUMERATED *ASN1_ENUMERATED_new(void); void ASN1_ENUMERATED_free(ASN1_ENUMERATED *a); ASN1_ENUMERATED *d2i_ASN1_ENUMERATED(ASN1_ENUMERATED **a, const unsigned char **in, long len); int i2d_ASN1_ENUMERATED(ASN1_ENUMERATED *a, unsigned char **out); extern const ASN1_ITEM ASN1_ENUMERATED_it;
int ASN1_UTCTIME_check(ASN1_UTCTIME *a);
ASN1_UTCTIME *ASN1_UTCTIME_set(ASN1_UTCTIME *s,time_t t);
ASN1_UTCTIME *ASN1_UTCTIME_adj(ASN1_UTCTIME *s, time_t t,
    int offset_day, long offset_sec);
int ASN1_UTCTIME_set_string(ASN1_UTCTIME *s, const char *str);
int ASN1_UTCTIME_cmp_time_t(const ASN1_UTCTIME *s, time_t t);
int ASN1_GENERALIZEDTIME_check(ASN1_GENERALIZEDTIME *a);
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_set(ASN1_GENERALIZEDTIME *s,time_t t);
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_adj(ASN1_GENERALIZEDTIME *s,
      time_t t, int offset_day, long offset_sec);
int ASN1_GENERALIZEDTIME_set_string(ASN1_GENERALIZEDTIME *s, const char *str);
ASN1_OCTET_STRING *ASN1_OCTET_STRING_new(void); void ASN1_OCTET_STRING_free(ASN1_OCTET_STRING *a); ASN1_OCTET_STRING *d2i_ASN1_OCTET_STRING(ASN1_OCTET_STRING **a, const unsigned char **in, long len); int i2d_ASN1_OCTET_STRING(ASN1_OCTET_STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_OCTET_STRING_it;
ASN1_OCTET_STRING * ASN1_OCTET_STRING_dup(const ASN1_OCTET_STRING *a);
int ASN1_OCTET_STRING_cmp(const ASN1_OCTET_STRING *a, const ASN1_OCTET_STRING *b);
int ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *str, const unsigned char *data, int len);
ASN1_VISIBLESTRING *ASN1_VISIBLESTRING_new(void); void ASN1_VISIBLESTRING_free(ASN1_VISIBLESTRING *a); ASN1_VISIBLESTRING *d2i_ASN1_VISIBLESTRING(ASN1_VISIBLESTRING **a, const unsigned char **in, long len); int i2d_ASN1_VISIBLESTRING(ASN1_VISIBLESTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_VISIBLESTRING_it;
ASN1_UNIVERSALSTRING *ASN1_UNIVERSALSTRING_new(void); void ASN1_UNIVERSALSTRING_free(ASN1_UNIVERSALSTRING *a); ASN1_UNIVERSALSTRING *d2i_ASN1_UNIVERSALSTRING(ASN1_UNIVERSALSTRING **a, const unsigned char **in, long len); int i2d_ASN1_UNIVERSALSTRING(ASN1_UNIVERSALSTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_UNIVERSALSTRING_it;
ASN1_UTF8STRING *ASN1_UTF8STRING_new(void); void ASN1_UTF8STRING_free(ASN1_UTF8STRING *a); ASN1_UTF8STRING *d2i_ASN1_UTF8STRING(ASN1_UTF8STRING **a, const unsigned char **in, long len); int i2d_ASN1_UTF8STRING(ASN1_UTF8STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_UTF8STRING_it;
ASN1_NULL *ASN1_NULL_new(void); void ASN1_NULL_free(ASN1_NULL *a); ASN1_NULL *d2i_ASN1_NULL(ASN1_NULL **a, const unsigned char **in, long len); int i2d_ASN1_NULL(ASN1_NULL *a, unsigned char **out); extern const ASN1_ITEM ASN1_NULL_it;
ASN1_BMPSTRING *ASN1_BMPSTRING_new(void); void ASN1_BMPSTRING_free(ASN1_BMPSTRING *a); ASN1_BMPSTRING *d2i_ASN1_BMPSTRING(ASN1_BMPSTRING **a, const unsigned char **in, long len); int i2d_ASN1_BMPSTRING(ASN1_BMPSTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_BMPSTRING_it;
int UTF8_getc(const unsigned char *str, int len, unsigned long *val);
int UTF8_putc(unsigned char *str, int len, unsigned long value);
ASN1_STRING *ASN1_PRINTABLE_new(void); void ASN1_PRINTABLE_free(ASN1_STRING *a); ASN1_STRING *d2i_ASN1_PRINTABLE(ASN1_STRING **a, const unsigned char **in, long len); int i2d_ASN1_PRINTABLE(ASN1_STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_PRINTABLE_it;
ASN1_STRING *DIRECTORYSTRING_new(void); void DIRECTORYSTRING_free(ASN1_STRING *a); ASN1_STRING *d2i_DIRECTORYSTRING(ASN1_STRING **a, const unsigned char **in, long len); int i2d_DIRECTORYSTRING(ASN1_STRING *a, unsigned char **out); extern const ASN1_ITEM DIRECTORYSTRING_it;
ASN1_STRING *DISPLAYTEXT_new(void); void DISPLAYTEXT_free(ASN1_STRING *a); ASN1_STRING *d2i_DISPLAYTEXT(ASN1_STRING **a, const unsigned char **in, long len); int i2d_DISPLAYTEXT(ASN1_STRING *a, unsigned char **out); extern const ASN1_ITEM DISPLAYTEXT_it;
ASN1_PRINTABLESTRING *ASN1_PRINTABLESTRING_new(void); void ASN1_PRINTABLESTRING_free(ASN1_PRINTABLESTRING *a); ASN1_PRINTABLESTRING *d2i_ASN1_PRINTABLESTRING(ASN1_PRINTABLESTRING **a, const unsigned char **in, long len); int i2d_ASN1_PRINTABLESTRING(ASN1_PRINTABLESTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_PRINTABLESTRING_it;
ASN1_T61STRING *ASN1_T61STRING_new(void); void ASN1_T61STRING_free(ASN1_T61STRING *a); ASN1_T61STRING *d2i_ASN1_T61STRING(ASN1_T61STRING **a, const unsigned char **in, long len); int i2d_ASN1_T61STRING(ASN1_T61STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_T61STRING_it;
ASN1_IA5STRING *ASN1_IA5STRING_new(void); void ASN1_IA5STRING_free(ASN1_IA5STRING *a); ASN1_IA5STRING *d2i_ASN1_IA5STRING(ASN1_IA5STRING **a, const unsigned char **in, long len); int i2d_ASN1_IA5STRING(ASN1_IA5STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_IA5STRING_it;
ASN1_GENERALSTRING *ASN1_GENERALSTRING_new(void); void ASN1_GENERALSTRING_free(ASN1_GENERALSTRING *a); ASN1_GENERALSTRING *d2i_ASN1_GENERALSTRING(ASN1_GENERALSTRING **a, const unsigned char **in, long len); int i2d_ASN1_GENERALSTRING(ASN1_GENERALSTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_GENERALSTRING_it;
ASN1_UTCTIME *ASN1_UTCTIME_new(void); void ASN1_UTCTIME_free(ASN1_UTCTIME *a); ASN1_UTCTIME *d2i_ASN1_UTCTIME(ASN1_UTCTIME **a, const unsigned char **in, long len); int i2d_ASN1_UTCTIME(ASN1_UTCTIME *a, unsigned char **out); extern const ASN1_ITEM ASN1_UTCTIME_it;
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_new(void); void ASN1_GENERALIZEDTIME_free(ASN1_GENERALIZEDTIME *a); ASN1_GENERALIZEDTIME *d2i_ASN1_GENERALIZEDTIME(ASN1_GENERALIZEDTIME **a, const unsigned char **in, long len); int i2d_ASN1_GENERALIZEDTIME(ASN1_GENERALIZEDTIME *a, unsigned char **out); extern const ASN1_ITEM ASN1_GENERALIZEDTIME_it;
ASN1_TIME *ASN1_TIME_new(void); void ASN1_TIME_free(ASN1_TIME *a); ASN1_TIME *d2i_ASN1_TIME(ASN1_TIME **a, const unsigned char **in, long len); int i2d_ASN1_TIME(ASN1_TIME *a, unsigned char **out); extern const ASN1_ITEM ASN1_TIME_it;
extern const ASN1_ITEM ASN1_OCTET_STRING_NDEF_it;
ASN1_TIME *ASN1_TIME_set(ASN1_TIME *s,time_t t);
ASN1_TIME *ASN1_TIME_adj(ASN1_TIME *s,time_t t,
    int offset_day, long offset_sec);
int ASN1_TIME_check(ASN1_TIME *t);
ASN1_GENERALIZEDTIME *ASN1_TIME_to_generalizedtime(ASN1_TIME *t, ASN1_GENERALIZEDTIME **out);
int ASN1_TIME_set_string(ASN1_TIME *s, const char *str);
int i2d_ASN1_SET(struct stack_st_OPENSSL_BLOCK *a, unsigned char **pp,
   i2d_of_void *i2d, int ex_tag, int ex_class,
   int is_set);
struct stack_st_OPENSSL_BLOCK *d2i_ASN1_SET(struct stack_st_OPENSSL_BLOCK **a,
         const unsigned char **pp,
         long length, d2i_of_void *d2i,
         void (*free_func)(OPENSSL_BLOCK), int ex_tag,
         int ex_class);
int i2a_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *a);
int a2i_ASN1_INTEGER(BIO *bp,ASN1_INTEGER *bs,char *buf,int size);
int i2a_ASN1_ENUMERATED(BIO *bp, ASN1_ENUMERATED *a);
int a2i_ASN1_ENUMERATED(BIO *bp,ASN1_ENUMERATED *bs,char *buf,int size);
int i2a_ASN1_OBJECT(BIO *bp,ASN1_OBJECT *a);
int a2i_ASN1_STRING(BIO *bp,ASN1_STRING *bs,char *buf,int size);
int i2a_ASN1_STRING(BIO *bp, ASN1_STRING *a, int type);
int i2t_ASN1_OBJECT(char *buf,int buf_len,ASN1_OBJECT *a);
int a2d_ASN1_OBJECT(unsigned char *out,int olen, const char *buf, int num);
ASN1_OBJECT *ASN1_OBJECT_create(int nid, unsigned char *data,int len,
 const char *sn, const char *ln);
int ASN1_INTEGER_set(ASN1_INTEGER *a, long v);
long ASN1_INTEGER_get(const ASN1_INTEGER *a);
ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai);
BIGNUM *ASN1_INTEGER_to_BN(const ASN1_INTEGER *ai,BIGNUM *bn);
int ASN1_ENUMERATED_set(ASN1_ENUMERATED *a, long v);
long ASN1_ENUMERATED_get(ASN1_ENUMERATED *a);
ASN1_ENUMERATED *BN_to_ASN1_ENUMERATED(BIGNUM *bn, ASN1_ENUMERATED *ai);
BIGNUM *ASN1_ENUMERATED_to_BN(ASN1_ENUMERATED *ai,BIGNUM *bn);
int ASN1_PRINTABLE_type(const unsigned char *s, int max);
int i2d_ASN1_bytes(ASN1_STRING *a, unsigned char **pp, int tag, int xclass);
ASN1_STRING *d2i_ASN1_bytes(ASN1_STRING **a, const unsigned char **pp,
 long length, int Ptag, int Pclass);
unsigned long ASN1_tag2bit(int tag);
ASN1_STRING *d2i_ASN1_type_bytes(ASN1_STRING **a,const unsigned char **pp,
  long length,int type);
int asn1_Finish(ASN1_CTX *c);
int asn1_const_Finish(ASN1_const_CTX *c);
int ASN1_get_object(const unsigned char **pp, long *plength, int *ptag,
 int *pclass, long omax);
int ASN1_check_infinite_end(unsigned char **p,long len);
int ASN1_const_check_infinite_end(const unsigned char **p,long len);
void ASN1_put_object(unsigned char **pp, int constructed, int length,
 int tag, int xclass);
int ASN1_put_eoc(unsigned char **pp);
int ASN1_object_size(int constructed, int length, int tag);
void *ASN1_dup(i2d_of_void *i2d, d2i_of_void *d2i, void *x);
void *ASN1_item_dup(const ASN1_ITEM *it, void *x);
void *ASN1_d2i_fp(void *(*xnew)(void), d2i_of_void *d2i, FILE *in, void **x);
void *ASN1_item_d2i_fp(const ASN1_ITEM *it, FILE *in, void *x);
int ASN1_i2d_fp(i2d_of_void *i2d,FILE *out,void *x);
int ASN1_item_i2d_fp(const ASN1_ITEM *it, FILE *out, void *x);
int ASN1_STRING_print_ex_fp(FILE *fp, ASN1_STRING *str, unsigned long flags);
int ASN1_STRING_to_UTF8(unsigned char **out, ASN1_STRING *in);
void *ASN1_d2i_bio(void *(*xnew)(void), d2i_of_void *d2i, BIO *in, void **x);
void *ASN1_item_d2i_bio(const ASN1_ITEM *it, BIO *in, void *x);
int ASN1_i2d_bio(i2d_of_void *i2d,BIO *out, unsigned char *x);
int ASN1_item_i2d_bio(const ASN1_ITEM *it, BIO *out, void *x);
int ASN1_UTCTIME_print(BIO *fp, const ASN1_UTCTIME *a);
int ASN1_GENERALIZEDTIME_print(BIO *fp, const ASN1_GENERALIZEDTIME *a);
int ASN1_TIME_print(BIO *fp, const ASN1_TIME *a);
int ASN1_STRING_print(BIO *bp, const ASN1_STRING *v);
int ASN1_STRING_print_ex(BIO *out, ASN1_STRING *str, unsigned long flags);
int ASN1_bn_print(BIO *bp, const char *number, const BIGNUM *num,
    unsigned char *buf, int off);
int ASN1_parse(BIO *bp,const unsigned char *pp,long len,int indent);
int ASN1_parse_dump(BIO *bp,const unsigned char *pp,long len,int indent,int dump);
const char *ASN1_tag2str(int tag);
NETSCAPE_X509 *NETSCAPE_X509_new(void); void NETSCAPE_X509_free(NETSCAPE_X509 *a); NETSCAPE_X509 *d2i_NETSCAPE_X509(NETSCAPE_X509 **a, const unsigned char **in, long len); int i2d_NETSCAPE_X509(NETSCAPE_X509 *a, unsigned char **out); extern const ASN1_ITEM NETSCAPE_X509_it;
int ASN1_UNIVERSALSTRING_to_string(ASN1_UNIVERSALSTRING *s);
int ASN1_TYPE_set_octetstring(ASN1_TYPE *a,
 unsigned char *data, int len);
int ASN1_TYPE_get_octetstring(ASN1_TYPE *a,
 unsigned char *data, int max_len);
int ASN1_TYPE_set_int_octetstring(ASN1_TYPE *a, long num,
 unsigned char *data, int len);
int ASN1_TYPE_get_int_octetstring(ASN1_TYPE *a,long *num,
 unsigned char *data, int max_len);
struct stack_st_OPENSSL_BLOCK *ASN1_seq_unpack(const unsigned char *buf, int len,
     d2i_of_void *d2i, void (*free_func)(OPENSSL_BLOCK));
unsigned char *ASN1_seq_pack(struct stack_st_OPENSSL_BLOCK *safes, i2d_of_void *i2d,
        unsigned char **buf, int *len );
void *ASN1_unpack_string(ASN1_STRING *oct, d2i_of_void *d2i);
void *ASN1_item_unpack(ASN1_STRING *oct, const ASN1_ITEM *it);
ASN1_STRING *ASN1_pack_string(void *obj, i2d_of_void *i2d,
         ASN1_OCTET_STRING **oct);
ASN1_STRING *ASN1_item_pack(void *obj, const ASN1_ITEM *it, ASN1_OCTET_STRING **oct);
void ASN1_STRING_set_default_mask(unsigned long mask);
int ASN1_STRING_set_default_mask_asc(const char *p);
unsigned long ASN1_STRING_get_default_mask(void);
int ASN1_mbstring_copy(ASN1_STRING **out, const unsigned char *in, int len,
     int inform, unsigned long mask);
int ASN1_mbstring_ncopy(ASN1_STRING **out, const unsigned char *in, int len,
     int inform, unsigned long mask,
     long minsize, long maxsize);
ASN1_STRING *ASN1_STRING_set_by_NID(ASN1_STRING **out,
  const unsigned char *in, int inlen, int inform, int nid);
ASN1_STRING_TABLE *ASN1_STRING_TABLE_get(int nid);
int ASN1_STRING_TABLE_add(int, long, long, unsigned long, unsigned long);
void ASN1_STRING_TABLE_cleanup(void);
ASN1_VALUE *ASN1_item_new(const ASN1_ITEM *it);
void ASN1_item_free(ASN1_VALUE *val, const ASN1_ITEM *it);
ASN1_VALUE * ASN1_item_d2i(ASN1_VALUE **val, const unsigned char **in, long len, const ASN1_ITEM *it);
int ASN1_item_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it);
int ASN1_item_ndef_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it);
void ASN1_add_oid_module(void);
ASN1_TYPE *ASN1_generate_nconf(char *str, CONF *nconf);
ASN1_TYPE *ASN1_generate_v3(char *str, X509V3_CTX *cnf);
int ASN1_item_print(BIO *out, ASN1_VALUE *ifld, int indent,
    const ASN1_ITEM *it, const ASN1_PCTX *pctx);
ASN1_PCTX *ASN1_PCTX_new(void);
void ASN1_PCTX_free(ASN1_PCTX *p);
unsigned long ASN1_PCTX_get_flags(ASN1_PCTX *p);
void ASN1_PCTX_set_flags(ASN1_PCTX *p, unsigned long flags);
unsigned long ASN1_PCTX_get_nm_flags(ASN1_PCTX *p);
void ASN1_PCTX_set_nm_flags(ASN1_PCTX *p, unsigned long flags);
unsigned long ASN1_PCTX_get_cert_flags(ASN1_PCTX *p);
void ASN1_PCTX_set_cert_flags(ASN1_PCTX *p, unsigned long flags);
unsigned long ASN1_PCTX_get_oid_flags(ASN1_PCTX *p);
void ASN1_PCTX_set_oid_flags(ASN1_PCTX *p, unsigned long flags);
unsigned long ASN1_PCTX_get_str_flags(ASN1_PCTX *p);
void ASN1_PCTX_set_str_flags(ASN1_PCTX *p, unsigned long flags);
BIO_METHOD *BIO_f_asn1(void);
BIO *BIO_new_NDEF(BIO *out, ASN1_VALUE *val, const ASN1_ITEM *it);
int i2d_ASN1_bio_stream(BIO *out, ASN1_VALUE *val, BIO *in, int flags,
    const ASN1_ITEM *it);
int PEM_write_bio_ASN1_stream(BIO *out, ASN1_VALUE *val, BIO *in, int flags,
    const char *hdr,
    const ASN1_ITEM *it);
int SMIME_write_ASN1(BIO *bio, ASN1_VALUE *val, BIO *data, int flags,
    int ctype_nid, int econt_nid,
    struct stack_st_X509_ALGOR *mdalgs,
    const ASN1_ITEM *it);
ASN1_VALUE *SMIME_read_ASN1(BIO *bio, BIO **bcont, const ASN1_ITEM *it);
int SMIME_crlf_copy(BIO *in, BIO *out, int flags);
int SMIME_text(BIO *in, BIO *out);
void ERR_load_ASN1_strings(void);
]]

module ( ... )

ASN1_F_A2D_ASN1_OBJECT = 100
ASN1_F_A2I_ASN1_ENUMERATED = 101
ASN1_F_A2I_ASN1_INTEGER = 102
ASN1_F_A2I_ASN1_STRING = 103
ASN1_F_APPEND_EXP = 176
ASN1_F_ASN1_BIT_STRING_SET_BIT = 183
ASN1_F_ASN1_CB = 177
ASN1_F_ASN1_CHECK_TLEN = 104
ASN1_F_ASN1_COLLATE_PRIMITIVE = 105
ASN1_F_ASN1_COLLECT = 106
ASN1_F_ASN1_D2I_EX_PRIMITIVE = 108
ASN1_F_ASN1_D2I_FP = 109
ASN1_F_ASN1_D2I_READ_BIO = 107
ASN1_F_ASN1_DIGEST = 184
ASN1_F_ASN1_DO_ADB = 110
ASN1_F_ASN1_DUP = 111
ASN1_F_ASN1_ENUMERATED_SET = 112
ASN1_F_ASN1_ENUMERATED_TO_BN = 113
ASN1_F_ASN1_EX_C2I = 204
ASN1_F_ASN1_FIND_END = 190
ASN1_F_ASN1_GENERALIZEDTIME_ADJ = 216
ASN1_F_ASN1_GENERALIZEDTIME_SET = 185
ASN1_F_ASN1_GENERATE_V3 = 178
ASN1_F_ASN1_GET_OBJECT = 114
ASN1_F_ASN1_HEADER_NEW = 115
ASN1_F_ASN1_I2D_BIO = 116
ASN1_F_ASN1_I2D_FP = 117
ASN1_F_ASN1_INTEGER_SET = 118
ASN1_F_ASN1_INTEGER_TO_BN = 119
ASN1_F_ASN1_ITEM_D2I_FP = 206
ASN1_F_ASN1_ITEM_DUP = 191
ASN1_F_ASN1_ITEM_EX_COMBINE_NEW = 121
ASN1_F_ASN1_ITEM_EX_D2I = 120
ASN1_F_ASN1_ITEM_I2D_BIO = 192
ASN1_F_ASN1_ITEM_I2D_FP = 193
ASN1_F_ASN1_ITEM_PACK = 198
ASN1_F_ASN1_ITEM_SIGN = 195
ASN1_F_ASN1_ITEM_SIGN_CTX = 220
ASN1_F_ASN1_ITEM_UNPACK = 199
ASN1_F_ASN1_ITEM_VERIFY = 197
ASN1_F_ASN1_MBSTRING_NCOPY = 122
ASN1_F_ASN1_OBJECT_NEW = 123
ASN1_F_ASN1_OUTPUT_DATA = 214
ASN1_F_ASN1_PACK_STRING = 124
ASN1_F_ASN1_PCTX_NEW = 205
ASN1_F_ASN1_PKCS5_PBE_SET = 125
ASN1_F_ASN1_SEQ_PACK = 126
ASN1_F_ASN1_SEQ_UNPACK = 127
ASN1_F_ASN1_SIGN = 128
ASN1_F_ASN1_STR2TYPE = 179
ASN1_F_ASN1_STRING_SET = 186
ASN1_F_ASN1_STRING_TABLE_ADD = 129
ASN1_F_ASN1_STRING_TYPE_NEW = 130
ASN1_F_ASN1_TEMPLATE_EX_D2I = 132
ASN1_F_ASN1_TEMPLATE_NEW = 133
ASN1_F_ASN1_TEMPLATE_NOEXP_D2I = 131
ASN1_F_ASN1_TIME_ADJ = 217
ASN1_F_ASN1_TIME_SET = 175
ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING = 134
ASN1_F_ASN1_TYPE_GET_OCTETSTRING = 135
ASN1_F_ASN1_UNPACK_STRING = 136
ASN1_F_ASN1_UTCTIME_ADJ = 218
ASN1_F_ASN1_UTCTIME_SET = 187
ASN1_F_ASN1_VERIFY = 137
ASN1_F_B64_READ_ASN1 = 209
ASN1_F_B64_WRITE_ASN1 = 210
ASN1_F_BIO_NEW_NDEF = 208
ASN1_F_BITSTR_CB = 180
ASN1_F_BN_TO_ASN1_ENUMERATED = 138
ASN1_F_BN_TO_ASN1_INTEGER = 139
ASN1_F_C2I_ASN1_BIT_STRING = 189
ASN1_F_C2I_ASN1_INTEGER = 194
ASN1_F_C2I_ASN1_OBJECT = 196
ASN1_F_COLLECT_DATA = 140
ASN1_F_D2I_ASN1_BIT_STRING = 141
ASN1_F_D2I_ASN1_BOOLEAN = 142
ASN1_F_D2I_ASN1_BYTES = 143
ASN1_F_D2I_ASN1_GENERALIZEDTIME = 144
ASN1_F_D2I_ASN1_HEADER = 145
ASN1_F_D2I_ASN1_INTEGER = 146
ASN1_F_D2I_ASN1_OBJECT = 147
ASN1_F_D2I_ASN1_SET = 148
ASN1_F_D2I_ASN1_TYPE_BYTES = 149
ASN1_F_D2I_ASN1_UINTEGER = 150
ASN1_F_D2I_ASN1_UTCTIME = 151
ASN1_F_D2I_AUTOPRIVATEKEY = 207
ASN1_F_D2I_NETSCAPE_RSA = 152
ASN1_F_D2I_NETSCAPE_RSA_2 = 153
ASN1_F_D2I_PRIVATEKEY = 154
ASN1_F_D2I_PUBLICKEY = 155
ASN1_F_D2I_RSA_NET = 200
ASN1_F_D2I_RSA_NET_2 = 201
ASN1_F_D2I_X509 = 156
ASN1_F_D2I_X509_CINF = 157
ASN1_F_D2I_X509_PKEY = 159
ASN1_F_I2D_ASN1_BIO_STREAM = 211
ASN1_F_I2D_ASN1_SET = 188
ASN1_F_I2D_ASN1_TIME = 160
ASN1_F_I2D_DSA_PUBKEY = 161
ASN1_F_I2D_EC_PUBKEY = 181
ASN1_F_I2D_PRIVATEKEY = 163
ASN1_F_I2D_PUBLICKEY = 164
ASN1_F_I2D_RSA_NET = 162
ASN1_F_I2D_RSA_PUBKEY = 165
ASN1_F_LONG_C2I = 166
ASN1_F_OID_MODULE_INIT = 174
ASN1_F_PARSE_TAGGING = 182
ASN1_F_PKCS5_PBE2_SET_IV = 167
ASN1_F_PKCS5_PBE_SET = 202
ASN1_F_PKCS5_PBE_SET0_ALGOR = 215
ASN1_F_PKCS5_PBKDF2_SET = 219
ASN1_F_SMIME_READ_ASN1 = 212
ASN1_F_SMIME_TEXT = 213
ASN1_F_X509_CINF_NEW = 168
ASN1_F_X509_CRL_ADD0_REVOKED = 169
ASN1_F_X509_INFO_NEW = 170
ASN1_F_X509_NAME_ENCODE = 203
ASN1_F_X509_NAME_EX_D2I = 158
ASN1_F_X509_NAME_EX_NEW = 171
ASN1_F_X509_NEW = 172
ASN1_F_X509_PKEY_NEW = 173
ASN1_LONG_UNDEF = 0x7fffffff
ASN1_OBJECT_FLAG_CRITICAL = 0x02
ASN1_OBJECT_FLAG_DYNAMIC = 0x01
ASN1_OBJECT_FLAG_DYNAMIC_DATA = 0x08
ASN1_OBJECT_FLAG_DYNAMIC_STRINGS = 0x04
ASN1_PCTX_FLAGS_NO_ANY_TYPE = 0x010
ASN1_PCTX_FLAGS_NO_FIELD_NAME = 0x040
ASN1_PCTX_FLAGS_NO_MSTRING_TYPE = 0x020
ASN1_PCTX_FLAGS_NO_STRUCT_NAME = 0x100
ASN1_PCTX_FLAGS_SHOW_ABSENT = 0x001
ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME = 0x080
ASN1_PCTX_FLAGS_SHOW_SEQUENCE = 0x002
ASN1_PCTX_FLAGS_SHOW_SSOF = 0x004
ASN1_PCTX_FLAGS_SHOW_TYPE = 0x008
ASN1_PKEY_ALIAS = 0x1
ASN1_PKEY_CTRL_CMS_ENVELOPE = 0x7
ASN1_PKEY_CTRL_CMS_SIGN = 0x5
ASN1_PKEY_CTRL_DEFAULT_MD_NID = 0x3
ASN1_PKEY_CTRL_PKCS7_ENCRYPT = 0x2
ASN1_PKEY_CTRL_PKCS7_SIGN = 0x1
ASN1_PKEY_DYNAMIC = 0x2
ASN1_PKEY_SIGPARAM_NULL = 0x4
ASN1_R_ADDING_OBJECT = 171
ASN1_R_ASN1_PARSE_ERROR = 203
ASN1_R_ASN1_SIG_PARSE_ERROR = 204
ASN1_R_AUX_ERROR = 100
ASN1_R_BAD_CLASS = 101
ASN1_R_BAD_OBJECT_HEADER = 102
ASN1_R_BAD_PASSWORD_READ = 103
ASN1_R_BAD_TAG = 104
ASN1_R_BMPSTRING_IS_WRONG_LENGTH = 214
ASN1_R_BN_LIB = 105
ASN1_R_BOOLEAN_IS_WRONG_LENGTH = 106
ASN1_R_BUFFER_TOO_SMALL = 107
ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER = 108
ASN1_R_CONTEXT_NOT_INITIALISED = 217
ASN1_R_DATA_IS_WRONG = 109
ASN1_R_DECODE_ERROR = 110
ASN1_R_DECODING_ERROR = 111
ASN1_R_DEPTH_EXCEEDED = 174
ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED = 198
ASN1_R_ENCODE_ERROR = 112
ASN1_R_ERROR_GETTING_TIME = 173
ASN1_R_ERROR_LOADING_SECTION = 172
ASN1_R_ERROR_PARSING_SET_ELEMENT = 113
ASN1_R_ERROR_SETTING_CIPHER_PARAMS = 114
ASN1_R_EXPECTING_A_BOOLEAN = 117
ASN1_R_EXPECTING_A_TIME = 118
ASN1_R_EXPECTING_AN_INTEGER = 115
ASN1_R_EXPECTING_AN_OBJECT = 116
ASN1_R_EXPLICIT_LENGTH_MISMATCH = 119
ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED = 120
ASN1_R_FIELD_MISSING = 121
ASN1_R_FIRST_NUM_TOO_LARGE = 122
ASN1_R_HEADER_TOO_LONG = 123
ASN1_R_ILLEGAL_BITSTRING_FORMAT = 175
ASN1_R_ILLEGAL_BOOLEAN = 176
ASN1_R_ILLEGAL_CHARACTERS = 124
ASN1_R_ILLEGAL_FORMAT = 177
ASN1_R_ILLEGAL_HEX = 178
ASN1_R_ILLEGAL_IMPLICIT_TAG = 179
ASN1_R_ILLEGAL_INTEGER = 180
ASN1_R_ILLEGAL_NESTED_TAGGING = 181
ASN1_R_ILLEGAL_NULL = 125
ASN1_R_ILLEGAL_NULL_VALUE = 182
ASN1_R_ILLEGAL_OBJECT = 183
ASN1_R_ILLEGAL_OPTIONAL_ANY = 126
ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE = 170
ASN1_R_ILLEGAL_TAGGED_ANY = 127
ASN1_R_ILLEGAL_TIME_VALUE = 184
ASN1_R_INTEGER_NOT_ASCII_FORMAT = 185
ASN1_R_INTEGER_TOO_LARGE_FOR_LONG = 128
ASN1_R_INVALID_BMPSTRING_LENGTH = 129
ASN1_R_INVALID_DIGIT = 130
ASN1_R_INVALID_MIME_TYPE = 205
ASN1_R_INVALID_MODIFIER = 186
ASN1_R_INVALID_NUMBER = 187
ASN1_R_INVALID_OBJECT_ENCODING = 216
ASN1_R_INVALID_SEPARATOR = 131
ASN1_R_INVALID_TIME_FORMAT = 132
ASN1_R_INVALID_UNIVERSALSTRING_LENGTH = 133
ASN1_R_INVALID_UTF8STRING = 134
ASN1_R_IV_TOO_LARGE = 135
ASN1_R_LENGTH_ERROR = 136
ASN1_R_LIST_ERROR = 188
ASN1_R_MIME_NO_CONTENT_TYPE = 206
ASN1_R_MIME_PARSE_ERROR = 207
ASN1_R_MIME_SIG_PARSE_ERROR = 208
ASN1_R_MISSING_EOC = 137
ASN1_R_MISSING_SECOND_NUMBER = 138
ASN1_R_MISSING_VALUE = 189
ASN1_R_MSTRING_NOT_UNIVERSAL = 139
ASN1_R_MSTRING_WRONG_TAG = 140
ASN1_R_NESTED_ASN1_STRING = 197
ASN1_R_NO_CONTENT_TYPE = 209
ASN1_R_NO_DEFAULT_DIGEST = 201
ASN1_R_NO_MATCHING_CHOICE_TYPE = 143
ASN1_R_NO_MULTIPART_BODY_FAILURE = 210
ASN1_R_NO_MULTIPART_BOUNDARY = 211
ASN1_R_NO_SIG_CONTENT_TYPE = 212
ASN1_R_NON_HEX_CHARACTERS = 141
ASN1_R_NOT_ASCII_FORMAT = 190
ASN1_R_NOT_ENOUGH_DATA = 142
ASN1_R_NULL_IS_WRONG_LENGTH = 144
ASN1_R_OBJECT_NOT_ASCII_FORMAT = 191
ASN1_R_ODD_NUMBER_OF_CHARS = 145
ASN1_R_PRIVATE_KEY_HEADER_MISSING = 146
ASN1_R_SECOND_NUMBER_TOO_LARGE = 147
ASN1_R_SEQUENCE_LENGTH_MISMATCH = 148
ASN1_R_SEQUENCE_NOT_CONSTRUCTED = 149
ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG = 192
ASN1_R_SHORT_LINE = 150
ASN1_R_SIG_INVALID_MIME_TYPE = 213
ASN1_R_STREAMING_NOT_SUPPORTED = 202
ASN1_R_STRING_TOO_LONG = 151
ASN1_R_STRING_TOO_SHORT = 152
ASN1_R_TAG_VALUE_TOO_HIGH = 153
ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD = 154
ASN1_R_TIME_NOT_ASCII_FORMAT = 193
ASN1_R_TOO_LONG = 155
ASN1_R_TYPE_NOT_CONSTRUCTED = 156
ASN1_R_UNABLE_TO_DECODE_RSA_KEY = 157
ASN1_R_UNABLE_TO_DECODE_RSA_PRIVATE_KEY = 158
ASN1_R_UNEXPECTED_EOC = 159
ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH = 215
ASN1_R_UNKNOWN_FORMAT = 160
ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM = 161
ASN1_R_UNKNOWN_OBJECT_TYPE = 162
ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE = 163
ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM = 199
ASN1_R_UNKNOWN_TAG = 194
ASN1_R_UNKOWN_FORMAT = 195
ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE = 164
ASN1_R_UNSUPPORTED_CIPHER = 165
ASN1_R_UNSUPPORTED_ENCRYPTION_ALGORITHM = 166
ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE = 167
ASN1_R_UNSUPPORTED_TYPE = 196
ASN1_R_WRONG_PUBLIC_KEY_TYPE = 200
ASN1_R_WRONG_TAG = 168
ASN1_R_WRONG_TYPE = 169
ASN1_STRFLGS_DUMP_ALL = 0x80
ASN1_STRFLGS_DUMP_DER = 0x200
ASN1_STRFLGS_DUMP_UNKNOWN = 0x100
ASN1_STRFLGS_ESC_2253 = 1
ASN1_STRFLGS_ESC_CTRL = 2
ASN1_STRFLGS_ESC_MSB = 4
ASN1_STRFLGS_ESC_QUOTE = 8
ASN1_STRFLGS_IGNORE_TYPE = 0x20
ASN1_STRFLGS_SHOW_TYPE = 0x40
ASN1_STRFLGS_UTF8_CONVERT = 0x10
ASN1_STRING_FLAG_BITS_LEFT = 0x08
ASN1_STRING_FLAG_CONT = 0x020
ASN1_STRING_FLAG_MSTRING = 0x040
ASN1_STRING_FLAG_NDEF = 0x010
B_ASN1_BIT_STRING = 0x0400
B_ASN1_BMPSTRING = 0x0800
B_ASN1_GENERALIZEDTIME = 0x8000
B_ASN1_GENERALSTRING = 0x0080
B_ASN1_GRAPHICSTRING = 0x0020
B_ASN1_IA5STRING = 0x0010
B_ASN1_ISO64STRING = 0x0040
B_ASN1_NUMERICSTRING = 0x0001
B_ASN1_OCTET_STRING = 0x0200
B_ASN1_PRINTABLESTRING = 0x0002
B_ASN1_SEQUENCE = 0x10000
B_ASN1_T61STRING = 0x0004
B_ASN1_TELETEXSTRING = 0x0004
B_ASN1_UNIVERSALSTRING = 0x0100
B_ASN1_UNKNOWN = 0x1000
B_ASN1_UTCTIME = 0x4000
B_ASN1_UTF8STRING = 0x2000
B_ASN1_VIDEOTEXSTRING = 0x0008
B_ASN1_VISIBLESTRING = 0x0040

return _M
