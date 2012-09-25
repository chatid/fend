local ffi = require "ffi"

include "openssl/bio"
include "openssl/x509"
include "openssl/conf"

ffi.cdef[[
struct v3_ext_method;
struct v3_ext_ctx;
typedef void * (*X509V3_EXT_NEW)(void);
typedef void (*X509V3_EXT_FREE)(void *);
typedef void * (*X509V3_EXT_D2I)(void *, const unsigned char ** , long);
typedef int (*X509V3_EXT_I2D)(void *, unsigned char **);
typedef struct stack_st_CONF_VALUE *
  (*X509V3_EXT_I2V)(const struct v3_ext_method *method, void *ext,
      struct stack_st_CONF_VALUE *extlist);
typedef void * (*X509V3_EXT_V2I)(const struct v3_ext_method *method,
     struct v3_ext_ctx *ctx,
     struct stack_st_CONF_VALUE *values);
typedef char * (*X509V3_EXT_I2S)(const struct v3_ext_method *method, void *ext);
typedef void * (*X509V3_EXT_S2I)(const struct v3_ext_method *method,
     struct v3_ext_ctx *ctx, const char *str);
typedef int (*X509V3_EXT_I2R)(const struct v3_ext_method *method, void *ext,
         BIO *out, int indent);
typedef void * (*X509V3_EXT_R2I)(const struct v3_ext_method *method,
     struct v3_ext_ctx *ctx, const char *str);
struct v3_ext_method {
int ext_nid;
int ext_flags;
ASN1_ITEM_EXP *it;
X509V3_EXT_NEW ext_new;
X509V3_EXT_FREE ext_free;
X509V3_EXT_D2I d2i;
X509V3_EXT_I2D i2d;
X509V3_EXT_I2S i2s;
X509V3_EXT_S2I s2i;
X509V3_EXT_I2V i2v;
X509V3_EXT_V2I v2i;
X509V3_EXT_I2R i2r;
X509V3_EXT_R2I r2i;
void *usr_data;
};
typedef struct X509V3_CONF_METHOD_st {
char * (*get_string)(void *db, char *section, char *value);
struct stack_st_CONF_VALUE * (*get_section)(void *db, char *section);
void (*free_string)(void *db, char * string);
void (*free_section)(void *db, struct stack_st_CONF_VALUE *section);
} X509V3_CONF_METHOD;
struct v3_ext_ctx {
int flags;
X509 *issuer_cert;
X509 *subject_cert;
X509_REQ *subject_req;
X509_CRL *crl;
X509V3_CONF_METHOD *db_meth;
void *db;
};
typedef struct v3_ext_method X509V3_EXT_METHOD;
struct stack_st_X509V3_EXT_METHOD { _STACK stack; };
typedef BIT_STRING_BITNAME ENUMERATED_NAMES;
typedef struct BASIC_CONSTRAINTS_st {
int ca;
ASN1_INTEGER *pathlen;
} BASIC_CONSTRAINTS;
typedef struct PKEY_USAGE_PERIOD_st {
ASN1_GENERALIZEDTIME *notBefore;
ASN1_GENERALIZEDTIME *notAfter;
} PKEY_USAGE_PERIOD;
typedef struct otherName_st {
ASN1_OBJECT *type_id;
ASN1_TYPE *value;
} OTHERNAME;
typedef struct EDIPartyName_st {
 ASN1_STRING *nameAssigner;
 ASN1_STRING *partyName;
} EDIPARTYNAME;
typedef struct GENERAL_NAME_st {
int type;
union {
 char *ptr;
 OTHERNAME *otherName;
 ASN1_IA5STRING *rfc822Name;
 ASN1_IA5STRING *dNSName;
 ASN1_TYPE *x400Address;
 X509_NAME *directoryName;
 EDIPARTYNAME *ediPartyName;
 ASN1_IA5STRING *uniformResourceIdentifier;
 ASN1_OCTET_STRING *iPAddress;
 ASN1_OBJECT *registeredID;
 ASN1_OCTET_STRING *ip;
 X509_NAME *dirn;
 ASN1_IA5STRING *ia5;
 ASN1_OBJECT *rid;
 ASN1_TYPE *other;
} d;
} GENERAL_NAME;
typedef struct stack_st_GENERAL_NAME GENERAL_NAMES;
typedef struct ACCESS_DESCRIPTION_st {
 ASN1_OBJECT *method;
 GENERAL_NAME *location;
} ACCESS_DESCRIPTION;
typedef struct stack_st_ACCESS_DESCRIPTION AUTHORITY_INFO_ACCESS;
typedef struct stack_st_ASN1_OBJECT EXTENDED_KEY_USAGE;
struct stack_st_GENERAL_NAME { _STACK stack; };

struct stack_st_ACCESS_DESCRIPTION { _STACK stack; };

typedef struct DIST_POINT_NAME_st {
int type;
union {
 GENERAL_NAMES *fullname;
 struct stack_st_X509_NAME_ENTRY *relativename;
} name;
X509_NAME *dpname;
} DIST_POINT_NAME;
struct DIST_POINT_st {
DIST_POINT_NAME *distpoint;
ASN1_BIT_STRING *reasons;
GENERAL_NAMES *CRLissuer;
int dp_reasons;
};
typedef struct stack_st_DIST_POINT CRL_DIST_POINTS;
struct stack_st_DIST_POINT { _STACK stack; };

struct AUTHORITY_KEYID_st {
ASN1_OCTET_STRING *keyid;
GENERAL_NAMES *issuer;
ASN1_INTEGER *serial;
};
typedef struct SXNET_ID_st {
 ASN1_INTEGER *zone;
 ASN1_OCTET_STRING *user;
} SXNETID;
struct stack_st_SXNETID { _STACK stack; };

typedef struct SXNET_st {
 ASN1_INTEGER *version;
 struct stack_st_SXNETID *ids;
} SXNET;
typedef struct NOTICEREF_st {
 ASN1_STRING *organization;
 struct stack_st_ASN1_INTEGER *noticenos;
} NOTICEREF;
typedef struct USERNOTICE_st {
 NOTICEREF *noticeref;
 ASN1_STRING *exptext;
} USERNOTICE;
typedef struct POLICYQUALINFO_st {
 ASN1_OBJECT *pqualid;
 union {
  ASN1_IA5STRING *cpsuri;
  USERNOTICE *usernotice;
  ASN1_TYPE *other;
 } d;
} POLICYQUALINFO;
struct stack_st_POLICYQUALINFO { _STACK stack; };

typedef struct POLICYINFO_st {
 ASN1_OBJECT *policyid;
 struct stack_st_POLICYQUALINFO *qualifiers;
} POLICYINFO;
typedef struct stack_st_POLICYINFO CERTIFICATEPOLICIES;
struct stack_st_POLICYINFO { _STACK stack; };

typedef struct POLICY_MAPPING_st {
 ASN1_OBJECT *issuerDomainPolicy;
 ASN1_OBJECT *subjectDomainPolicy;
} POLICY_MAPPING;
struct stack_st_POLICY_MAPPING { _STACK stack; };
typedef struct stack_st_POLICY_MAPPING POLICY_MAPPINGS;
typedef struct GENERAL_SUBTREE_st {
 GENERAL_NAME *base;
 ASN1_INTEGER *minimum;
 ASN1_INTEGER *maximum;
} GENERAL_SUBTREE;
struct stack_st_GENERAL_SUBTREE { _STACK stack; };
struct NAME_CONSTRAINTS_st {
 struct stack_st_GENERAL_SUBTREE *permittedSubtrees;
 struct stack_st_GENERAL_SUBTREE *excludedSubtrees;
};
typedef struct POLICY_CONSTRAINTS_st {
 ASN1_INTEGER *requireExplicitPolicy;
 ASN1_INTEGER *inhibitPolicyMapping;
} POLICY_CONSTRAINTS;
typedef struct PROXY_POLICY_st
 {
 ASN1_OBJECT *policyLanguage;
 ASN1_OCTET_STRING *policy;
 } PROXY_POLICY;
typedef struct PROXY_CERT_INFO_EXTENSION_st
 {
 ASN1_INTEGER *pcPathLengthConstraint;
 PROXY_POLICY *proxyPolicy;
 } PROXY_CERT_INFO_EXTENSION;
PROXY_POLICY *PROXY_POLICY_new(void); void PROXY_POLICY_free(PROXY_POLICY *a); PROXY_POLICY *d2i_PROXY_POLICY(PROXY_POLICY **a, const unsigned char **in, long len); int i2d_PROXY_POLICY(PROXY_POLICY *a, unsigned char **out); extern const ASN1_ITEM PROXY_POLICY_it;
PROXY_CERT_INFO_EXTENSION *PROXY_CERT_INFO_EXTENSION_new(void); void PROXY_CERT_INFO_EXTENSION_free(PROXY_CERT_INFO_EXTENSION *a); PROXY_CERT_INFO_EXTENSION *d2i_PROXY_CERT_INFO_EXTENSION(PROXY_CERT_INFO_EXTENSION **a, const unsigned char **in, long len); int i2d_PROXY_CERT_INFO_EXTENSION(PROXY_CERT_INFO_EXTENSION *a, unsigned char **out); extern const ASN1_ITEM PROXY_CERT_INFO_EXTENSION_it;
struct ISSUING_DIST_POINT_st
 {
 DIST_POINT_NAME *distpoint;
 int onlyuser;
 int onlyCA;
 ASN1_BIT_STRING *onlysomereasons;
 int indirectCRL;
 int onlyattr;
 };
typedef struct x509_purpose_st {
 int purpose;
 int trust;
 int flags;
 int (*check_purpose)(const struct x509_purpose_st *,
    const X509 *, int);
 char *name;
 char *sname;
 void *usr_data;
} X509_PURPOSE;
struct stack_st_X509_PURPOSE { _STACK stack; };
BASIC_CONSTRAINTS *BASIC_CONSTRAINTS_new(void); void BASIC_CONSTRAINTS_free(BASIC_CONSTRAINTS *a); BASIC_CONSTRAINTS *d2i_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS **a, const unsigned char **in, long len); int i2d_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS *a, unsigned char **out); extern const ASN1_ITEM BASIC_CONSTRAINTS_it;
SXNET *SXNET_new(void); void SXNET_free(SXNET *a); SXNET *d2i_SXNET(SXNET **a, const unsigned char **in, long len); int i2d_SXNET(SXNET *a, unsigned char **out); extern const ASN1_ITEM SXNET_it;
SXNETID *SXNETID_new(void); void SXNETID_free(SXNETID *a); SXNETID *d2i_SXNETID(SXNETID **a, const unsigned char **in, long len); int i2d_SXNETID(SXNETID *a, unsigned char **out); extern const ASN1_ITEM SXNETID_it;
int SXNET_add_id_asc(SXNET **psx, char *zone, char *user, int userlen);
int SXNET_add_id_ulong(SXNET **psx, unsigned long lzone, char *user, int userlen);
int SXNET_add_id_INTEGER(SXNET **psx, ASN1_INTEGER *izone, char *user, int userlen);
ASN1_OCTET_STRING *SXNET_get_id_asc(SXNET *sx, char *zone);
ASN1_OCTET_STRING *SXNET_get_id_ulong(SXNET *sx, unsigned long lzone);
ASN1_OCTET_STRING *SXNET_get_id_INTEGER(SXNET *sx, ASN1_INTEGER *zone);
AUTHORITY_KEYID *AUTHORITY_KEYID_new(void); void AUTHORITY_KEYID_free(AUTHORITY_KEYID *a); AUTHORITY_KEYID *d2i_AUTHORITY_KEYID(AUTHORITY_KEYID **a, const unsigned char **in, long len); int i2d_AUTHORITY_KEYID(AUTHORITY_KEYID *a, unsigned char **out); extern const ASN1_ITEM AUTHORITY_KEYID_it;
PKEY_USAGE_PERIOD *PKEY_USAGE_PERIOD_new(void); void PKEY_USAGE_PERIOD_free(PKEY_USAGE_PERIOD *a); PKEY_USAGE_PERIOD *d2i_PKEY_USAGE_PERIOD(PKEY_USAGE_PERIOD **a, const unsigned char **in, long len); int i2d_PKEY_USAGE_PERIOD(PKEY_USAGE_PERIOD *a, unsigned char **out); extern const ASN1_ITEM PKEY_USAGE_PERIOD_it;
GENERAL_NAME *GENERAL_NAME_new(void); void GENERAL_NAME_free(GENERAL_NAME *a); GENERAL_NAME *d2i_GENERAL_NAME(GENERAL_NAME **a, const unsigned char **in, long len); int i2d_GENERAL_NAME(GENERAL_NAME *a, unsigned char **out); extern const ASN1_ITEM GENERAL_NAME_it;
GENERAL_NAME *GENERAL_NAME_dup(GENERAL_NAME *a);
int GENERAL_NAME_cmp(GENERAL_NAME *a, GENERAL_NAME *b);
ASN1_BIT_STRING *v2i_ASN1_BIT_STRING(X509V3_EXT_METHOD *method,
    X509V3_CTX *ctx, struct stack_st_CONF_VALUE *nval);
struct stack_st_CONF_VALUE *i2v_ASN1_BIT_STRING(X509V3_EXT_METHOD *method,
    ASN1_BIT_STRING *bits,
    struct stack_st_CONF_VALUE *extlist);
struct stack_st_CONF_VALUE *i2v_GENERAL_NAME(X509V3_EXT_METHOD *method, GENERAL_NAME *gen, struct stack_st_CONF_VALUE *ret);
int GENERAL_NAME_print(BIO *out, GENERAL_NAME *gen);
GENERAL_NAMES *GENERAL_NAMES_new(void); void GENERAL_NAMES_free(GENERAL_NAMES *a); GENERAL_NAMES *d2i_GENERAL_NAMES(GENERAL_NAMES **a, const unsigned char **in, long len); int i2d_GENERAL_NAMES(GENERAL_NAMES *a, unsigned char **out); extern const ASN1_ITEM GENERAL_NAMES_it;
struct stack_st_CONF_VALUE *i2v_GENERAL_NAMES(X509V3_EXT_METHOD *method,
  GENERAL_NAMES *gen, struct stack_st_CONF_VALUE *extlist);
GENERAL_NAMES *v2i_GENERAL_NAMES(const X509V3_EXT_METHOD *method,
     X509V3_CTX *ctx, struct stack_st_CONF_VALUE *nval);
OTHERNAME *OTHERNAME_new(void); void OTHERNAME_free(OTHERNAME *a); OTHERNAME *d2i_OTHERNAME(OTHERNAME **a, const unsigned char **in, long len); int i2d_OTHERNAME(OTHERNAME *a, unsigned char **out); extern const ASN1_ITEM OTHERNAME_it;
EDIPARTYNAME *EDIPARTYNAME_new(void); void EDIPARTYNAME_free(EDIPARTYNAME *a); EDIPARTYNAME *d2i_EDIPARTYNAME(EDIPARTYNAME **a, const unsigned char **in, long len); int i2d_EDIPARTYNAME(EDIPARTYNAME *a, unsigned char **out); extern const ASN1_ITEM EDIPARTYNAME_it;
int OTHERNAME_cmp(OTHERNAME *a, OTHERNAME *b);
void GENERAL_NAME_set0_value(GENERAL_NAME *a, int type, void *value);
void *GENERAL_NAME_get0_value(GENERAL_NAME *a, int *ptype);
int GENERAL_NAME_set0_othername(GENERAL_NAME *gen,
    ASN1_OBJECT *oid, ASN1_TYPE *value);
int GENERAL_NAME_get0_otherName(GENERAL_NAME *gen,
    ASN1_OBJECT **poid, ASN1_TYPE **pvalue);
char *i2s_ASN1_OCTET_STRING(X509V3_EXT_METHOD *method, ASN1_OCTET_STRING *ia5);
ASN1_OCTET_STRING *s2i_ASN1_OCTET_STRING(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, char *str);
EXTENDED_KEY_USAGE *EXTENDED_KEY_USAGE_new(void); void EXTENDED_KEY_USAGE_free(EXTENDED_KEY_USAGE *a); EXTENDED_KEY_USAGE *d2i_EXTENDED_KEY_USAGE(EXTENDED_KEY_USAGE **a, const unsigned char **in, long len); int i2d_EXTENDED_KEY_USAGE(EXTENDED_KEY_USAGE *a, unsigned char **out); extern const ASN1_ITEM EXTENDED_KEY_USAGE_it;
int i2a_ACCESS_DESCRIPTION(BIO *bp, ACCESS_DESCRIPTION* a);
CERTIFICATEPOLICIES *CERTIFICATEPOLICIES_new(void); void CERTIFICATEPOLICIES_free(CERTIFICATEPOLICIES *a); CERTIFICATEPOLICIES *d2i_CERTIFICATEPOLICIES(CERTIFICATEPOLICIES **a, const unsigned char **in, long len); int i2d_CERTIFICATEPOLICIES(CERTIFICATEPOLICIES *a, unsigned char **out); extern const ASN1_ITEM CERTIFICATEPOLICIES_it;
POLICYINFO *POLICYINFO_new(void); void POLICYINFO_free(POLICYINFO *a); POLICYINFO *d2i_POLICYINFO(POLICYINFO **a, const unsigned char **in, long len); int i2d_POLICYINFO(POLICYINFO *a, unsigned char **out); extern const ASN1_ITEM POLICYINFO_it;
POLICYQUALINFO *POLICYQUALINFO_new(void); void POLICYQUALINFO_free(POLICYQUALINFO *a); POLICYQUALINFO *d2i_POLICYQUALINFO(POLICYQUALINFO **a, const unsigned char **in, long len); int i2d_POLICYQUALINFO(POLICYQUALINFO *a, unsigned char **out); extern const ASN1_ITEM POLICYQUALINFO_it;
USERNOTICE *USERNOTICE_new(void); void USERNOTICE_free(USERNOTICE *a); USERNOTICE *d2i_USERNOTICE(USERNOTICE **a, const unsigned char **in, long len); int i2d_USERNOTICE(USERNOTICE *a, unsigned char **out); extern const ASN1_ITEM USERNOTICE_it;
NOTICEREF *NOTICEREF_new(void); void NOTICEREF_free(NOTICEREF *a); NOTICEREF *d2i_NOTICEREF(NOTICEREF **a, const unsigned char **in, long len); int i2d_NOTICEREF(NOTICEREF *a, unsigned char **out); extern const ASN1_ITEM NOTICEREF_it;
CRL_DIST_POINTS *CRL_DIST_POINTS_new(void); void CRL_DIST_POINTS_free(CRL_DIST_POINTS *a); CRL_DIST_POINTS *d2i_CRL_DIST_POINTS(CRL_DIST_POINTS **a, const unsigned char **in, long len); int i2d_CRL_DIST_POINTS(CRL_DIST_POINTS *a, unsigned char **out); extern const ASN1_ITEM CRL_DIST_POINTS_it;
DIST_POINT *DIST_POINT_new(void); void DIST_POINT_free(DIST_POINT *a); DIST_POINT *d2i_DIST_POINT(DIST_POINT **a, const unsigned char **in, long len); int i2d_DIST_POINT(DIST_POINT *a, unsigned char **out); extern const ASN1_ITEM DIST_POINT_it;
DIST_POINT_NAME *DIST_POINT_NAME_new(void); void DIST_POINT_NAME_free(DIST_POINT_NAME *a); DIST_POINT_NAME *d2i_DIST_POINT_NAME(DIST_POINT_NAME **a, const unsigned char **in, long len); int i2d_DIST_POINT_NAME(DIST_POINT_NAME *a, unsigned char **out); extern const ASN1_ITEM DIST_POINT_NAME_it;
ISSUING_DIST_POINT *ISSUING_DIST_POINT_new(void); void ISSUING_DIST_POINT_free(ISSUING_DIST_POINT *a); ISSUING_DIST_POINT *d2i_ISSUING_DIST_POINT(ISSUING_DIST_POINT **a, const unsigned char **in, long len); int i2d_ISSUING_DIST_POINT(ISSUING_DIST_POINT *a, unsigned char **out); extern const ASN1_ITEM ISSUING_DIST_POINT_it;
int DIST_POINT_set_dpname(DIST_POINT_NAME *dpn, X509_NAME *iname);
int NAME_CONSTRAINTS_check(X509 *x, NAME_CONSTRAINTS *nc);
ACCESS_DESCRIPTION *ACCESS_DESCRIPTION_new(void); void ACCESS_DESCRIPTION_free(ACCESS_DESCRIPTION *a); ACCESS_DESCRIPTION *d2i_ACCESS_DESCRIPTION(ACCESS_DESCRIPTION **a, const unsigned char **in, long len); int i2d_ACCESS_DESCRIPTION(ACCESS_DESCRIPTION *a, unsigned char **out); extern const ASN1_ITEM ACCESS_DESCRIPTION_it;
AUTHORITY_INFO_ACCESS *AUTHORITY_INFO_ACCESS_new(void); void AUTHORITY_INFO_ACCESS_free(AUTHORITY_INFO_ACCESS *a); AUTHORITY_INFO_ACCESS *d2i_AUTHORITY_INFO_ACCESS(AUTHORITY_INFO_ACCESS **a, const unsigned char **in, long len); int i2d_AUTHORITY_INFO_ACCESS(AUTHORITY_INFO_ACCESS *a, unsigned char **out); extern const ASN1_ITEM AUTHORITY_INFO_ACCESS_it;
extern const ASN1_ITEM POLICY_MAPPING_it;
POLICY_MAPPING *POLICY_MAPPING_new(void); void POLICY_MAPPING_free(POLICY_MAPPING *a);
extern const ASN1_ITEM POLICY_MAPPINGS_it;
extern const ASN1_ITEM GENERAL_SUBTREE_it;
GENERAL_SUBTREE *GENERAL_SUBTREE_new(void); void GENERAL_SUBTREE_free(GENERAL_SUBTREE *a);
extern const ASN1_ITEM NAME_CONSTRAINTS_it;
NAME_CONSTRAINTS *NAME_CONSTRAINTS_new(void); void NAME_CONSTRAINTS_free(NAME_CONSTRAINTS *a);
POLICY_CONSTRAINTS *POLICY_CONSTRAINTS_new(void); void POLICY_CONSTRAINTS_free(POLICY_CONSTRAINTS *a);
extern const ASN1_ITEM POLICY_CONSTRAINTS_it;
GENERAL_NAME *a2i_GENERAL_NAME(GENERAL_NAME *out,
          const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
          int gen_type, char *value, int is_nc);
GENERAL_NAME *v2i_GENERAL_NAME(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
          CONF_VALUE *cnf);
GENERAL_NAME *v2i_GENERAL_NAME_ex(GENERAL_NAME *out,
      const X509V3_EXT_METHOD *method,
      X509V3_CTX *ctx, CONF_VALUE *cnf, int is_nc);
void X509V3_conf_free(CONF_VALUE *val);
X509_EXTENSION *X509V3_EXT_nconf_nid(CONF *conf, X509V3_CTX *ctx, int ext_nid, char *value);
X509_EXTENSION *X509V3_EXT_nconf(CONF *conf, X509V3_CTX *ctx, char *name, char *value);
int X509V3_EXT_add_nconf_sk(CONF *conf, X509V3_CTX *ctx, char *section, struct stack_st_X509_EXTENSION **sk);
int X509V3_EXT_add_nconf(CONF *conf, X509V3_CTX *ctx, char *section, X509 *cert);
int X509V3_EXT_REQ_add_nconf(CONF *conf, X509V3_CTX *ctx, char *section, X509_REQ *req);
int X509V3_EXT_CRL_add_nconf(CONF *conf, X509V3_CTX *ctx, char *section, X509_CRL *crl);
X509_EXTENSION *X509V3_EXT_conf_nid(struct lhash_st_CONF_VALUE *conf, X509V3_CTX *ctx,
        int ext_nid, char *value);
X509_EXTENSION *X509V3_EXT_conf(struct lhash_st_CONF_VALUE *conf, X509V3_CTX *ctx,
    char *name, char *value);
int X509V3_EXT_add_conf(struct lhash_st_CONF_VALUE *conf, X509V3_CTX *ctx,
   char *section, X509 *cert);
int X509V3_EXT_REQ_add_conf(struct lhash_st_CONF_VALUE *conf, X509V3_CTX *ctx,
       char *section, X509_REQ *req);
int X509V3_EXT_CRL_add_conf(struct lhash_st_CONF_VALUE *conf, X509V3_CTX *ctx,
       char *section, X509_CRL *crl);
int X509V3_add_value_bool_nf(char *name, int asn1_bool,
        struct stack_st_CONF_VALUE **extlist);
int X509V3_get_value_bool(CONF_VALUE *value, int *asn1_bool);
int X509V3_get_value_int(CONF_VALUE *value, ASN1_INTEGER **aint);
void X509V3_set_nconf(X509V3_CTX *ctx, CONF *conf);
void X509V3_set_conf_lhash(X509V3_CTX *ctx, struct lhash_st_CONF_VALUE *lhash);
char * X509V3_get_string(X509V3_CTX *ctx, char *name, char *section);
struct stack_st_CONF_VALUE * X509V3_get_section(X509V3_CTX *ctx, char *section);
void X509V3_string_free(X509V3_CTX *ctx, char *str);
void X509V3_section_free( X509V3_CTX *ctx, struct stack_st_CONF_VALUE *section);
void X509V3_set_ctx(X509V3_CTX *ctx, X509 *issuer, X509 *subject,
     X509_REQ *req, X509_CRL *crl, int flags);
int X509V3_add_value(const char *name, const char *value,
      struct stack_st_CONF_VALUE **extlist);
int X509V3_add_value_uchar(const char *name, const unsigned char *value,
      struct stack_st_CONF_VALUE **extlist);
int X509V3_add_value_bool(const char *name, int asn1_bool,
      struct stack_st_CONF_VALUE **extlist);
int X509V3_add_value_int(const char *name, ASN1_INTEGER *aint,
      struct stack_st_CONF_VALUE **extlist);
char * i2s_ASN1_INTEGER(X509V3_EXT_METHOD *meth, ASN1_INTEGER *aint);
ASN1_INTEGER * s2i_ASN1_INTEGER(X509V3_EXT_METHOD *meth, char *value);
char * i2s_ASN1_ENUMERATED(X509V3_EXT_METHOD *meth, ASN1_ENUMERATED *aint);
char * i2s_ASN1_ENUMERATED_TABLE(X509V3_EXT_METHOD *meth, ASN1_ENUMERATED *aint);
int X509V3_EXT_add(X509V3_EXT_METHOD *ext);
int X509V3_EXT_add_list(X509V3_EXT_METHOD *extlist);
int X509V3_EXT_add_alias(int nid_to, int nid_from);
void X509V3_EXT_cleanup(void);
const X509V3_EXT_METHOD *X509V3_EXT_get(X509_EXTENSION *ext);
const X509V3_EXT_METHOD *X509V3_EXT_get_nid(int nid);
int X509V3_add_standard_extensions(void);
struct stack_st_CONF_VALUE *X509V3_parse_list(const char *line);
void *X509V3_EXT_d2i(X509_EXTENSION *ext);
void *X509V3_get_d2i(struct stack_st_X509_EXTENSION *x, int nid, int *crit, int *idx);
X509_EXTENSION *X509V3_EXT_i2d(int ext_nid, int crit, void *ext_struc);
int X509V3_add1_i2d(struct stack_st_X509_EXTENSION **x, int nid, void *value, int crit, unsigned long flags);
char *hex_to_string(const unsigned char *buffer, long len);
unsigned char *string_to_hex(const char *str, long *len);
int name_cmp(const char *name, const char *cmp);
void X509V3_EXT_val_prn(BIO *out, struct stack_st_CONF_VALUE *val, int indent,
         int ml);
int X509V3_EXT_print(BIO *out, X509_EXTENSION *ext, unsigned long flag, int indent);
int X509V3_EXT_print_fp(FILE *out, X509_EXTENSION *ext, int flag, int indent);
int X509V3_extensions_print(BIO *out, char *title, struct stack_st_X509_EXTENSION *exts, unsigned long flag, int indent);
int X509_check_ca(X509 *x);
int X509_check_purpose(X509 *x, int id, int ca);
int X509_supported_extension(X509_EXTENSION *ex);
int X509_PURPOSE_set(int *p, int purpose);
int X509_check_issued(X509 *issuer, X509 *subject);
int X509_check_akid(X509 *issuer, AUTHORITY_KEYID *akid);
int X509_PURPOSE_get_count(void);
X509_PURPOSE * X509_PURPOSE_get0(int idx);
int X509_PURPOSE_get_by_sname(char *sname);
int X509_PURPOSE_get_by_id(int id);
int X509_PURPOSE_add(int id, int trust, int flags,
   int (*ck)(const X509_PURPOSE *, const X509 *, int),
    char *name, char *sname, void *arg);
char *X509_PURPOSE_get0_name(X509_PURPOSE *xp);
char *X509_PURPOSE_get0_sname(X509_PURPOSE *xp);
int X509_PURPOSE_get_trust(X509_PURPOSE *xp);
void X509_PURPOSE_cleanup(void);
int X509_PURPOSE_get_id(X509_PURPOSE *);
struct stack_st_OPENSSL_STRING *X509_get1_email(X509 *x);
struct stack_st_OPENSSL_STRING *X509_REQ_get1_email(X509_REQ *x);
void X509_email_free(struct stack_st_OPENSSL_STRING *sk);
struct stack_st_OPENSSL_STRING *X509_get1_ocsp(X509 *x);
ASN1_OCTET_STRING *a2i_IPADDRESS(const char *ipasc);
ASN1_OCTET_STRING *a2i_IPADDRESS_NC(const char *ipasc);
int a2i_ipadd(unsigned char *ipout, const char *ipasc);
int X509V3_NAME_from_section(X509_NAME *nm, struct stack_st_CONF_VALUE*dn_sk,
      unsigned long chtype);
void X509_POLICY_NODE_print(BIO *out, X509_POLICY_NODE *node, int indent);
struct stack_st_X509_POLICY_NODE { _STACK stack; };
void ERR_load_X509V3_strings(void);
]]

module ( ... )

X509v3_KU_CRL_SIGN = 0x0002
X509v3_KU_DATA_ENCIPHERMENT = 0x0010
X509v3_KU_DECIPHER_ONLY = 0x8000
X509v3_KU_DIGITAL_SIGNATURE = 0x0080
X509v3_KU_ENCIPHER_ONLY = 0x0001
X509v3_KU_KEY_AGREEMENT = 0x0008
X509v3_KU_KEY_CERT_SIGN = 0x0004
X509v3_KU_KEY_ENCIPHERMENT = 0x0020
X509v3_KU_NON_REPUDIATION = 0x0040
X509v3_KU_UNDEF = 0xffff

return _M
