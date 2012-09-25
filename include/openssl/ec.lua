include "openssl/asn1"
include "openssl/symhacks"
include "openssl/bn"

ffi.cdef [[
typedef enum {
 POINT_CONVERSION_COMPRESSED = 2,
 POINT_CONVERSION_UNCOMPRESSED = 4,
 POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;
typedef struct ec_method_st EC_METHOD;
typedef struct ec_group_st
 EC_GROUP;
typedef struct ec_point_st EC_POINT;
const EC_METHOD *EC_GFp_simple_method(void);
const EC_METHOD *EC_GFp_mont_method(void);
const EC_METHOD *EC_GFp_nist_method(void);
const EC_METHOD *EC_GFp_nistp224_method(void);
const EC_METHOD *EC_GFp_nistp256_method(void);
const EC_METHOD *EC_GFp_nistp521_method(void);
const EC_METHOD *EC_GF2m_simple_method(void);
EC_GROUP *EC_GROUP_new(const EC_METHOD *meth);
void EC_GROUP_free(EC_GROUP *group);
void EC_GROUP_clear_free(EC_GROUP *group);
int EC_GROUP_copy(EC_GROUP *dst, const EC_GROUP *src);
EC_GROUP *EC_GROUP_dup(const EC_GROUP *src);
const EC_METHOD *EC_GROUP_method_of(const EC_GROUP *group);
int EC_METHOD_get_field_type(const EC_METHOD *meth);
int EC_GROUP_set_generator(EC_GROUP *group, const EC_POINT *generator, const BIGNUM *order, const BIGNUM *cofactor);
const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *group);
int EC_GROUP_get_order(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx);
int EC_GROUP_get_cofactor(const EC_GROUP *group, BIGNUM *cofactor, BN_CTX *ctx);
void EC_GROUP_set_curve_name(EC_GROUP *group, int nid);
int EC_GROUP_get_curve_name(const EC_GROUP *group);
void EC_GROUP_set_asn1_flag(EC_GROUP *group, int flag);
int EC_GROUP_get_asn1_flag(const EC_GROUP *group);
void EC_GROUP_set_point_conversion_form(EC_GROUP *, point_conversion_form_t);
point_conversion_form_t EC_GROUP_get_point_conversion_form(const EC_GROUP *);
unsigned char *EC_GROUP_get0_seed(const EC_GROUP *);
size_t EC_GROUP_get_seed_len(const EC_GROUP *);
size_t EC_GROUP_set_seed(EC_GROUP *, const unsigned char *, size_t len);
int EC_GROUP_set_curve_GFp(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int EC_GROUP_get_curve_GFp(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx);
int EC_GROUP_set_curve_GF2m(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int EC_GROUP_get_curve_GF2m(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx);
int EC_GROUP_get_degree(const EC_GROUP *group);
int EC_GROUP_check(const EC_GROUP *group, BN_CTX *ctx);
int EC_GROUP_check_discriminant(const EC_GROUP *group, BN_CTX *ctx);
int EC_GROUP_cmp(const EC_GROUP *a, const EC_GROUP *b, BN_CTX *ctx);
EC_GROUP *EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
EC_GROUP *EC_GROUP_new_curve_GF2m(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
EC_GROUP *EC_GROUP_new_by_curve_name(int nid);
typedef struct {
 int nid;
 const char *comment;
 } EC_builtin_curve;
size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);
EC_POINT *EC_POINT_new(const EC_GROUP *group);
void EC_POINT_free(EC_POINT *point);
void EC_POINT_clear_free(EC_POINT *point);
int EC_POINT_copy(EC_POINT *dst, const EC_POINT *src);
EC_POINT *EC_POINT_dup(const EC_POINT *src, const EC_GROUP *group);
const EC_METHOD *EC_POINT_method_of(const EC_POINT *point);
int EC_POINT_set_to_infinity(const EC_GROUP *group, EC_POINT *point);
int EC_POINT_set_Jprojective_coordinates_GFp(const EC_GROUP *group, EC_POINT *p,
 const BIGNUM *x, const BIGNUM *y, const BIGNUM *z, BN_CTX *ctx);
int EC_POINT_get_Jprojective_coordinates_GFp(const EC_GROUP *group,
 const EC_POINT *p, BIGNUM *x, BIGNUM *y, BIGNUM *z, BN_CTX *ctx);
int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group, EC_POINT *p,
 const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx);
int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group,
 const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx);
int EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP *group, EC_POINT *p,
 const BIGNUM *x, int y_bit, BN_CTX *ctx);
int EC_POINT_set_affine_coordinates_GF2m(const EC_GROUP *group, EC_POINT *p,
 const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx);
int EC_POINT_get_affine_coordinates_GF2m(const EC_GROUP *group,
 const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx);
int EC_POINT_set_compressed_coordinates_GF2m(const EC_GROUP *group, EC_POINT *p,
 const BIGNUM *x, int y_bit, BN_CTX *ctx);
size_t EC_POINT_point2oct(const EC_GROUP *group, const EC_POINT *p,
 point_conversion_form_t form,
        unsigned char *buf, size_t len, BN_CTX *ctx);
int EC_POINT_oct2point(const EC_GROUP *group, EC_POINT *p,
        const unsigned char *buf, size_t len, BN_CTX *ctx);
BIGNUM *EC_POINT_point2bn(const EC_GROUP *, const EC_POINT *,
 point_conversion_form_t form, BIGNUM *, BN_CTX *);
EC_POINT *EC_POINT_bn2point(const EC_GROUP *, const BIGNUM *,
 EC_POINT *, BN_CTX *);
char *EC_POINT_point2hex(const EC_GROUP *, const EC_POINT *,
 point_conversion_form_t form, BN_CTX *);
EC_POINT *EC_POINT_hex2point(const EC_GROUP *, const char *,
 EC_POINT *, BN_CTX *);
int EC_POINT_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx);
int EC_POINT_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, BN_CTX *ctx);
int EC_POINT_invert(const EC_GROUP *group, EC_POINT *a, BN_CTX *ctx);
int EC_POINT_is_at_infinity(const EC_GROUP *group, const EC_POINT *p);
int EC_POINT_is_on_curve(const EC_GROUP *group, const EC_POINT *point, BN_CTX *ctx);
int EC_POINT_cmp(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx);
int EC_POINT_make_affine(const EC_GROUP *, EC_POINT *, BN_CTX *);
int EC_POINTs_make_affine(const EC_GROUP *, size_t num, EC_POINT *[], BN_CTX *);
int EC_POINTs_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, size_t num, const EC_POINT *p[], const BIGNUM *m[], BN_CTX *ctx);
int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx);
int EC_GROUP_precompute_mult(EC_GROUP *group, BN_CTX *ctx);
int EC_GROUP_have_precompute_mult(const EC_GROUP *group);
int EC_GROUP_get_basis_type(const EC_GROUP *);
int EC_GROUP_get_trinomial_basis(const EC_GROUP *, unsigned int *k);
int EC_GROUP_get_pentanomial_basis(const EC_GROUP *, unsigned int *k1,
 unsigned int *k2, unsigned int *k3);
typedef struct ecpk_parameters_st ECPKPARAMETERS;
EC_GROUP *d2i_ECPKParameters(EC_GROUP **, const unsigned char **in, long len);
int i2d_ECPKParameters(const EC_GROUP *, unsigned char **out);
int ECPKParameters_print(BIO *bp, const EC_GROUP *x, int off);
int ECPKParameters_print_fp(FILE *fp, const EC_GROUP *x, int off);
typedef struct ec_key_st EC_KEY;
EC_KEY *EC_KEY_new(void);
int EC_KEY_get_flags(const EC_KEY *key);
void EC_KEY_set_flags(EC_KEY *key, int flags);
void EC_KEY_clear_flags(EC_KEY *key, int flags);
EC_KEY *EC_KEY_new_by_curve_name(int nid);
void EC_KEY_free(EC_KEY *key);
EC_KEY *EC_KEY_copy(EC_KEY *dst, const EC_KEY *src);
EC_KEY *EC_KEY_dup(const EC_KEY *src);
int EC_KEY_up_ref(EC_KEY *key);
const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key);
int EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group);
const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *key);
int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *prv);
const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key);
int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub);
unsigned EC_KEY_get_enc_flags(const EC_KEY *key);
void EC_KEY_set_enc_flags(EC_KEY *, unsigned int);
point_conversion_form_t EC_KEY_get_conv_form(const EC_KEY *);
void EC_KEY_set_conv_form(EC_KEY *, point_conversion_form_t);
void *EC_KEY_get_key_method_data(EC_KEY *,
 void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));
void EC_KEY_insert_key_method_data(EC_KEY *, void *data,
 void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));
void EC_KEY_set_asn1_flag(EC_KEY *, int);
int EC_KEY_precompute_mult(EC_KEY *key, BN_CTX *ctx);
int EC_KEY_generate_key(EC_KEY *key);
int EC_KEY_check_key(const EC_KEY *key);
int EC_KEY_set_public_key_affine_coordinates(EC_KEY *key, BIGNUM *x, BIGNUM *y);
EC_KEY *d2i_ECPrivateKey(EC_KEY **key, const unsigned char **in, long len);
int i2d_ECPrivateKey(EC_KEY *key, unsigned char **out);
EC_KEY *d2i_ECParameters(EC_KEY **key, const unsigned char **in, long len);
int i2d_ECParameters(EC_KEY *key, unsigned char **out);
EC_KEY *o2i_ECPublicKey(EC_KEY **key, const unsigned char **in, long len);
int i2o_ECPublicKey(EC_KEY *key, unsigned char **out);
int ECParameters_print(BIO *bp, const EC_KEY *key);
int EC_KEY_print(BIO *bp, const EC_KEY *key, int off);
int ECParameters_print_fp(FILE *fp, const EC_KEY *key);
int EC_KEY_print_fp(FILE *fp, const EC_KEY *key, int off);
void ERR_load_EC_strings(void);
]]

EC_F_BN_TO_FELEM = 224
EC_F_COMPUTE_WNAF = 143
EC_F_D2I_ECPARAMETERS = 144
EC_F_D2I_ECPKPARAMETERS = 145
EC_F_D2I_ECPRIVATEKEY = 146
EC_F_DO_EC_KEY_PRINT = 221
EC_F_EC_ASN1_GROUP2CURVE = 153
EC_F_EC_ASN1_GROUP2FIELDID = 154
EC_F_EC_ASN1_GROUP2PARAMETERS = 155
EC_F_EC_ASN1_GROUP2PKPARAMETERS = 156
EC_F_EC_ASN1_PARAMETERS2GROUP = 157
EC_F_EC_ASN1_PKPARAMETERS2GROUP = 158
EC_F_EC_EX_DATA_SET_DATA = 211
EC_F_EC_GF2M_MONTGOMERY_POINT_MULTIPLY = 208
EC_F_EC_GF2M_SIMPLE_GROUP_CHECK_DISCRIMINANT = 159
EC_F_EC_GF2M_SIMPLE_GROUP_SET_CURVE = 195
EC_F_EC_GF2M_SIMPLE_OCT2POINT = 160
EC_F_EC_GF2M_SIMPLE_POINT2OCT = 161
EC_F_EC_GF2M_SIMPLE_POINT_GET_AFFINE_COORDINATES = 162
EC_F_EC_GF2M_SIMPLE_POINT_SET_AFFINE_COORDINATES = 163
EC_F_EC_GF2M_SIMPLE_SET_COMPRESSED_COORDINATES = 164
EC_F_EC_GFP_MONT_FIELD_DECODE = 133
EC_F_EC_GFP_MONT_FIELD_ENCODE = 134
EC_F_EC_GFP_MONT_FIELD_MUL = 131
EC_F_EC_GFP_MONT_FIELD_SET_TO_ONE = 209
EC_F_EC_GFP_MONT_FIELD_SQR = 132
EC_F_EC_GFP_MONT_GROUP_SET_CURVE = 189
EC_F_EC_GFP_MONT_GROUP_SET_CURVE_GFP = 135
EC_F_EC_GFP_NIST_FIELD_MUL = 200
EC_F_EC_GFP_NIST_FIELD_SQR = 201
EC_F_EC_GFP_NIST_GROUP_SET_CURVE = 202
EC_F_EC_GFP_NISTP224_GROUP_SET_CURVE = 225
EC_F_EC_GFP_NISTP224_POINT_GET_AFFINE_COORDINATES = 226
EC_F_EC_GFP_NISTP224_POINTS_MUL = 228
EC_F_EC_GFP_NISTP256_GROUP_SET_CURVE = 230
EC_F_EC_GFP_NISTP256_POINT_GET_AFFINE_COORDINATES = 232
EC_F_EC_GFP_NISTP256_POINTS_MUL = 231
EC_F_EC_GFP_NISTP521_GROUP_SET_CURVE = 233
EC_F_EC_GFP_NISTP521_POINT_GET_AFFINE_COORDINATES = 235
EC_F_EC_GFP_NISTP521_POINTS_MUL = 234
EC_F_EC_GFP_SIMPLE_GROUP_CHECK_DISCRIMINANT = 165
EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE = 166
EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE_GFP = 100
EC_F_EC_GFP_SIMPLE_GROUP_SET_GENERATOR = 101
EC_F_EC_GFP_SIMPLE_MAKE_AFFINE = 102
EC_F_EC_GFP_SIMPLE_OCT2POINT = 103
EC_F_EC_GFP_SIMPLE_POINT2OCT = 104
EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES = 167
EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES_GFP = 105
EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES = 168
EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES_GFP = 128
EC_F_EC_GFP_SIMPLE_POINTS_MAKE_AFFINE = 137
EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES = 169
EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES_GFP = 129
EC_F_EC_GROUP_CHECK = 170
EC_F_EC_GROUP_CHECK_DISCRIMINANT = 171
EC_F_EC_GROUP_COPY = 106
EC_F_EC_GROUP_GET0_GENERATOR = 139
EC_F_EC_GROUP_GET_COFACTOR = 140
EC_F_EC_GROUP_GET_CURVE_GF2M = 172
EC_F_EC_GROUP_GET_CURVE_GFP = 130
EC_F_EC_GROUP_GET_DEGREE = 173
EC_F_EC_GROUP_GET_ORDER = 141
EC_F_EC_GROUP_GET_PENTANOMIAL_BASIS = 193
EC_F_EC_GROUP_GET_TRINOMIAL_BASIS = 194
EC_F_EC_GROUP_NEW = 108
EC_F_EC_GROUP_NEW_BY_CURVE_NAME = 174
EC_F_EC_GROUP_NEW_FROM_DATA = 175
EC_F_EC_GROUP_PRECOMPUTE_MULT = 142
EC_F_EC_GROUP_SET_CURVE_GF2M = 176
EC_F_EC_GROUP_SET_CURVE_GFP = 109
EC_F_EC_GROUP_SET_EXTRA_DATA = 110
EC_F_EC_GROUP_SET_GENERATOR = 111
EC_F_EC_KEY_CHECK_KEY = 177
EC_F_EC_KEY_COPY = 178
EC_F_EC_KEY_GENERATE_KEY = 179
EC_F_EC_KEY_NEW = 182
EC_F_EC_KEY_PRINT = 180
EC_F_EC_KEY_PRINT_FP = 181
EC_F_EC_KEY_SET_PUBLIC_KEY_AFFINE_COORDINATES = 229
EC_F_EC_POINT_ADD = 112
EC_F_EC_POINT_CMP = 113
EC_F_EC_POINT_COPY = 114
EC_F_EC_POINT_DBL = 115
EC_F_EC_POINT_GET_AFFINE_COORDINATES_GF2M = 183
EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP = 116
EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP = 117
EC_F_EC_POINT_INVERT = 210
EC_F_EC_POINT_IS_AT_INFINITY = 118
EC_F_EC_POINT_IS_ON_CURVE = 119
EC_F_EC_POINT_MAKE_AFFINE = 120
EC_F_EC_POINT_MUL = 184
EC_F_EC_POINT_NEW = 121
EC_F_EC_POINT_OCT2POINT = 122
EC_F_EC_POINT_POINT2OCT = 123
EC_F_EC_POINT_SET_AFFINE_COORDINATES_GF2M = 185
EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP = 124
EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GF2M = 186
EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GFP = 125
EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP = 126
EC_F_EC_POINT_SET_TO_INFINITY = 127
EC_F_EC_POINTS_MAKE_AFFINE = 136
EC_F_EC_PRE_COMP_DUP = 207
EC_F_EC_PRE_COMP_NEW = 196
EC_F_EC_WNAF_MUL = 187
EC_F_EC_WNAF_PRECOMPUTE_MULT = 188
EC_F_ECKEY_PARAM2TYPE = 223
EC_F_ECKEY_PARAM_DECODE = 212
EC_F_ECKEY_PRIV_DECODE = 213
EC_F_ECKEY_PRIV_ENCODE = 214
EC_F_ECKEY_PUB_DECODE = 215
EC_F_ECKEY_PUB_ENCODE = 216
EC_F_ECKEY_TYPE2PARAM = 220
EC_F_ECP_NIST_MOD_192 = 203
EC_F_ECP_NIST_MOD_224 = 204
EC_F_ECP_NIST_MOD_256 = 205
EC_F_ECP_NIST_MOD_521 = 206
EC_F_ECPARAMETERS_PRINT = 147
EC_F_ECPARAMETERS_PRINT_FP = 148
EC_F_ECPKPARAMETERS_PRINT = 149
EC_F_ECPKPARAMETERS_PRINT_FP = 150
EC_F_I2D_ECPARAMETERS = 190
EC_F_I2D_ECPKPARAMETERS = 191
EC_F_I2D_ECPRIVATEKEY = 192
EC_F_I2O_ECPUBLICKEY = 151
EC_F_NISTP224_PRE_COMP_NEW = 227
EC_F_NISTP256_PRE_COMP_NEW = 236
EC_F_NISTP521_PRE_COMP_NEW = 237
EC_F_O2I_ECPUBLICKEY = 152
EC_F_OLD_EC_PRIV_DECODE = 222
EC_F_PKEY_EC_CTRL = 197
EC_F_PKEY_EC_CTRL_STR = 198
EC_F_PKEY_EC_DERIVE = 217
EC_F_PKEY_EC_KEYGEN = 199
EC_F_PKEY_EC_PARAMGEN = 219
EC_F_PKEY_EC_SIGN = 218
EC_FLAG_FIPS_CHECKED = 0x2
EC_FLAG_NON_FIPS_ALLOW = 0x1
EC_PKEY_NO_PARAMETERS = 0x001
EC_PKEY_NO_PUBKEY = 0x002
EC_R_ASN1_ERROR = 115
EC_R_ASN1_UNKNOWN_FIELD = 116
EC_R_BIGNUM_OUT_OF_RANGE = 144
EC_R_BUFFER_TOO_SMALL = 100
EC_R_COORDINATES_OUT_OF_RANGE = 146
EC_R_D2I_ECPKPARAMETERS_FAILURE = 117
EC_R_DECODE_ERROR = 142
EC_R_DISCRIMINANT_IS_ZERO = 118
EC_R_EC_GROUP_NEW_BY_NAME_FAILURE = 119
EC_R_FIELD_TOO_LARGE = 143
EC_R_GF2M_NOT_SUPPORTED = 147
EC_R_GROUP2PKPARAMETERS_FAILURE = 120
EC_R_I2D_ECPKPARAMETERS_FAILURE = 121
EC_R_INCOMPATIBLE_OBJECTS = 101
EC_R_INVALID_ARGUMENT = 112
EC_R_INVALID_COMPRESSED_POINT = 110
EC_R_INVALID_COMPRESSION_BIT = 109
EC_R_INVALID_CURVE = 141
EC_R_INVALID_DIGEST_TYPE = 138
EC_R_INVALID_ENCODING = 102
EC_R_INVALID_FIELD = 103
EC_R_INVALID_FORM = 104
EC_R_INVALID_GROUP_ORDER = 122
EC_R_INVALID_PENTANOMIAL_BASIS = 132
EC_R_INVALID_PRIVATE_KEY = 123
EC_R_INVALID_TRINOMIAL_BASIS = 137
EC_R_KEYS_NOT_SET = 140
EC_R_MISSING_PARAMETERS = 124
EC_R_MISSING_PRIVATE_KEY = 125
EC_R_NO_FIELD_MOD = 133
EC_R_NO_PARAMETERS_SET = 139
EC_R_NOT_A_NIST_PRIME = 135
EC_R_NOT_A_SUPPORTED_NIST_PRIME = 136
EC_R_NOT_IMPLEMENTED = 126
EC_R_NOT_INITIALIZED = 111
EC_R_PASSED_NULL_PARAMETER = 134
EC_R_PKPARAMETERS2GROUP_FAILURE = 127
EC_R_POINT_AT_INFINITY = 106
EC_R_POINT_IS_NOT_ON_CURVE = 107
EC_R_SLOT_FULL = 108
EC_R_UNDEFINED_GENERATOR = 113
EC_R_UNDEFINED_ORDER = 128
EC_R_UNKNOWN_GROUP = 129
EC_R_UNKNOWN_ORDER = 114
EC_R_UNSUPPORTED_FIELD = 131
EC_R_WRONG_CURVE_PARAMETERS = 145
EC_R_WRONG_ORDER = 130
