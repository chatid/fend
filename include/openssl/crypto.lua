local ffi = require "ffi"

include "stdlib"
include "stdio"
include "openssl/e_os2"
include "openssl/stack"
include "openssl/safestack"
include "openssl/opensslv"
include "openssl/ossl_typ"

ffi.cdef[[
typedef struct openssl_item_st
 {
 int code;
 void *value;
 size_t value_size;
 size_t *value_length;
 } OPENSSL_ITEM;
typedef struct
 {
 int references;
 struct CRYPTO_dynlock_value *data;
 } CRYPTO_dynlock;
typedef struct bio_st BIO_dummy;
struct crypto_ex_data_st
 {
 struct stack_st_void *sk;
 int dummy;
 };
struct stack_st_void { _STACK stack; };
typedef struct crypto_ex_data_func_st
 {
 long argl;
 void *argp;
 CRYPTO_EX_new *new_func;
 CRYPTO_EX_free *free_func;
 CRYPTO_EX_dup *dup_func;
 } CRYPTO_EX_DATA_FUNCS;
struct stack_st_CRYPTO_EX_DATA_FUNCS { _STACK stack; };
int CRYPTO_mem_ctrl(int mode);
int CRYPTO_is_mem_check_on(void);
const char *SSLeay_version(int type);
unsigned long SSLeay(void);
int OPENSSL_issetugid(void);
typedef struct st_CRYPTO_EX_DATA_IMPL CRYPTO_EX_DATA_IMPL;
const CRYPTO_EX_DATA_IMPL *CRYPTO_get_ex_data_implementation(void);
int CRYPTO_set_ex_data_implementation(const CRYPTO_EX_DATA_IMPL *i);
int CRYPTO_ex_data_new_class(void);
int CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
  CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
  CRYPTO_EX_free *free_func);
int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
int CRYPTO_dup_ex_data(int class_index, CRYPTO_EX_DATA *to,
  CRYPTO_EX_DATA *from);
void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
int CRYPTO_set_ex_data(CRYPTO_EX_DATA *ad, int idx, void *val);
void *CRYPTO_get_ex_data(const CRYPTO_EX_DATA *ad,int idx);
void CRYPTO_cleanup_all_ex_data(void);
int CRYPTO_get_new_lockid(char *name);
int CRYPTO_num_locks(void);
void CRYPTO_lock(int mode, int type,const char *file,int line);
void CRYPTO_set_locking_callback(void (*func)(int mode,int type,
           const char *file,int line));
void (*CRYPTO_get_locking_callback(void))(int mode,int type,const char *file,
  int line);
void CRYPTO_set_add_lock_callback(int (*func)(int *num,int mount,int type,
           const char *file, int line));
int (*CRYPTO_get_add_lock_callback(void))(int *num,int mount,int type,
       const char *file,int line);
typedef struct crypto_threadid_st
 {
 void *ptr;
 unsigned long val;
 } CRYPTO_THREADID;
void CRYPTO_THREADID_set_numeric(CRYPTO_THREADID *id, unsigned long val);
void CRYPTO_THREADID_set_pointer(CRYPTO_THREADID *id, void *ptr);
int CRYPTO_THREADID_set_callback(void (*threadid_func)(CRYPTO_THREADID *));
void (*CRYPTO_THREADID_get_callback(void))(CRYPTO_THREADID *);
void CRYPTO_THREADID_current(CRYPTO_THREADID *id);
int CRYPTO_THREADID_cmp(const CRYPTO_THREADID *a, const CRYPTO_THREADID *b);
void CRYPTO_THREADID_cpy(CRYPTO_THREADID *dest, const CRYPTO_THREADID *src);
unsigned long CRYPTO_THREADID_hash(const CRYPTO_THREADID *id);
void CRYPTO_set_id_callback(unsigned long (*func)(void));
unsigned long (*CRYPTO_get_id_callback(void))(void);
unsigned long CRYPTO_thread_id(void);
const char *CRYPTO_get_lock_name(int type);
int CRYPTO_add_lock(int *pointer,int amount,int type, const char *file,
      int line);
int CRYPTO_get_new_dynlockid(void);
void CRYPTO_destroy_dynlockid(int i);
struct CRYPTO_dynlock_value *CRYPTO_get_dynlock_value(int i);
void CRYPTO_set_dynlock_create_callback(struct CRYPTO_dynlock_value *(*dyn_create_function)(const char *file, int line));
void CRYPTO_set_dynlock_lock_callback(void (*dyn_lock_function)(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line));
void CRYPTO_set_dynlock_destroy_callback(void (*dyn_destroy_function)(struct CRYPTO_dynlock_value *l, const char *file, int line));
struct CRYPTO_dynlock_value *(*CRYPTO_get_dynlock_create_callback(void))(const char *file,int line);
void (*CRYPTO_get_dynlock_lock_callback(void))(int mode, struct CRYPTO_dynlock_value *l, const char *file,int line);
void (*CRYPTO_get_dynlock_destroy_callback(void))(struct CRYPTO_dynlock_value *l, const char *file,int line);
int CRYPTO_set_mem_functions(void *(*m)(size_t),void *(*r)(void *,size_t), void (*f)(void *));
int CRYPTO_set_locked_mem_functions(void *(*m)(size_t), void (*free_func)(void *));
int CRYPTO_set_mem_ex_functions(void *(*m)(size_t,const char *,int),
                                void *(*r)(void *,size_t,const char *,int),
                                void (*f)(void *));
int CRYPTO_set_locked_mem_ex_functions(void *(*m)(size_t,const char *,int),
                                       void (*free_func)(void *));
int CRYPTO_set_mem_debug_functions(void (*m)(void *,int,const char *,int,int),
       void (*r)(void *,void *,int,const char *,int,int),
       void (*f)(void *,int),
       void (*so)(long),
       long (*go)(void));
void CRYPTO_get_mem_functions(void *(**m)(size_t),void *(**r)(void *, size_t), void (**f)(void *));
void CRYPTO_get_locked_mem_functions(void *(**m)(size_t), void (**f)(void *));
void CRYPTO_get_mem_ex_functions(void *(**m)(size_t,const char *,int),
                                 void *(**r)(void *, size_t,const char *,int),
                                 void (**f)(void *));
void CRYPTO_get_locked_mem_ex_functions(void *(**m)(size_t,const char *,int),
                                        void (**f)(void *));
void CRYPTO_get_mem_debug_functions(void (**m)(void *,int,const char *,int,int),
        void (**r)(void *,void *,int,const char *,int,int),
        void (**f)(void *,int),
        void (**so)(long),
        long (**go)(void));
void *CRYPTO_malloc_locked(int num, const char *file, int line);
void CRYPTO_free_locked(void *);
void *CRYPTO_malloc(int num, const char *file, int line);
char *CRYPTO_strdup(const char *str, const char *file, int line);
void CRYPTO_free(void *);
void *CRYPTO_realloc(void *addr,int num, const char *file, int line);
void *CRYPTO_realloc_clean(void *addr,int old_num,int num,const char *file,
      int line);
void *CRYPTO_remalloc(void *addr,int num, const char *file, int line);
void OPENSSL_cleanse(void *ptr, size_t len);
void CRYPTO_set_mem_debug_options(long bits);
long CRYPTO_get_mem_debug_options(void);
int CRYPTO_push_info_(const char *info, const char *file, int line);
int CRYPTO_pop_info(void);
int CRYPTO_remove_all_info(void);
void CRYPTO_dbg_malloc(void *addr,int num,const char *file,int line,int before_p);
void CRYPTO_dbg_realloc(void *addr1,void *addr2,int num,const char *file,int line,int before_p);
void CRYPTO_dbg_free(void *addr,int before_p);
void CRYPTO_dbg_set_options(long bits);
long CRYPTO_dbg_get_options(void);
void CRYPTO_mem_leaks_fp(FILE *);
void CRYPTO_mem_leaks(struct bio_st *bio);
typedef void *CRYPTO_MEM_LEAK_CB(unsigned long, const char *, int, int, void *);
void CRYPTO_mem_leaks_cb(CRYPTO_MEM_LEAK_CB *cb);
void OpenSSLDie(const char *file,int line,const char *assertion);
unsigned long *OPENSSL_ia32cap_loc(void);
int OPENSSL_isservice(void);
int FIPS_mode(void);
int FIPS_mode_set(int r);
void OPENSSL_init(void);
void ERR_load_CRYPTO_strings(void);
]]

module ( ... )

CRYPTO_EX_INDEX_BIO = 0
CRYPTO_EX_INDEX_COMP = 14
CRYPTO_EX_INDEX_DH = 8
CRYPTO_EX_INDEX_DSA = 7
CRYPTO_EX_INDEX_ECDH = 13
CRYPTO_EX_INDEX_ECDSA = 12
CRYPTO_EX_INDEX_ENGINE = 9
CRYPTO_EX_INDEX_RSA = 6
CRYPTO_EX_INDEX_SSL = 1
CRYPTO_EX_INDEX_SSL_CTX = 2
CRYPTO_EX_INDEX_SSL_SESSION = 3
CRYPTO_EX_INDEX_STORE = 15
CRYPTO_EX_INDEX_UI = 11
CRYPTO_EX_INDEX_USER = 100
CRYPTO_EX_INDEX_X509 = 10
CRYPTO_EX_INDEX_X509_STORE = 4
CRYPTO_EX_INDEX_X509_STORE_CTX = 5
CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX = 100
CRYPTO_F_CRYPTO_GET_NEW_DYNLOCKID = 103
CRYPTO_F_CRYPTO_GET_NEW_LOCKID = 101
CRYPTO_F_CRYPTO_SET_EX_DATA = 102
CRYPTO_F_DEF_ADD_INDEX = 104
CRYPTO_F_DEF_GET_CLASS = 105
CRYPTO_F_FIPS_MODE_SET = 109
CRYPTO_F_INT_DUP_EX_DATA = 106
CRYPTO_F_INT_FREE_EX_DATA = 107
CRYPTO_F_INT_NEW_EX_DATA = 108
CRYPTO_LOCK = 1
CRYPTO_LOCK_BIO = 21
CRYPTO_LOCK_BN = 35
CRYPTO_LOCK_COMP = 38
CRYPTO_LOCK_DH = 26
CRYPTO_LOCK_DSA = 8
CRYPTO_LOCK_DSO = 28
CRYPTO_LOCK_DYNLOCK = 29
CRYPTO_LOCK_EC = 33
CRYPTO_LOCK_EC_PRE_COMP = 36
CRYPTO_LOCK_ECDH = 34
CRYPTO_LOCK_ECDSA = 32
CRYPTO_LOCK_ENGINE = 30
CRYPTO_LOCK_ERR = 1
CRYPTO_LOCK_EVP_PKEY = 10
CRYPTO_LOCK_EX_DATA = 2
CRYPTO_LOCK_FIPS = 39
CRYPTO_LOCK_FIPS2 = 40
CRYPTO_LOCK_GETHOSTBYNAME = 22
CRYPTO_LOCK_GETSERVBYNAME = 23
CRYPTO_LOCK_MALLOC = 20
CRYPTO_LOCK_MALLOC2 = 27
CRYPTO_LOCK_RAND = 18
CRYPTO_LOCK_RAND2 = 19
CRYPTO_LOCK_READDIR = 24
CRYPTO_LOCK_RSA = 9
CRYPTO_LOCK_RSA_BLINDING = 25
CRYPTO_LOCK_SSL = 16
CRYPTO_LOCK_SSL_CERT = 13
CRYPTO_LOCK_SSL_CTX = 12
CRYPTO_LOCK_SSL_METHOD = 17
CRYPTO_LOCK_SSL_SESS_CERT = 15
CRYPTO_LOCK_SSL_SESSION = 14
CRYPTO_LOCK_STORE = 37
CRYPTO_LOCK_UI = 31
CRYPTO_LOCK_X509 = 3
CRYPTO_LOCK_X509_CRL = 6
CRYPTO_LOCK_X509_INFO = 4
CRYPTO_LOCK_X509_PKEY = 5
CRYPTO_LOCK_X509_REQ = 7
CRYPTO_LOCK_X509_STORE = 11
CRYPTO_MEM_CHECK_DISABLE = 0x3
CRYPTO_MEM_CHECK_ENABLE = 0x2
CRYPTO_MEM_CHECK_OFF = 0x0
CRYPTO_MEM_CHECK_ON = 0x1
CRYPTO_NUM_LOCKS = 41
CRYPTO_R_FIPS_MODE_NOT_SUPPORTED = 101
CRYPTO_R_NO_DYNLOCK_CREATE_CALLBACK = 100
CRYPTO_READ = 4
CRYPTO_UNLOCK = 2
CRYPTO_WRITE = 8

return _M
