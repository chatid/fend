include "stdio"

require "ffi".cdef [[
extern int *__errno_location (void) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));

typedef struct err_state_st
 {
 CRYPTO_THREADID tid;
 int err_flags[16];
 unsigned long err_buffer[16];
 char *err_data[16];
 int err_data_flags[16];
 const char *err_file[16];
 int err_line[16];
 int top,bottom;
 } ERR_STATE;
typedef struct ERR_string_data_st
 {
 unsigned long error;
 const char *string;
 } ERR_STRING_DATA;
void ERR_put_error(int lib, int func,int reason,const char *file,int line);
void ERR_set_error_data(char *data,int flags);
unsigned long ERR_get_error(void);
unsigned long ERR_get_error_line(const char **file,int *line);
unsigned long ERR_get_error_line_data(const char **file,int *line,
          const char **data, int *flags);
unsigned long ERR_peek_error(void);
unsigned long ERR_peek_error_line(const char **file,int *line);
unsigned long ERR_peek_error_line_data(const char **file,int *line,
           const char **data,int *flags);
unsigned long ERR_peek_last_error(void);
unsigned long ERR_peek_last_error_line(const char **file,int *line);
unsigned long ERR_peek_last_error_line_data(const char **file,int *line,
           const char **data,int *flags);
void ERR_clear_error(void );
char *ERR_error_string(unsigned long e,char *buf);
void ERR_error_string_n(unsigned long e, char *buf, size_t len);
const char *ERR_lib_error_string(unsigned long e);
const char *ERR_func_error_string(unsigned long e);
const char *ERR_reason_error_string(unsigned long e);
void ERR_print_errors_cb(int (*cb)(const char *str, size_t len, void *u),
    void *u);
void ERR_print_errors_fp(FILE *fp);
void ERR_print_errors(BIO *bp);
void ERR_add_error_data(int num, ...);
void ERR_add_error_vdata(int num, va_list args);
void ERR_load_strings(int lib,ERR_STRING_DATA str[]);
void ERR_unload_strings(int lib,ERR_STRING_DATA str[]);
void ERR_load_ERR_strings(void);
void ERR_load_crypto_strings(void);
void ERR_free_strings(void);
void ERR_remove_thread_state(const CRYPTO_THREADID *tid);
void ERR_remove_state(unsigned long pid);
ERR_STATE *ERR_get_state(void);
struct lhash_st_ERR_STRING_DATA *ERR_get_string_table(void);
struct lhash_st_ERR_STATE *ERR_get_err_state_table(void);
void ERR_release_err_state_table(struct lhash_st_ERR_STATE **hash);
int ERR_get_next_error_library(void);
int ERR_set_mark(void);
int ERR_pop_to_mark(void);
const ERR_FNS *ERR_get_implementation(void);
int ERR_set_implementation(const ERR_FNS *fns);
]]
