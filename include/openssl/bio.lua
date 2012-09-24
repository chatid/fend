local ffi = require "ffi"

include "openssl/e_os2"
include "stdio"
include "openssl/crypto"

ffi.cdef[[
typedef struct bio_st BIO;
void BIO_set_flags(BIO *b, int flags);
int BIO_test_flags(const BIO *b, int flags);
void BIO_clear_flags(BIO *b, int flags);
long (*BIO_get_callback(const BIO *b)) (struct bio_st *,int,const char *,int, long,long);
void BIO_set_callback(BIO *b,
 long (*callback)(struct bio_st *,int,const char *,int, long,long));
char *BIO_get_callback_arg(const BIO *b);
void BIO_set_callback_arg(BIO *b, char *arg);
const char * BIO_method_name(const BIO *b);
int BIO_method_type(const BIO *b);
typedef void bio_info_cb(struct bio_st *, int, const char *, int, long, long);
typedef struct bio_method_st
 {
 int type;
 const char *name;
 int (*bwrite)(BIO *, const char *, int);
 int (*bread)(BIO *, char *, int);
 int (*bputs)(BIO *, const char *);
 int (*bgets)(BIO *, char *, int);
 long (*ctrl)(BIO *, int, long, void *);
 int (*create)(BIO *);
 int (*destroy)(BIO *);
        long (*callback_ctrl)(BIO *, int, bio_info_cb *);
 } BIO_METHOD;
struct bio_st
 {
 BIO_METHOD *method;
 long (*callback)(struct bio_st *,int,const char *,int, long,long);
 char *cb_arg;
 int init;
 int shutdown;
 int flags;
 int retry_reason;
 int num;
 void *ptr;
 struct bio_st *next_bio;
 struct bio_st *prev_bio;
 int references;
 unsigned long num_read;
 unsigned long num_write;
 CRYPTO_EX_DATA ex_data;
 };
struct stack_st_BIO { _STACK stack; };
typedef struct bio_f_buffer_ctx_struct
 {
 int ibuf_size;
 int obuf_size;
 char *ibuf;
 int ibuf_len;
 int ibuf_off;
 char *obuf;
 int obuf_len;
 int obuf_off;
 } BIO_F_BUFFER_CTX;
typedef int asn1_ps_func(BIO *b, unsigned char **pbuf, int *plen, void *parg);
size_t BIO_ctrl_pending(BIO *b);
size_t BIO_ctrl_wpending(BIO *b);
size_t BIO_ctrl_get_write_guarantee(BIO *b);
size_t BIO_ctrl_get_read_request(BIO *b);
int BIO_ctrl_reset_read_request(BIO *b);
int BIO_set_ex_data(BIO *bio,int idx,void *data);
void *BIO_get_ex_data(BIO *bio,int idx);
int BIO_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
 CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
unsigned long BIO_number_read(BIO *bio);
unsigned long BIO_number_written(BIO *bio);
int BIO_asn1_set_prefix(BIO *b, asn1_ps_func *prefix,
     asn1_ps_func *prefix_free);
int BIO_asn1_get_prefix(BIO *b, asn1_ps_func **pprefix,
     asn1_ps_func **pprefix_free);
int BIO_asn1_set_suffix(BIO *b, asn1_ps_func *suffix,
     asn1_ps_func *suffix_free);
int BIO_asn1_get_suffix(BIO *b, asn1_ps_func **psuffix,
     asn1_ps_func **psuffix_free);
BIO_METHOD *BIO_s_file(void );
BIO *BIO_new_file(const char *filename, const char *mode);
BIO *BIO_new_fp(FILE *stream, int close_flag);
BIO * BIO_new(BIO_METHOD *type);
int BIO_set(BIO *a,BIO_METHOD *type);
int BIO_free(BIO *a);
void BIO_vfree(BIO *a);
int BIO_read(BIO *b, void *data, int len);
int BIO_gets(BIO *bp,char *buf, int size);
int BIO_write(BIO *b, const void *data, int len);
int BIO_puts(BIO *bp,const char *buf);
int BIO_indent(BIO *b,int indent,int max);
long BIO_ctrl(BIO *bp,int cmd,long larg,void *parg);
long BIO_callback_ctrl(BIO *b, int cmd, void (*fp)(struct bio_st *, int, const char *, int, long, long));
char * BIO_ptr_ctrl(BIO *bp,int cmd,long larg);
long BIO_int_ctrl(BIO *bp,int cmd,long larg,int iarg);
BIO * BIO_push(BIO *b,BIO *append);
BIO * BIO_pop(BIO *b);
void BIO_free_all(BIO *a);
BIO * BIO_find_type(BIO *b,int bio_type);
BIO * BIO_next(BIO *b);
BIO * BIO_get_retry_BIO(BIO *bio, int *reason);
int BIO_get_retry_reason(BIO *bio);
BIO * BIO_dup_chain(BIO *in);
int BIO_nread0(BIO *bio, char **buf);
int BIO_nread(BIO *bio, char **buf, int num);
int BIO_nwrite0(BIO *bio, char **buf);
int BIO_nwrite(BIO *bio, char **buf, int num);
long BIO_debug_callback(BIO *bio,int cmd,const char *argp,int argi,
 long argl,long ret);
BIO_METHOD *BIO_s_mem(void);
BIO *BIO_new_mem_buf(void *buf, int len);
BIO_METHOD *BIO_s_socket(void);
BIO_METHOD *BIO_s_connect(void);
BIO_METHOD *BIO_s_accept(void);
BIO_METHOD *BIO_s_fd(void);
BIO_METHOD *BIO_s_log(void);
BIO_METHOD *BIO_s_bio(void);
BIO_METHOD *BIO_s_null(void);
BIO_METHOD *BIO_f_null(void);
BIO_METHOD *BIO_f_buffer(void);
BIO_METHOD *BIO_f_nbio_test(void);
BIO_METHOD *BIO_s_datagram(void);
int BIO_sock_should_retry(int i);
int BIO_sock_non_fatal_error(int error);
int BIO_dgram_non_fatal_error(int error);
int BIO_fd_should_retry(int i);
int BIO_fd_non_fatal_error(int error);
int BIO_dump_cb(int (*cb)(const void *data, size_t len, void *u),
  void *u, const char *s, int len);
int BIO_dump_indent_cb(int (*cb)(const void *data, size_t len, void *u),
         void *u, const char *s, int len, int indent);
int BIO_dump(BIO *b,const char *bytes,int len);
int BIO_dump_indent(BIO *b,const char *bytes,int len,int indent);
int BIO_dump_fp(FILE *fp, const char *s, int len);
int BIO_dump_indent_fp(FILE *fp, const char *s, int len, int indent);
struct hostent *BIO_gethostbyname(const char *name);
int BIO_sock_error(int sock);
int BIO_socket_ioctl(int fd, long type, void *arg);
int BIO_socket_nbio(int fd,int mode);
int BIO_get_port(const char *str, unsigned short *port_ptr);
int BIO_get_host_ip(const char *str, unsigned char *ip);
int BIO_get_accept_socket(char *host_port,int mode);
int BIO_accept(int sock,char **ip_port);
int BIO_sock_init(void );
void BIO_sock_cleanup(void);
int BIO_set_tcp_ndelay(int sock,int turn_on);
BIO *BIO_new_socket(int sock, int close_flag);
BIO *BIO_new_dgram(int fd, int close_flag);
BIO *BIO_new_fd(int fd, int close_flag);
BIO *BIO_new_connect(char *host_port);
BIO *BIO_new_accept(char *host_port);
int BIO_new_bio_pair(BIO **bio1, size_t writebuf1,
 BIO **bio2, size_t writebuf2);
void BIO_copy_next_retry(BIO *b);
int BIO_printf(BIO *bio, const char *format, ...)
 __attribute__((__format__(__printf__,2,3)));
int BIO_vprintf(BIO *bio, const char *format, va_list args)
 __attribute__((__format__(__printf__,2,0)));
int BIO_snprintf(char *buf, size_t n, const char *format, ...)
 __attribute__((__format__(__printf__,3,4)));
int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
 __attribute__((__format__(__printf__,3,0)));
void ERR_load_BIO_strings(void);
]]

module ( ... )

BIO_BIND_NORMAL = 0
BIO_BIND_REUSEADDR = 2
BIO_BIND_REUSEADDR_IF_UNUSED = 1
BIO_C_DESTROY_BIO_PAIR = 139
BIO_C_DO_STATE_MACHINE = 101
BIO_C_FILE_SEEK = 128
BIO_C_FILE_TELL = 133
BIO_C_GET_ACCEPT = 124
BIO_C_GET_BIND_MODE = 132
BIO_C_GET_BUF_MEM_PTR = 115
BIO_C_GET_BUFF_NUM_LINES = 116
BIO_C_GET_CIPHER_CTX = 129
BIO_C_GET_CIPHER_STATUS = 113
BIO_C_GET_CONNECT = 123
BIO_C_GET_EX_ARG = 154
BIO_C_GET_FD = 105
BIO_C_GET_FILE_PTR = 107
BIO_C_GET_MD = 112
BIO_C_GET_MD_CTX = 120
BIO_C_GET_PREFIX = 150
BIO_C_GET_PROXY_PARAM = 121
BIO_C_GET_READ_REQUEST = 141
BIO_C_GET_SOCKS = 134
BIO_C_GET_SSL = 110
BIO_C_GET_SSL_NUM_RENEGOTIATES = 126
BIO_C_GET_SUFFIX = 152
BIO_C_GET_WRITE_BUF_SIZE = 137
BIO_C_GET_WRITE_GUARANTEE = 140
BIO_C_MAKE_BIO_PAIR = 138
BIO_C_NREAD = 144
BIO_C_NREAD0 = 143
BIO_C_NWRITE = 146
BIO_C_NWRITE0 = 145
BIO_C_RESET_READ_REQUEST = 147
BIO_C_SET_ACCEPT = 118
BIO_C_SET_BIND_MODE = 131
BIO_C_SET_BUF_MEM = 114
BIO_C_SET_BUF_MEM_EOF_RETURN = 130
BIO_C_SET_BUFF_READ_DATA = 122
BIO_C_SET_BUFF_SIZE = 117
BIO_C_SET_CONNECT = 100
BIO_C_SET_EX_ARG = 153
BIO_C_SET_FD = 104
BIO_C_SET_FILE_PTR = 106
BIO_C_SET_FILENAME = 108
BIO_C_SET_MD = 111
BIO_C_SET_MD_CTX = 148
BIO_C_SET_NBIO = 102
BIO_C_SET_PREFIX = 149
BIO_C_SET_PROXY_PARAM = 103
BIO_C_SET_SOCKS = 135
BIO_C_SET_SSL = 109
BIO_C_SET_SSL_RENEGOTIATE_BYTES = 125
BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT = 127
BIO_C_SET_SUFFIX = 151
BIO_C_SET_WRITE_BUF_SIZE = 136
BIO_C_SHUTDOWN_WR = 142
BIO_C_SSL_MODE = 119
BIO_CB_CTRL = 0x06
BIO_CB_FREE = 0x01
BIO_CB_GETS = 0x05
BIO_CB_PUTS = 0x04
BIO_CB_READ = 0x02
BIO_CB_RETURN = 0x80
BIO_CB_WRITE = 0x03
BIO_CLOSE = 0x01
BIO_CONN_S_BEFORE = 1
BIO_CONN_S_BLOCKED_CONNECT = 7
BIO_CONN_S_CONNECT = 5
BIO_CONN_S_CREATE_SOCKET = 4
BIO_CONN_S_GET_IP = 2
BIO_CONN_S_GET_PORT = 3
BIO_CONN_S_NBIO = 8
BIO_CONN_S_OK = 6
BIO_CTRL_DGRAM_CONNECT = 31
BIO_CTRL_DGRAM_GET_FALLBACK_MTU = 47
BIO_CTRL_DGRAM_GET_MTU = 41
BIO_CTRL_DGRAM_GET_PEER = 46
BIO_CTRL_DGRAM_GET_RECV_TIMEOUT = 34
BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP = 37
BIO_CTRL_DGRAM_GET_SEND_TIMEOUT = 36
BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP = 38
BIO_CTRL_DGRAM_MTU_DISCOVER = 39
BIO_CTRL_DGRAM_MTU_EXCEEDED = 43
BIO_CTRL_DGRAM_QUERY_MTU = 40
BIO_CTRL_DGRAM_SET_CONNECTED = 32
BIO_CTRL_DGRAM_SET_MTU = 42
BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT = 45
BIO_CTRL_DGRAM_SET_PEER = 44
BIO_CTRL_DGRAM_SET_RECV_TIMEOUT = 33
BIO_CTRL_DGRAM_SET_SEND_TIMEOUT = 35
BIO_CTRL_DUP = 12
BIO_CTRL_EOF = 2
BIO_CTRL_FLUSH = 11
BIO_CTRL_GET = 5
BIO_CTRL_GET_CALLBACK = 15
BIO_CTRL_GET_CLOSE = 8
BIO_CTRL_INFO = 3
BIO_CTRL_PENDING = 10
BIO_CTRL_POP = 7
BIO_CTRL_PUSH = 6
BIO_CTRL_RESET = 1
BIO_CTRL_SET = 4
BIO_CTRL_SET_CALLBACK = 14
BIO_CTRL_SET_CLOSE = 9
BIO_CTRL_SET_FILENAME = 30
BIO_CTRL_WPENDING = 13
BIO_F_ACPT_STATE = 100
BIO_F_BIO_ACCEPT = 101
BIO_F_BIO_BER_GET_HEADER = 102
BIO_F_BIO_CALLBACK_CTRL = 131
BIO_F_BIO_CTRL = 103
BIO_F_BIO_GET_ACCEPT_SOCKET = 105
BIO_F_BIO_GET_HOST_IP = 106
BIO_F_BIO_GET_PORT = 107
BIO_F_BIO_GETHOSTBYNAME = 120
BIO_F_BIO_GETS = 104
BIO_F_BIO_MAKE_PAIR = 121
BIO_F_BIO_NEW = 108
BIO_F_BIO_NEW_FILE = 109
BIO_F_BIO_NEW_MEM_BUF = 126
BIO_F_BIO_NREAD = 123
BIO_F_BIO_NREAD0 = 124
BIO_F_BIO_NWRITE = 125
BIO_F_BIO_NWRITE0 = 122
BIO_F_BIO_PUTS = 110
BIO_F_BIO_READ = 111
BIO_F_BIO_SOCK_INIT = 112
BIO_F_BIO_WRITE = 113
BIO_F_BUFFER_CTRL = 114
BIO_F_CONN_CTRL = 127
BIO_F_CONN_STATE = 115
BIO_F_DGRAM_SCTP_READ = 132
BIO_F_FILE_CTRL = 116
BIO_F_FILE_READ = 130
BIO_F_LINEBUFFER_CTRL = 129
BIO_F_MEM_READ = 128
BIO_F_MEM_WRITE = 117
BIO_F_SSL_NEW = 118
BIO_F_WSASTARTUP = 119
BIO_FLAGS_BASE64_NO_NL = 0x100
BIO_FLAGS_IO_SPECIAL = 0x04
BIO_FLAGS_MEM_RDONLY = 0x200
BIO_FLAGS_READ = 0x01
BIO_FLAGS_SHOULD_RETRY = 0x08
BIO_FLAGS_UPLINK = 0
BIO_FLAGS_WRITE = 0x02
BIO_FP_APPEND = 0x08
BIO_FP_READ = 0x02
BIO_FP_TEXT = 0x10
BIO_FP_WRITE = 0x04
BIO_GHBN_CTRL_CACHE_SIZE = 3
BIO_GHBN_CTRL_FLUSH = 5
BIO_GHBN_CTRL_GET_ENTRY = 4
BIO_GHBN_CTRL_HITS = 1
BIO_GHBN_CTRL_MISSES = 2
BIO_NOCLOSE = 0x00
BIO_R_ACCEPT_ERROR = 100
BIO_R_BAD_FOPEN_MODE = 101
BIO_R_BAD_HOSTNAME_LOOKUP = 102
BIO_R_BROKEN_PIPE = 124
BIO_R_CONNECT_ERROR = 103
BIO_R_EOF_ON_MEMORY_BIO = 127
BIO_R_ERROR_SETTING_NBIO = 104
BIO_R_ERROR_SETTING_NBIO_ON_ACCEPT_SOCKET = 106
BIO_R_ERROR_SETTING_NBIO_ON_ACCEPTED_SOCKET = 105
BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET = 107
BIO_R_IN_USE = 123
BIO_R_INVALID_ARGUMENT = 125
BIO_R_INVALID_IP_ADDRESS = 108
BIO_R_KEEPALIVE = 109
BIO_R_NBIO_CONNECT_ERROR = 110
BIO_R_NO_ACCEPT_PORT_SPECIFIED = 111
BIO_R_NO_HOSTNAME_SPECIFIED = 112
BIO_R_NO_PORT_DEFINED = 113
BIO_R_NO_PORT_SPECIFIED = 114
BIO_R_NO_SUCH_FILE = 128
BIO_R_NULL_PARAMETER = 115
BIO_R_TAG_MISMATCH = 116
BIO_R_UNABLE_TO_BIND_SOCKET = 117
BIO_R_UNABLE_TO_CREATE_SOCKET = 118
BIO_R_UNABLE_TO_LISTEN_SOCKET = 119
BIO_R_UNINITIALIZED = 120
BIO_R_UNSUPPORTED_METHOD = 121
BIO_R_WRITE_TO_READ_ONLY_BIO = 126
BIO_R_WSASTARTUP = 122
BIO_RR_ACCEPT = 0x03
BIO_RR_CONNECT = 0x02
BIO_RR_SSL_X509_LOOKUP = 0x01
BIO_s_file_internal = BIO_s_file
BIO_TYPE_DESCRIPTOR = 0x0100
BIO_TYPE_FILTER = 0x0200
BIO_TYPE_NONE = 0
BIO_TYPE_SOURCE_SINK = 0x0400

return _M
