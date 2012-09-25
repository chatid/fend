include "openssl/e_os2"
include "openssl/comp"
include "openssl/bio"
include "openssl/x509"
include "openssl/crypto"
include "openssl/lhash"
include "openssl/buffer"
include "openssl/pem"
include "openssl/hmac"
include "openssl/kssl"
include "openssl/safestack"
include "openssl/symhacks"

ffi.cdef[[
typedef struct ssl_st *ssl_crock_st;
typedef struct tls_session_ticket_ext_st TLS_SESSION_TICKET_EXT;
typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_cipher_st SSL_CIPHER;
typedef struct ssl_session_st SSL_SESSION;
struct stack_st_SSL_CIPHER { _STACK stack; };
typedef struct srtp_protection_profile_st
       {
       const char *name;
       unsigned long id;
       } SRTP_PROTECTION_PROFILE;
struct stack_st_SRTP_PROTECTION_PROFILE { _STACK stack; };
typedef int (*tls_session_ticket_ext_cb_fn)(SSL *s, const unsigned char *data, int len, void *arg);
typedef int (*tls_session_secret_cb_fn)(SSL *s, void *secret, int *secret_len, struct stack_st_SSL_CIPHER *peer_ciphers, SSL_CIPHER **cipher, void *arg);
struct ssl_cipher_st
 {
 int valid;
 const char *name;
 unsigned long id;
 unsigned long algorithm_mkey;
 unsigned long algorithm_auth;
 unsigned long algorithm_enc;
 unsigned long algorithm_mac;
 unsigned long algorithm_ssl;
 unsigned long algo_strength;
 unsigned long algorithm2;
 int strength_bits;
 int alg_bits;
 };
struct ssl_method_st
 {
 int version;
 int (*ssl_new)(SSL *s);
 void (*ssl_clear)(SSL *s);
 void (*ssl_free)(SSL *s);
 int (*ssl_accept)(SSL *s);
 int (*ssl_connect)(SSL *s);
 int (*ssl_read)(SSL *s,void *buf,int len);
 int (*ssl_peek)(SSL *s,void *buf,int len);
 int (*ssl_write)(SSL *s,const void *buf,int len);
 int (*ssl_shutdown)(SSL *s);
 int (*ssl_renegotiate)(SSL *s);
 int (*ssl_renegotiate_check)(SSL *s);
 long (*ssl_get_message)(SSL *s, int st1, int stn, int mt, long
  max, int *ok);
 int (*ssl_read_bytes)(SSL *s, int type, unsigned char *buf, int len,
  int peek);
 int (*ssl_write_bytes)(SSL *s, int type, const void *buf_, int len);
 int (*ssl_dispatch_alert)(SSL *s);
 long (*ssl_ctrl)(SSL *s,int cmd,long larg,void *parg);
 long (*ssl_ctx_ctrl)(SSL_CTX *ctx,int cmd,long larg,void *parg);
 const SSL_CIPHER *(*get_cipher_by_char)(const unsigned char *ptr);
 int (*put_cipher_by_char)(const SSL_CIPHER *cipher,unsigned char *ptr);
 int (*ssl_pending)(const SSL *s);
 int (*num_ciphers)(void);
 const SSL_CIPHER *(*get_cipher)(unsigned ncipher);
 const struct ssl_method_st *(*get_ssl_method)(int version);
 long (*get_timeout)(void);
 struct ssl3_enc_method *ssl3_enc;
 int (*ssl_version)(void);
 long (*ssl_callback_ctrl)(SSL *s, int cb_id, void (*fp)(void));
 long (*ssl_ctx_callback_ctrl)(SSL_CTX *s, int cb_id, void (*fp)(void));
 };
struct ssl_session_st
 {
 int ssl_version;
 unsigned int key_arg_length;
 unsigned char key_arg[8];
 int master_key_length;
 unsigned char master_key[48];
 unsigned int session_id_length;
 unsigned char session_id[32];
 unsigned int sid_ctx_length;
 unsigned char sid_ctx[32];
 char *psk_identity_hint;
 char *psk_identity;
 int not_resumable;
 struct sess_cert_st *sess_cert;
 X509 *peer;
 long verify_result;
 int references;
 long timeout;
 long time;
 unsigned int compress_meth;
 const SSL_CIPHER *cipher;
 unsigned long cipher_id;
 struct stack_st_SSL_CIPHER *ciphers;
 CRYPTO_EX_DATA ex_data;
 struct ssl_session_st *prev,*next;
 char *tlsext_hostname;
 size_t tlsext_ecpointformatlist_length;
 unsigned char *tlsext_ecpointformatlist;
 size_t tlsext_ellipticcurvelist_length;
 unsigned char *tlsext_ellipticcurvelist;
 unsigned char *tlsext_tick;
 size_t tlsext_ticklen;
 long tlsext_tick_lifetime_hint;
 char *srp_username;
 };
void SSL_CTX_set_msg_callback(SSL_CTX *ctx, void (*cb)(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg));
void SSL_set_msg_callback(SSL *ssl, void (*cb)(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg));
typedef struct srp_ctx_st
 {
 void *SRP_cb_arg;
 int (*TLS_ext_srp_username_callback)(SSL *, int *, void *);
 int (*SRP_verify_param_callback)(SSL *, void *);
 char *(*SRP_give_srp_client_pwd_callback)(SSL *, void *);
 char *login;
 BIGNUM *N,*g,*s,*B,*A;
 BIGNUM *a,*b,*v;
 char *info;
 int strength;
 unsigned long srp_Mask;
 } SRP_CTX;
int SSL_SRP_CTX_init(SSL *s);
int SSL_CTX_SRP_CTX_init(SSL_CTX *ctx);
int SSL_SRP_CTX_free(SSL *ctx);
int SSL_CTX_SRP_CTX_free(SSL_CTX *ctx);
int SSL_srp_server_param_with_username(SSL *s, int *ad);
int SRP_generate_server_master_secret(SSL *s,unsigned char *master_key);
int SRP_Calc_A_param(SSL *s);
int SRP_generate_client_master_secret(SSL *s,unsigned char *master_key);
typedef int (*GEN_SESSION_CB)(const SSL *ssl, unsigned char *id,
    unsigned int *id_len);
typedef struct ssl_comp_st SSL_COMP;
struct ssl_comp_st
 {
 int id;
 const char *name;
 COMP_METHOD *method;
 };
struct stack_st_SSL_COMP { _STACK stack; };
struct lhash_st_SSL_SESSION { int dummy; };
struct ssl_ctx_st
 {
 const SSL_METHOD *method;
 struct stack_st_SSL_CIPHER *cipher_list;
 struct stack_st_SSL_CIPHER *cipher_list_by_id;
 struct x509_store_st *cert_store;
 struct lhash_st_SSL_SESSION *sessions;
 unsigned long session_cache_size;
 struct ssl_session_st *session_cache_head;
 struct ssl_session_st *session_cache_tail;
 int session_cache_mode;
 long session_timeout;
 int (*new_session_cb)(struct ssl_st *ssl,SSL_SESSION *sess);
 void (*remove_session_cb)(struct ssl_ctx_st *ctx,SSL_SESSION *sess);
 SSL_SESSION *(*get_session_cb)(struct ssl_st *ssl,
  unsigned char *data,int len,int *copy);
 struct
  {
  int sess_connect;
  int sess_connect_renegotiate;
  int sess_connect_good;
  int sess_accept;
  int sess_accept_renegotiate;
  int sess_accept_good;
  int sess_miss;
  int sess_timeout;
  int sess_cache_full;
  int sess_hit;
  int sess_cb_hit;
  } stats;
 int references;
 int (*app_verify_callback)(X509_STORE_CTX *, void *);
 void *app_verify_arg;
 pem_password_cb *default_passwd_callback;
 void *default_passwd_callback_userdata;
 int (*client_cert_cb)(SSL *ssl, X509 **x509, EVP_PKEY **pkey);
    int (*app_gen_cookie_cb)(SSL *ssl, unsigned char *cookie,
        unsigned int *cookie_len);
    int (*app_verify_cookie_cb)(SSL *ssl, unsigned char *cookie,
        unsigned int cookie_len);
 CRYPTO_EX_DATA ex_data;
 const EVP_MD *rsa_md5;
 const EVP_MD *md5;
 const EVP_MD *sha1;
 struct stack_st_X509 *extra_certs;
 struct stack_st_SSL_COMP *comp_methods;
 void (*info_callback)(const SSL *ssl,int type,int val);
 struct stack_st_X509_NAME *client_CA;
 unsigned long options;
 unsigned long mode;
 long max_cert_list;
 struct cert_st *cert;
 int read_ahead;
 void (*msg_callback)(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
 void *msg_callback_arg;
 int verify_mode;
 unsigned int sid_ctx_length;
 unsigned char sid_ctx[32];
 int (*default_verify_callback)(int ok,X509_STORE_CTX *ctx);
 GEN_SESSION_CB generate_session_id;
 X509_VERIFY_PARAM *param;
 int quiet_shutdown;
 unsigned int max_send_fragment;
 ENGINE *client_cert_engine;
 int (*tlsext_servername_callback)(SSL*, int *, void *);
 void *tlsext_servername_arg;
 unsigned char tlsext_tick_key_name[16];
 unsigned char tlsext_tick_hmac_key[16];
 unsigned char tlsext_tick_aes_key[16];
 int (*tlsext_ticket_key_cb)(SSL *ssl,
     unsigned char *name, unsigned char *iv,
     EVP_CIPHER_CTX *ectx,
      HMAC_CTX *hctx, int enc);
 int (*tlsext_status_cb)(SSL *ssl, void *arg);
 void *tlsext_status_arg;
 int (*tlsext_opaque_prf_input_callback)(SSL *, void *peerinput, size_t len, void *arg);
 void *tlsext_opaque_prf_input_callback_arg;
 char *psk_identity_hint;
 unsigned int (*psk_client_callback)(SSL *ssl, const char *hint, char *identity,
  unsigned int max_identity_len, unsigned char *psk,
  unsigned int max_psk_len);
 unsigned int (*psk_server_callback)(SSL *ssl, const char *identity,
  unsigned char *psk, unsigned int max_psk_len);
 unsigned int freelist_max_len;
 struct ssl3_buf_freelist_st *wbuf_freelist;
 struct ssl3_buf_freelist_st *rbuf_freelist;
 SRP_CTX srp_ctx;
 int (*next_protos_advertised_cb)(SSL *s, const unsigned char **buf,
                    unsigned int *len, void *arg);
 void *next_protos_advertised_cb_arg;
 int (*next_proto_select_cb)(SSL *s, unsigned char **out,
        unsigned char *outlen,
        const unsigned char *in,
        unsigned int inlen,
        void *arg);
 void *next_proto_select_cb_arg;
        struct stack_st_SRTP_PROTECTION_PROFILE *srtp_profiles;
 };
struct lhash_st_SSL_SESSION *SSL_CTX_sessions(SSL_CTX *ctx);
void SSL_CTX_sess_set_new_cb(SSL_CTX *ctx, int (*new_session_cb)(struct ssl_st *ssl,SSL_SESSION *sess));
int (*SSL_CTX_sess_get_new_cb(SSL_CTX *ctx))(struct ssl_st *ssl, SSL_SESSION *sess);
void SSL_CTX_sess_set_remove_cb(SSL_CTX *ctx, void (*remove_session_cb)(struct ssl_ctx_st *ctx,SSL_SESSION *sess));
void (*SSL_CTX_sess_get_remove_cb(SSL_CTX *ctx))(struct ssl_ctx_st *ctx, SSL_SESSION *sess);
void SSL_CTX_sess_set_get_cb(SSL_CTX *ctx, SSL_SESSION *(*get_session_cb)(struct ssl_st *ssl, unsigned char *data,int len,int *copy));
SSL_SESSION *(*SSL_CTX_sess_get_get_cb(SSL_CTX *ctx))(struct ssl_st *ssl, unsigned char *Data, int len, int *copy);
void SSL_CTX_set_info_callback(SSL_CTX *ctx, void (*cb)(const SSL *ssl,int type,int val));
void (*SSL_CTX_get_info_callback(SSL_CTX *ctx))(const SSL *ssl,int type,int val);
void SSL_CTX_set_client_cert_cb(SSL_CTX *ctx, int (*client_cert_cb)(SSL *ssl, X509 **x509, EVP_PKEY **pkey));
int (*SSL_CTX_get_client_cert_cb(SSL_CTX *ctx))(SSL *ssl, X509 **x509, EVP_PKEY **pkey);
int SSL_CTX_set_client_cert_engine(SSL_CTX *ctx, ENGINE *e);
void SSL_CTX_set_cookie_generate_cb(SSL_CTX *ctx, int (*app_gen_cookie_cb)(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len));
void SSL_CTX_set_cookie_verify_cb(SSL_CTX *ctx, int (*app_verify_cookie_cb)(SSL *ssl, unsigned char *cookie, unsigned int cookie_len));
void SSL_CTX_set_next_protos_advertised_cb(SSL_CTX *s,
        int (*cb) (SSL *ssl,
            const unsigned char **out,
            unsigned int *outlen,
            void *arg),
        void *arg);
void SSL_CTX_set_next_proto_select_cb(SSL_CTX *s,
          int (*cb) (SSL *ssl,
       unsigned char **out,
       unsigned char *outlen,
       const unsigned char *in,
       unsigned int inlen,
       void *arg),
          void *arg);
int SSL_select_next_proto(unsigned char **out, unsigned char *outlen,
     const unsigned char *in, unsigned int inlen,
     const unsigned char *client, unsigned int client_len);
void SSL_get0_next_proto_negotiated(const SSL *s,
        const unsigned char **data, unsigned *len);
void SSL_CTX_set_psk_client_callback(SSL_CTX *ctx,
 unsigned int (*psk_client_callback)(SSL *ssl, const char *hint,
  char *identity, unsigned int max_identity_len, unsigned char *psk,
  unsigned int max_psk_len));
void SSL_set_psk_client_callback(SSL *ssl,
 unsigned int (*psk_client_callback)(SSL *ssl, const char *hint,
  char *identity, unsigned int max_identity_len, unsigned char *psk,
  unsigned int max_psk_len));
void SSL_CTX_set_psk_server_callback(SSL_CTX *ctx,
 unsigned int (*psk_server_callback)(SSL *ssl, const char *identity,
  unsigned char *psk, unsigned int max_psk_len));
void SSL_set_psk_server_callback(SSL *ssl,
 unsigned int (*psk_server_callback)(SSL *ssl, const char *identity,
  unsigned char *psk, unsigned int max_psk_len));
int SSL_CTX_use_psk_identity_hint(SSL_CTX *ctx, const char *identity_hint);
int SSL_use_psk_identity_hint(SSL *s, const char *identity_hint);
const char *SSL_get_psk_identity_hint(const SSL *s);
const char *SSL_get_psk_identity(const SSL *s);
struct ssl_st
 {
 int version;
 int type;
 const SSL_METHOD *method;
 BIO *rbio;
 BIO *wbio;
 BIO *bbio;
 int rwstate;
 int in_handshake;
 int (*handshake_func)(SSL *);
 int server;
 int new_session;
 int quiet_shutdown;
 int shutdown;
 int state;
 int rstate;
 BUF_MEM *init_buf;
 void *init_msg;
 int init_num;
 int init_off;
 unsigned char *packet;
 unsigned int packet_length;
 struct ssl2_state_st *s2;
 struct ssl3_state_st *s3;
 struct dtls1_state_st *d1;
 int read_ahead;
 void (*msg_callback)(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
 void *msg_callback_arg;
 int hit;
 X509_VERIFY_PARAM *param;
 struct stack_st_SSL_CIPHER *cipher_list;
 struct stack_st_SSL_CIPHER *cipher_list_by_id;
 int mac_flags;
 EVP_CIPHER_CTX *enc_read_ctx;
 EVP_MD_CTX *read_hash;
 COMP_CTX *expand;
 EVP_CIPHER_CTX *enc_write_ctx;
 EVP_MD_CTX *write_hash;
 COMP_CTX *compress;
 struct cert_st *cert;
 unsigned int sid_ctx_length;
 unsigned char sid_ctx[32];
 SSL_SESSION *session;
 GEN_SESSION_CB generate_session_id;
 int verify_mode;
 int (*verify_callback)(int ok,X509_STORE_CTX *ctx);
 void (*info_callback)(const SSL *ssl,int type,int val);
 int error;
 int error_code;
 unsigned int (*psk_client_callback)(SSL *ssl, const char *hint, char *identity,
  unsigned int max_identity_len, unsigned char *psk,
  unsigned int max_psk_len);
 unsigned int (*psk_server_callback)(SSL *ssl, const char *identity,
  unsigned char *psk, unsigned int max_psk_len);
 SSL_CTX *ctx;
 int debug;
 long verify_result;
 CRYPTO_EX_DATA ex_data;
 struct stack_st_X509_NAME *client_CA;
 int references;
 unsigned long options;
 unsigned long mode;
 long max_cert_list;
 int first_packet;
 int client_version;
 unsigned int max_send_fragment;
 void (*tlsext_debug_cb)(SSL *s, int client_server, int type,
     unsigned char *data, int len,
     void *arg);
 void *tlsext_debug_arg;
 char *tlsext_hostname;
 int servername_done;
 int tlsext_status_type;
 int tlsext_status_expected;
 struct stack_st_OCSP_RESPID *tlsext_ocsp_ids;
 X509_EXTENSIONS *tlsext_ocsp_exts;
 unsigned char *tlsext_ocsp_resp;
 int tlsext_ocsp_resplen;
 int tlsext_ticket_expected;
 size_t tlsext_ecpointformatlist_length;
 unsigned char *tlsext_ecpointformatlist;
 size_t tlsext_ellipticcurvelist_length;
 unsigned char *tlsext_ellipticcurvelist;
 void *tlsext_opaque_prf_input;
 size_t tlsext_opaque_prf_input_len;
 TLS_SESSION_TICKET_EXT *tlsext_session_ticket;
 tls_session_ticket_ext_cb_fn tls_session_ticket_ext_cb;
 void *tls_session_ticket_ext_cb_arg;
 tls_session_secret_cb_fn tls_session_secret_cb;
 void *tls_session_secret_cb_arg;
 SSL_CTX * initial_ctx;
 unsigned char *next_proto_negotiated;
 unsigned char next_proto_negotiated_len;
 struct stack_st_SRTP_PROTECTION_PROFILE *srtp_profiles;
 SRTP_PROTECTION_PROFILE *srtp_profile;
 unsigned int tlsext_heartbeat;
 unsigned int tlsext_hb_pending;
 unsigned int tlsext_hb_seq;
 int renegotiate;
 SRP_CTX srp_ctx;
 };
typedef struct ssl2_state_st
 {
 int three_byte_header;
 int clear_text;
 int escape;
 int ssl2_rollback;
 unsigned int wnum;
 int wpend_tot;
 const unsigned char *wpend_buf;
 int wpend_off;
 int wpend_len;
 int wpend_ret;
 int rbuf_left;
 int rbuf_offs;
 unsigned char *rbuf;
 unsigned char *wbuf;
 unsigned char *write_ptr;
 unsigned int padding;
 unsigned int rlength;
 int ract_data_length;
 unsigned int wlength;
 int wact_data_length;
 unsigned char *ract_data;
 unsigned char *wact_data;
 unsigned char *mac_data;
 unsigned char *read_key;
 unsigned char *write_key;
 unsigned int challenge_length;
 unsigned char challenge[32];
 unsigned int conn_id_length;
 unsigned char conn_id[16];
 unsigned int key_material_length;
 unsigned char key_material[24*2];
 unsigned long read_sequence;
 unsigned long write_sequence;
 struct {
  unsigned int conn_id_length;
  unsigned int cert_type;
  unsigned int cert_length;
  unsigned int csl;
  unsigned int clear;
  unsigned int enc;
  unsigned char ccl[32];
  unsigned int cipher_spec_length;
  unsigned int session_id_length;
  unsigned int clen;
  unsigned int rlen;
  } tmp;
 } SSL2_STATE;
typedef struct ssl3_record_st
 {
       int type;
       unsigned int length;
       unsigned int off;
       unsigned char *data;
       unsigned char *input;
       unsigned char *comp;
        unsigned long epoch;
        unsigned char seq_num[8];
 } SSL3_RECORD;
typedef struct ssl3_buffer_st
 {
 unsigned char *buf;
 size_t len;
 int offset;
 int left;
 } SSL3_BUFFER;
typedef struct ssl3_state_st
 {
 long flags;
 int delay_buf_pop_ret;
 unsigned char read_sequence[8];
 int read_mac_secret_size;
 unsigned char read_mac_secret[64];
 unsigned char write_sequence[8];
 int write_mac_secret_size;
 unsigned char write_mac_secret[64];
 unsigned char server_random[32];
 unsigned char client_random[32];
 int need_empty_fragments;
 int empty_fragment_done;
 int init_extra;
 SSL3_BUFFER rbuf;
 SSL3_BUFFER wbuf;
 SSL3_RECORD rrec;
 SSL3_RECORD wrec;
 unsigned char alert_fragment[2];
 unsigned int alert_fragment_len;
 unsigned char handshake_fragment[4];
 unsigned int handshake_fragment_len;
 unsigned int wnum;
 int wpend_tot;
 int wpend_type;
 int wpend_ret;
 const unsigned char *wpend_buf;
 BIO *handshake_buffer;
 EVP_MD_CTX **handshake_dgst;
 int change_cipher_spec;
 int warn_alert;
 int fatal_alert;
 int alert_dispatch;
 unsigned char send_alert[2];
 int renegotiate;
 int total_renegotiations;
 int num_renegotiations;
 int in_read_app_data;
 void *client_opaque_prf_input;
 size_t client_opaque_prf_input_len;
 void *server_opaque_prf_input;
 size_t server_opaque_prf_input_len;
 struct {
  unsigned char cert_verify_md[64*2];
  unsigned char finish_md[64*2];
  int finish_md_len;
  unsigned char peer_finish_md[64*2];
  int peer_finish_md_len;
  unsigned long message_size;
  int message_type;
  const SSL_CIPHER *new_cipher;
  DH *dh;
  EC_KEY *ecdh;
  int next_state;
  int reuse_message;
  int cert_req;
  int ctype_num;
  char ctype[9];
  struct stack_st_X509_NAME *ca_names;
  int use_rsa_tmp;
  int key_block_length;
  unsigned char *key_block;
  const EVP_CIPHER *new_sym_enc;
  const EVP_MD *new_hash;
  int new_mac_pkey_type;
  int new_mac_secret_size;
  const SSL_COMP *new_compression;
  int cert_request;
  } tmp;
        unsigned char previous_client_finished[64];
        unsigned char previous_client_finished_len;
        unsigned char previous_server_finished[64];
        unsigned char previous_server_finished_len;
        int send_connection_binding;
 int next_proto_neg_seen;
 } SSL3_STATE;
const char *SSL_get_servername(const SSL *s, const int type);
int SSL_get_servername_type(const SSL *s);
int SSL_export_keying_material(SSL *s, unsigned char *out, size_t olen,
 const char *label, size_t llen, const unsigned char *p, size_t plen,
 int use_context);
struct tls_session_ticket_ext_st
 {
 unsigned short length;
 void *data;
 };

typedef struct _pqueue *pqueue;
typedef struct _pitem
 {
 unsigned char priority[8];
 void *data;
 struct _pitem *next;
 } pitem;
typedef struct _pitem *piterator;
pitem *pitem_new(unsigned char *prio64be, void *data);
void pitem_free(pitem *item);
pqueue pqueue_new(void);
void pqueue_free(pqueue pq);
pitem *pqueue_insert(pqueue pq, pitem *item);
pitem *pqueue_peek(pqueue pq);
pitem *pqueue_pop(pqueue pq);
pitem *pqueue_find(pqueue pq, unsigned char *prio64be);
pitem *pqueue_iterator(pqueue pq);
pitem *pqueue_next(piterator *iter);
void pqueue_print(pqueue pq);
int pqueue_size(pqueue pq);

typedef struct dtls1_bitmap_st
 {
 unsigned long map;
 unsigned char max_seq_num[8];
 } DTLS1_BITMAP;
struct dtls1_retransmit_state
 {
 EVP_CIPHER_CTX *enc_write_ctx;
 EVP_MD_CTX *write_hash;
 COMP_CTX *compress;
 SSL_SESSION *session;
 unsigned short epoch;
 };
struct hm_header_st
 {
 unsigned char type;
 unsigned long msg_len;
 unsigned short seq;
 unsigned long frag_off;
 unsigned long frag_len;
 unsigned int is_ccs;
 struct dtls1_retransmit_state saved_retransmit_state;
 };
struct ccs_header_st
 {
 unsigned char type;
 unsigned short seq;
 };
struct dtls1_timeout_st
 {
 unsigned int read_timeouts;
 unsigned int write_timeouts;
 unsigned int num_alerts;
 };
typedef struct record_pqueue_st
 {
 unsigned short epoch;
 pqueue q;
 } record_pqueue;
typedef struct hm_fragment_st
 {
 struct hm_header_st msg_header;
 unsigned char *fragment;
 unsigned char *reassembly;
 } hm_fragment;
typedef struct dtls1_state_st
 {
 unsigned int send_cookie;
 unsigned char cookie[256];
 unsigned char rcvd_cookie[256];
 unsigned int cookie_len;
 unsigned short r_epoch;
 unsigned short w_epoch;
 DTLS1_BITMAP bitmap;
 DTLS1_BITMAP next_bitmap;
 unsigned short handshake_write_seq;
 unsigned short next_handshake_write_seq;
 unsigned short handshake_read_seq;
 unsigned char last_write_sequence[8];
 record_pqueue unprocessed_rcds;
 record_pqueue processed_rcds;
 pqueue buffered_messages;
 pqueue sent_messages;
 record_pqueue buffered_app_data;
 unsigned int listen;
 unsigned int mtu;
 struct hm_header_st w_msg_hdr;
 struct hm_header_st r_msg_hdr;
 struct dtls1_timeout_st timeout;
 struct timeval next_timeout;
 unsigned short timeout_duration;
 unsigned char alert_fragment[2];
 unsigned int alert_fragment_len;
 unsigned char handshake_fragment[12];
 unsigned int handshake_fragment_len;
 unsigned int retransmitting;
 unsigned int change_cipher_spec_ok;
 } DTLS1_STATE;
typedef struct dtls1_record_data_st
 {
 unsigned char *packet;
 unsigned int packet_length;
 SSL3_BUFFER rbuf;
 SSL3_RECORD rrec;
 } DTLS1_RECORD_DATA;
int SSL_CTX_set_tlsext_use_srtp(SSL_CTX *ctx, const char *profiles);
int SSL_set_tlsext_use_srtp(SSL *ctx, const char *profiles);
SRTP_PROTECTION_PROFILE *SSL_get_selected_srtp_profile(SSL *s);
struct stack_st_SRTP_PROTECTION_PROFILE *SSL_get_srtp_profiles(SSL *ssl);
SRTP_PROTECTION_PROFILE *SSL_get_selected_srtp_profile(SSL *s);
size_t SSL_get_finished(const SSL *s, void *buf, size_t count);
size_t SSL_get_peer_finished(const SSL *s, void *buf, size_t count);
SSL_SESSION *PEM_read_bio_SSL_SESSION(BIO *bp, SSL_SESSION **x, pem_password_cb *cb, void *u); SSL_SESSION *PEM_read_SSL_SESSION(FILE *fp, SSL_SESSION **x, pem_password_cb *cb, void *u); int PEM_write_bio_SSL_SESSION(BIO *bp, SSL_SESSION *x); int PEM_write_SSL_SESSION(FILE *fp, SSL_SESSION *x);
BIO_METHOD *BIO_f_ssl(void);
BIO *BIO_new_ssl(SSL_CTX *ctx,int client);
BIO *BIO_new_ssl_connect(SSL_CTX *ctx);
BIO *BIO_new_buffer_ssl_connect(SSL_CTX *ctx);
int BIO_ssl_copy_session_id(BIO *to,BIO *from);
void BIO_ssl_shutdown(BIO *ssl_bio);
int SSL_CTX_set_cipher_list(SSL_CTX *,const char *str);
SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth);
void SSL_CTX_free(SSL_CTX *);
long SSL_CTX_set_timeout(SSL_CTX *ctx,long t);
long SSL_CTX_get_timeout(const SSL_CTX *ctx);
X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *);
void SSL_CTX_set_cert_store(SSL_CTX *,X509_STORE *);
int SSL_want(const SSL *s);
int SSL_clear(SSL *s);
void SSL_CTX_flush_sessions(SSL_CTX *ctx,long tm);
const SSL_CIPHER *SSL_get_current_cipher(const SSL *s);
int SSL_CIPHER_get_bits(const SSL_CIPHER *c,int *alg_bits);
char * SSL_CIPHER_get_version(const SSL_CIPHER *c);
const char * SSL_CIPHER_get_name(const SSL_CIPHER *c);
unsigned long SSL_CIPHER_get_id(const SSL_CIPHER *c);
int SSL_get_fd(const SSL *s);
int SSL_get_rfd(const SSL *s);
int SSL_get_wfd(const SSL *s);
const char * SSL_get_cipher_list(const SSL *s,int n);
char * SSL_get_shared_ciphers(const SSL *s, char *buf, int len);
int SSL_get_read_ahead(const SSL * s);
int SSL_pending(const SSL *s);
int SSL_set_fd(SSL *s, int fd);
int SSL_set_rfd(SSL *s, int fd);
int SSL_set_wfd(SSL *s, int fd);
void SSL_set_bio(SSL *s, BIO *rbio,BIO *wbio);
BIO * SSL_get_rbio(const SSL *s);
BIO * SSL_get_wbio(const SSL *s);
int SSL_set_cipher_list(SSL *s, const char *str);
void SSL_set_read_ahead(SSL *s, int yes);
int SSL_get_verify_mode(const SSL *s);
int SSL_get_verify_depth(const SSL *s);
int (*SSL_get_verify_callback(const SSL *s))(int,X509_STORE_CTX *);
void SSL_set_verify(SSL *s, int mode,
         int (*callback)(int ok,X509_STORE_CTX *ctx));
void SSL_set_verify_depth(SSL *s, int depth);
int SSL_use_RSAPrivateKey(SSL *ssl, RSA *rsa);
int SSL_use_RSAPrivateKey_ASN1(SSL *ssl, unsigned char *d, long len);
int SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey);
int SSL_use_PrivateKey_ASN1(int pk,SSL *ssl, const unsigned char *d, long len);
int SSL_use_certificate(SSL *ssl, X509 *x);
int SSL_use_certificate_ASN1(SSL *ssl, const unsigned char *d, int len);
int SSL_use_RSAPrivateKey_file(SSL *ssl, const char *file, int type);
int SSL_use_PrivateKey_file(SSL *ssl, const char *file, int type);
int SSL_use_certificate_file(SSL *ssl, const char *file, int type);
int SSL_CTX_use_RSAPrivateKey_file(SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);
struct stack_st_X509_NAME *SSL_load_client_CA_file(const char *file);
int SSL_add_file_cert_subjects_to_stack(struct stack_st_X509_NAME *stackCAs,
         const char *file);
int SSL_add_dir_cert_subjects_to_stack(struct stack_st_X509_NAME *stackCAs,
        const char *dir);
void SSL_load_error_strings(void );
const char *SSL_state_string(const SSL *s);
const char *SSL_rstate_string(const SSL *s);
const char *SSL_state_string_long(const SSL *s);
const char *SSL_rstate_string_long(const SSL *s);
long SSL_SESSION_get_time(const SSL_SESSION *s);
long SSL_SESSION_set_time(SSL_SESSION *s, long t);
long SSL_SESSION_get_timeout(const SSL_SESSION *s);
long SSL_SESSION_set_timeout(SSL_SESSION *s, long t);
void SSL_copy_session_id(SSL *to,const SSL *from);
X509 *SSL_SESSION_get0_peer(SSL_SESSION *s);
int SSL_SESSION_set1_id_context(SSL_SESSION *s,const unsigned char *sid_ctx,
          unsigned int sid_ctx_len);
SSL_SESSION *SSL_SESSION_new(void);
const unsigned char *SSL_SESSION_get_id(const SSL_SESSION *s,
     unsigned int *len);
unsigned int SSL_SESSION_get_compress_id(const SSL_SESSION *s);
int SSL_SESSION_print_fp(FILE *fp,const SSL_SESSION *ses);
int SSL_SESSION_print(BIO *fp,const SSL_SESSION *ses);
void SSL_SESSION_free(SSL_SESSION *ses);
int i2d_SSL_SESSION(SSL_SESSION *in,unsigned char **pp);
int SSL_set_session(SSL *to, SSL_SESSION *session);
int SSL_CTX_add_session(SSL_CTX *s, SSL_SESSION *c);
int SSL_CTX_remove_session(SSL_CTX *,SSL_SESSION *c);
int SSL_CTX_set_generate_session_id(SSL_CTX *, GEN_SESSION_CB);
int SSL_set_generate_session_id(SSL *, GEN_SESSION_CB);
int SSL_has_matching_session_id(const SSL *ssl, const unsigned char *id,
     unsigned int id_len);
SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a,const unsigned char **pp,
        long length);
X509 * SSL_get_peer_certificate(const SSL *s);
struct stack_st_X509 *SSL_get_peer_cert_chain(const SSL *s);
int SSL_CTX_get_verify_mode(const SSL_CTX *ctx);
int SSL_CTX_get_verify_depth(const SSL_CTX *ctx);
int (*SSL_CTX_get_verify_callback(const SSL_CTX *ctx))(int,X509_STORE_CTX *);
void SSL_CTX_set_verify(SSL_CTX *ctx,int mode,
   int (*callback)(int, X509_STORE_CTX *));
void SSL_CTX_set_verify_depth(SSL_CTX *ctx,int depth);
void SSL_CTX_set_cert_verify_callback(SSL_CTX *ctx, int (*cb)(X509_STORE_CTX *,void *), void *arg);
int SSL_CTX_use_RSAPrivateKey(SSL_CTX *ctx, RSA *rsa);
int SSL_CTX_use_RSAPrivateKey_ASN1(SSL_CTX *ctx, const unsigned char *d, long len);
int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey);
int SSL_CTX_use_PrivateKey_ASN1(int pk,SSL_CTX *ctx,
 const unsigned char *d, long len);
int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x);
int SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, int len, const unsigned char *d);
void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb);
void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u);
int SSL_CTX_check_private_key(const SSL_CTX *ctx);
int SSL_check_private_key(const SSL *ctx);
int SSL_CTX_set_session_id_context(SSL_CTX *ctx,const unsigned char *sid_ctx,
           unsigned int sid_ctx_len);
SSL * SSL_new(SSL_CTX *ctx);
int SSL_set_session_id_context(SSL *ssl,const unsigned char *sid_ctx,
       unsigned int sid_ctx_len);
int SSL_CTX_set_purpose(SSL_CTX *s, int purpose);
int SSL_set_purpose(SSL *s, int purpose);
int SSL_CTX_set_trust(SSL_CTX *s, int trust);
int SSL_set_trust(SSL *s, int trust);
int SSL_CTX_set1_param(SSL_CTX *ctx, X509_VERIFY_PARAM *vpm);
int SSL_set1_param(SSL *ssl, X509_VERIFY_PARAM *vpm);
int SSL_CTX_set_srp_username(SSL_CTX *ctx,char *name);
int SSL_CTX_set_srp_password(SSL_CTX *ctx,char *password);
int SSL_CTX_set_srp_strength(SSL_CTX *ctx, int strength);
int SSL_CTX_set_srp_client_pwd_callback(SSL_CTX *ctx,
     char *(*cb)(SSL *,void *));
int SSL_CTX_set_srp_verify_param_callback(SSL_CTX *ctx,
       int (*cb)(SSL *,void *));
int SSL_CTX_set_srp_username_callback(SSL_CTX *ctx,
          int (*cb)(SSL *,int *,void *));
int SSL_CTX_set_srp_cb_arg(SSL_CTX *ctx, void *arg);
int SSL_set_srp_server_param(SSL *s, const BIGNUM *N, const BIGNUM *g,
        BIGNUM *sa, BIGNUM *v, char *info);
int SSL_set_srp_server_param_pw(SSL *s, const char *user, const char *pass,
    const char *grp);
BIGNUM *SSL_get_srp_g(SSL *s);
BIGNUM *SSL_get_srp_N(SSL *s);
char *SSL_get_srp_username(SSL *s);
char *SSL_get_srp_userinfo(SSL *s);
void SSL_free(SSL *ssl);
int SSL_accept(SSL *ssl);
int SSL_connect(SSL *ssl);
int SSL_read(SSL *ssl,void *buf,int num);
int SSL_peek(SSL *ssl,void *buf,int num);
int SSL_write(SSL *ssl,const void *buf,int num);
long SSL_ctrl(SSL *ssl,int cmd, long larg, void *parg);
long SSL_callback_ctrl(SSL *, int, void (*)(void));
long SSL_CTX_ctrl(SSL_CTX *ctx,int cmd, long larg, void *parg);
long SSL_CTX_callback_ctrl(SSL_CTX *, int, void (*)(void));
int SSL_get_error(const SSL *s,int ret_code);
const char *SSL_get_version(const SSL *s);
int SSL_CTX_set_ssl_version(SSL_CTX *ctx, const SSL_METHOD *meth);
const SSL_METHOD *SSLv2_method(void);
const SSL_METHOD *SSLv2_server_method(void);
const SSL_METHOD *SSLv2_client_method(void);
const SSL_METHOD *SSLv3_method(void);
const SSL_METHOD *SSLv3_server_method(void);
const SSL_METHOD *SSLv3_client_method(void);
const SSL_METHOD *SSLv23_method(void);
const SSL_METHOD *SSLv23_server_method(void);
const SSL_METHOD *SSLv23_client_method(void);
const SSL_METHOD *TLSv1_method(void);
const SSL_METHOD *TLSv1_server_method(void);
const SSL_METHOD *TLSv1_client_method(void);
const SSL_METHOD *TLSv1_1_method(void);
const SSL_METHOD *TLSv1_1_server_method(void);
const SSL_METHOD *TLSv1_1_client_method(void);
const SSL_METHOD *TLSv1_2_method(void);
const SSL_METHOD *TLSv1_2_server_method(void);
const SSL_METHOD *TLSv1_2_client_method(void);
const SSL_METHOD *DTLSv1_method(void);
const SSL_METHOD *DTLSv1_server_method(void);
const SSL_METHOD *DTLSv1_client_method(void);
struct stack_st_SSL_CIPHER *SSL_get_ciphers(const SSL *s);
int SSL_do_handshake(SSL *s);
int SSL_renegotiate(SSL *s);
int SSL_renegotiate_abbreviated(SSL *s);
int SSL_renegotiate_pending(SSL *s);
int SSL_shutdown(SSL *s);
const SSL_METHOD *SSL_get_ssl_method(SSL *s);
int SSL_set_ssl_method(SSL *s, const SSL_METHOD *method);
const char *SSL_alert_type_string_long(int value);
const char *SSL_alert_type_string(int value);
const char *SSL_alert_desc_string_long(int value);
const char *SSL_alert_desc_string(int value);
void SSL_set_client_CA_list(SSL *s, struct stack_st_X509_NAME *name_list);
void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, struct stack_st_X509_NAME *name_list);
struct stack_st_X509_NAME *SSL_get_client_CA_list(const SSL *s);
struct stack_st_X509_NAME *SSL_CTX_get_client_CA_list(const SSL_CTX *s);
int SSL_add_client_CA(SSL *ssl,X509 *x);
int SSL_CTX_add_client_CA(SSL_CTX *ctx,X509 *x);
void SSL_set_connect_state(SSL *s);
void SSL_set_accept_state(SSL *s);
long SSL_get_default_timeout(const SSL *s);
int SSL_library_init(void );
char *SSL_CIPHER_description(const SSL_CIPHER *,char *buf,int size);
struct stack_st_X509_NAME *SSL_dup_CA_list(struct stack_st_X509_NAME *sk);
SSL *SSL_dup(SSL *ssl);
X509 *SSL_get_certificate(const SSL *ssl);
               struct evp_pkey_st *SSL_get_privatekey(SSL *ssl);
void SSL_CTX_set_quiet_shutdown(SSL_CTX *ctx,int mode);
int SSL_CTX_get_quiet_shutdown(const SSL_CTX *ctx);
void SSL_set_quiet_shutdown(SSL *ssl,int mode);
int SSL_get_quiet_shutdown(const SSL *ssl);
void SSL_set_shutdown(SSL *ssl,int mode);
int SSL_get_shutdown(const SSL *ssl);
int SSL_version(const SSL *ssl);
int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx);
int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
 const char *CApath);
SSL_SESSION *SSL_get_session(const SSL *ssl);
SSL_SESSION *SSL_get1_session(SSL *ssl);
SSL_CTX *SSL_get_SSL_CTX(const SSL *ssl);
SSL_CTX *SSL_set_SSL_CTX(SSL *ssl, SSL_CTX* ctx);
void SSL_set_info_callback(SSL *ssl,
      void (*cb)(const SSL *ssl,int type,int val));
void (*SSL_get_info_callback(const SSL *ssl))(const SSL *ssl,int type,int val);
int SSL_state(const SSL *ssl);
void SSL_set_state(SSL *ssl, int state);
void SSL_set_verify_result(SSL *ssl,long v);
long SSL_get_verify_result(const SSL *ssl);
int SSL_set_ex_data(SSL *ssl,int idx,void *data);
void *SSL_get_ex_data(const SSL *ssl,int idx);
int SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
 CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int SSL_SESSION_set_ex_data(SSL_SESSION *ss,int idx,void *data);
void *SSL_SESSION_get_ex_data(const SSL_SESSION *ss,int idx);
int SSL_SESSION_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
 CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int SSL_CTX_set_ex_data(SSL_CTX *ssl,int idx,void *data);
void *SSL_CTX_get_ex_data(const SSL_CTX *ssl,int idx);
int SSL_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
 CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int SSL_get_ex_data_X509_STORE_CTX_idx(void );
void SSL_CTX_set_tmp_rsa_callback(SSL_CTX *ctx,
      RSA *(*cb)(SSL *ssl,int is_export,
          int keylength));
void SSL_set_tmp_rsa_callback(SSL *ssl,
      RSA *(*cb)(SSL *ssl,int is_export,
          int keylength));
void SSL_CTX_set_tmp_dh_callback(SSL_CTX *ctx,
     DH *(*dh)(SSL *ssl,int is_export,
        int keylength));
void SSL_set_tmp_dh_callback(SSL *ssl,
     DH *(*dh)(SSL *ssl,int is_export,
        int keylength));
void SSL_CTX_set_tmp_ecdh_callback(SSL_CTX *ctx,
     EC_KEY *(*ecdh)(SSL *ssl,int is_export,
        int keylength));
void SSL_set_tmp_ecdh_callback(SSL *ssl,
     EC_KEY *(*ecdh)(SSL *ssl,int is_export,
        int keylength));
const COMP_METHOD *SSL_get_current_compression(SSL *s);
const COMP_METHOD *SSL_get_current_expansion(SSL *s);
const char *SSL_COMP_get_name(const COMP_METHOD *comp);
struct stack_st_SSL_COMP *SSL_COMP_get_compression_methods(void);
int SSL_COMP_add_compression_method(int id,COMP_METHOD *cm);
int SSL_set_session_ticket_ext(SSL *s, void *ext_data, int ext_len);
int SSL_set_session_ticket_ext_cb(SSL *s, tls_session_ticket_ext_cb_fn cb,
      void *arg);
int SSL_set_session_secret_cb(SSL *s, tls_session_secret_cb_fn tls_session_secret_cb, void *arg);
void SSL_set_debug(SSL *s, int debug);
int SSL_cache_hit(SSL *s);
void ERR_load_SSL_strings(void);
]]

CHARTYPE_FIRST_ESC_2253 = 0x20
CHARTYPE_LAST_ESC_2253 = 0x40
CHARTYPE_PRINTABLESTRING = 0x10
DSS_prime_checks = 50
DTLS1_AL_HEADER_LENGTH = 2
DTLS1_BAD_VER = 0x0100
DTLS1_CCS_HEADER_LENGTH = 1
DTLS1_COOKIE_LENGTH = 256
DTLS1_HM_BAD_FRAGMENT = -2
DTLS1_HM_FRAGMENT_RETRY = -3
DTLS1_HM_HEADER_LENGTH = 12
DTLS1_MT_HELLO_VERIFY_REQUEST = 3
DTLS1_RT_HEADER_LENGTH = 13
DTLS1_TMO_ALERT_COUNT = 12
DTLS1_TMO_READ_COUNT = 2
DTLS1_TMO_WRITE_COUNT = 2
DTLS1_VERSION = 0xFEFF
DTLS_CTRL_GET_TIMEOUT = 73
DTLS_CTRL_HANDLE_TIMEOUT = 74
DTLS_CTRL_LISTEN = 75
EOF = (-1)
LH_LOAD_MULT = 256
LN_ad_ca_issuers = "CA Issuers"
LN_ad_dvcs = "ad dvcs"
LN_ad_OCSP = "OCSP"
LN_ad_timeStamping = "AD Time Stamping"
LN_aes_128_cbc = "aes-128-cbc"
LN_aes_128_cbc_hmac_sha1 = "aes-128-cbc-hmac-sha1"
LN_aes_128_ccm = "aes-128-ccm"
LN_aes_128_cfb1 = "aes-128-cfb1"
LN_aes_128_cfb128 = "aes-128-cfb"
LN_aes_128_cfb8 = "aes-128-cfb8"
LN_aes_128_ctr = "aes-128-ctr"
LN_aes_128_ecb = "aes-128-ecb"
LN_aes_128_gcm = "aes-128-gcm"
LN_aes_128_ofb128 = "aes-128-ofb"
LN_aes_128_xts = "aes-128-xts"
LN_aes_192_cbc = "aes-192-cbc"
LN_aes_192_cbc_hmac_sha1 = "aes-192-cbc-hmac-sha1"
LN_aes_192_ccm = "aes-192-ccm"
LN_aes_192_cfb1 = "aes-192-cfb1"
LN_aes_192_cfb128 = "aes-192-cfb"
LN_aes_192_cfb8 = "aes-192-cfb8"
LN_aes_192_ctr = "aes-192-ctr"
LN_aes_192_ecb = "aes-192-ecb"
LN_aes_192_gcm = "aes-192-gcm"
LN_aes_192_ofb128 = "aes-192-ofb"
LN_aes_256_cbc = "aes-256-cbc"
LN_aes_256_cbc_hmac_sha1 = "aes-256-cbc-hmac-sha1"
LN_aes_256_ccm = "aes-256-ccm"
LN_aes_256_cfb1 = "aes-256-cfb1"
LN_aes_256_cfb128 = "aes-256-cfb"
LN_aes_256_cfb8 = "aes-256-cfb8"
LN_aes_256_ctr = "aes-256-ctr"
LN_aes_256_ecb = "aes-256-ecb"
LN_aes_256_gcm = "aes-256-gcm"
LN_aes_256_ofb128 = "aes-256-ofb"
LN_aes_256_xts = "aes-256-xts"
LN_algorithm = "algorithm"
LN_ansi_X9_62 = "ANSI X9.62"
LN_any_policy = "X509v3 Any Policy"
LN_anyExtendedKeyUsage = "Any Extended Key Usage"
LN_aRecord = "aRecord"
LN_associatedDomain = "associatedDomain"
LN_associatedName = "associatedName"
LN_authority_key_identifier = "X509v3 Authority Key Identifier"
LN_authorityRevocationList = "authorityRevocationList"
LN_basic_constraints = "X509v3 Basic Constraints"
LN_bf_cbc = "bf-cbc"
LN_bf_cfb64 = "bf-cfb"
LN_bf_ecb = "bf-ecb"
LN_bf_ofb64 = "bf-ofb"
LN_biometricInfo = "Biometric Info"
LN_buildingName = "buildingName"
LN_businessCategory = "businessCategory"
LN_cACertificate = "cACertificate"
LN_camellia_128_cbc = "camellia-128-cbc"
LN_camellia_128_cfb1 = "camellia-128-cfb1"
LN_camellia_128_cfb128 = "camellia-128-cfb"
LN_camellia_128_cfb8 = "camellia-128-cfb8"
LN_camellia_128_ecb = "camellia-128-ecb"
LN_camellia_128_ofb128 = "camellia-128-ofb"
LN_camellia_192_cbc = "camellia-192-cbc"
LN_camellia_192_cfb1 = "camellia-192-cfb1"
LN_camellia_192_cfb128 = "camellia-192-cfb"
LN_camellia_192_cfb8 = "camellia-192-cfb8"
LN_camellia_192_ecb = "camellia-192-ecb"
LN_camellia_192_ofb128 = "camellia-192-ofb"
LN_camellia_256_cbc = "camellia-256-cbc"
LN_camellia_256_cfb1 = "camellia-256-cfb1"
LN_camellia_256_cfb128 = "camellia-256-cfb"
LN_camellia_256_cfb8 = "camellia-256-cfb8"
LN_camellia_256_ecb = "camellia-256-ecb"
LN_camellia_256_ofb128 = "camellia-256-ofb"
LN_caRepository = "CA Repository"
LN_caseIgnoreIA5StringSyntax = "caseIgnoreIA5StringSyntax"
LN_cast5_cbc = "cast5-cbc"
LN_cast5_cfb64 = "cast5-cfb"
LN_cast5_ecb = "cast5-ecb"
LN_cast5_ofb64 = "cast5-ofb"
LN_certBag = "certBag"
LN_certificate_issuer = "X509v3 Certificate Issuer"
LN_certificate_policies = "X509v3 Certificate Policies"
LN_certificateRevocationList = "certificateRevocationList"
LN_client_auth = "TLS Web Client Authentication"
LN_cmac = "cmac"
LN_cNAMERecord = "cNAMERecord"
LN_code_sign = "Code Signing"
LN_commonName = "commonName"
LN_countryName = "countryName"
LN_crl_distribution_points = "X509v3 CRL Distribution Points"
LN_crl_number = "X509v3 CRL Number"
LN_crl_reason = "X509v3 CRL Reason Code"
LN_crlBag = "crlBag"
LN_crossCertificatePair = "crossCertificatePair"
LN_dcObject = "dcObject"
LN_delta_crl = "X509v3 Delta CRL Indicator"
LN_deltaRevocationList = "deltaRevocationList"
LN_des_cbc = "des-cbc"
LN_des_cdmf = "des-cdmf"
LN_des_cfb1 = "des-cfb1"
LN_des_cfb64 = "des-cfb"
LN_des_cfb8 = "des-cfb8"
LN_des_ecb = "des-ecb"
LN_des_ede3_cbc = "des-ede3-cbc"
LN_des_ede3_cfb1 = "des-ede3-cfb1"
LN_des_ede3_cfb64 = "des-ede3-cfb"
LN_des_ede3_cfb8 = "des-ede3-cfb8"
LN_des_ede3_ecb = "des-ede3"
LN_des_ede3_ofb64 = "des-ede3-ofb"
LN_des_ede_cbc = "des-ede-cbc"
LN_des_ede_cfb64 = "des-ede-cfb"
LN_des_ede_ecb = "des-ede"
LN_des_ede_ofb64 = "des-ede-ofb"
LN_des_ofb64 = "des-ofb"
LN_description = "description"
LN_destinationIndicator = "destinationIndicator"
LN_desx_cbc = "desx-cbc"
LN_dhKeyAgreement = "dhKeyAgreement"
LN_Directory = "Directory"
LN_distinguishedName = "distinguishedName"
LN_dITRedirect = "dITRedirect"
LN_dnQualifier = "dnQualifier"
LN_dNSDomain = "dNSDomain"
LN_documentAuthor = "documentAuthor"
LN_documentIdentifier = "documentIdentifier"
LN_documentLocation = "documentLocation"
LN_documentPublisher = "documentPublisher"
LN_documentSeries = "documentSeries"
LN_documentTitle = "documentTitle"
LN_documentVersion = "documentVersion"
LN_dod = "dod"
LN_Domain = "Domain"
LN_domainComponent = "domainComponent"
LN_domainRelatedObject = "domainRelatedObject"
LN_dsa = "dsaEncryption"
LN_dsa_2 = "dsaEncryption-old"
LN_dSAQuality = "dSAQuality"
LN_dsaWithSHA = "dsaWithSHA"
LN_dsaWithSHA1 = "dsaWithSHA1"
LN_dsaWithSHA1_2 = "dsaWithSHA1-old"
LN_dvcs = "dvcs"
LN_email_protect = "E-mail Protection"
LN_enhancedSearchGuide = "enhancedSearchGuide"
LN_Enterprises = "Enterprises"
LN_Experimental = "Experimental"
LN_ext_key_usage = "X509v3 Extended Key Usage"
LN_ext_req = "Extension Request"
LN_facsimileTelephoneNumber = "facsimileTelephoneNumber"
LN_favouriteDrink = "favouriteDrink"
LN_freshest_crl = "X509v3 Freshest CRL"
LN_friendlyCountry = "friendlyCountry"
LN_friendlyCountryName = "friendlyCountryName"
LN_friendlyName = "friendlyName"
LN_generationQualifier = "generationQualifier"
LN_givenName = "givenName"
LN_hmac = "hmac"
LN_hmac_md5 = "hmac-md5"
LN_hmac_sha1 = "hmac-sha1"
LN_hmacWithMD5 = "hmacWithMD5"
LN_hmacWithSHA1 = "hmacWithSHA1"
LN_hmacWithSHA224 = "hmacWithSHA224"
LN_hmacWithSHA256 = "hmacWithSHA256"
LN_hmacWithSHA384 = "hmacWithSHA384"
LN_hmacWithSHA512 = "hmacWithSHA512"
LN_hold_instruction_call_issuer = "Hold Instruction Call Issuer"
LN_hold_instruction_code = "Hold Instruction Code"
LN_hold_instruction_none = "Hold Instruction None"
LN_hold_instruction_reject = "Hold Instruction Reject"
LN_homePostalAddress = "homePostalAddress"
LN_homeTelephoneNumber = "homeTelephoneNumber"
LN_houseIdentifier = "houseIdentifier"
LN_iA5StringSyntax = "iA5StringSyntax"
LN_iana = "iana"
LN_id_DHBasedMac = "Diffie-Hellman based MAC"
LN_id_Gost28147_89 = "GOST 28147-89"
LN_id_Gost28147_89_cc = "GOST 28147-89 Cryptocom ParamSet"
LN_id_Gost28147_89_MAC = "GOST 28147-89 MAC"
LN_id_GostR3410_2001 = "GOST R 34.10-2001"
LN_id_GostR3410_2001_cc = "GOST 34.10-2001 Cryptocom"
LN_id_GostR3410_2001_ParamSet_cc = "GOST R 3410-2001 Parameter Set Cryptocom"
LN_id_GostR3410_2001DH = "GOST R 34.10-2001 DH"
LN_id_GostR3410_94 = "GOST R 34.10-94"
LN_id_GostR3410_94_cc = "GOST 34.10-94 Cryptocom"
LN_id_GostR3410_94DH = "GOST R 34.10-94 DH"
LN_id_GostR3411_94 = "GOST R 34.11-94"
LN_id_GostR3411_94_prf = "GOST R 34.11-94 PRF"
LN_id_GostR3411_94_with_GostR3410_2001 = "GOST R 34.11-94 with GOST R 34.10-2001"
LN_id_GostR3411_94_with_GostR3410_2001_cc = "GOST R 34.11-94 with GOST R 34.10-2001 Cryptocom"
LN_id_GostR3411_94_with_GostR3410_94 = "GOST R 34.11-94 with GOST R 34.10-94"
LN_id_GostR3411_94_with_GostR3410_94_cc = "GOST R 34.11-94 with GOST R 34.10-94 Cryptocom"
LN_id_hex_multipart_message = "id-hex-multipart-message"
LN_id_hex_partial_message = "id-hex-partial-message"
LN_id_HMACGostR3411_94 = "HMAC GOST 34.11-94"
LN_id_on_permanentIdentifier = "Permanent Identifier"
LN_id_PasswordBasedMAC = "password based MAC"
LN_id_pbkdf2 = "PBKDF2"
LN_id_pkix_OCSP_acceptableResponses = "Acceptable OCSP Responses"
LN_id_pkix_OCSP_archiveCutoff = "OCSP Archive Cutoff"
LN_id_pkix_OCSP_basic = "Basic OCSP Response"
LN_id_pkix_OCSP_CrlID = "OCSP CRL ID"
LN_id_pkix_OCSP_extendedStatus = "Extended OCSP Status"
LN_id_pkix_OCSP_noCheck = "OCSP No Check"
LN_id_pkix_OCSP_Nonce = "OCSP Nonce"
LN_id_pkix_OCSP_serviceLocator = "OCSP Service Locator"
LN_id_pkix_OCSP_trustRoot = "Trust Root"
LN_id_ppl_anyLanguage = "Any language"
LN_id_ppl_inheritAll = "Inherit all"
LN_id_qt_cps = "Policy Qualifier CPS"
LN_id_qt_unotice = "Policy Qualifier User Notice"
LN_id_set = "Secure Electronic Transactions"
LN_idea_cbc = "idea-cbc"
LN_idea_cfb64 = "idea-cfb"
LN_idea_ecb = "idea-ecb"
LN_idea_ofb64 = "idea-ofb"
LN_Independent = "Independent"
LN_info_access = "Authority Information Access"
LN_inhibit_any_policy = "X509v3 Inhibit Any Policy"
LN_initials = "initials"
LN_international_organizations = "International Organizations"
LN_internationaliSDNNumber = "internationaliSDNNumber"
LN_invalidity_date = "Invalidity Date"
LN_ipsec3 = "ipsec3"
LN_ipsec4 = "ipsec4"
LN_ipsecEndSystem = "IPSec End System"
LN_ipsecTunnel = "IPSec Tunnel"
LN_ipsecUser = "IPSec User"
LN_iso = "iso"
LN_ISO_US = "ISO US Member Body"
LN_issuer_alt_name = "X509v3 Issuer Alternative Name"
LN_issuing_distribution_point = "X509v3 Issuing Distrubution Point"
LN_itu_t = "itu-t"
LN_janetMailbox = "janetMailbox"
LN_joint_iso_itu_t = "joint-iso-itu-t"
LN_key_usage = "X509v3 Key Usage"
LN_keyBag = "keyBag"
LN_kisa = "kisa"
LN_lastModifiedBy = "lastModifiedBy"
LN_lastModifiedTime = "lastModifiedTime"
LN_localityName = "localityName"
LN_localKeyID = "localKeyID"
LN_LocalKeySet = "Microsoft Local Key set"
LN_Mail = "Mail"
LN_mailPreferenceOption = "mailPreferenceOption"
LN_Management = "Management"
LN_md2 = "md2"
LN_md2WithRSAEncryption = "md2WithRSAEncryption"
LN_md4 = "md4"
LN_md4WithRSAEncryption = "md4WithRSAEncryption"
LN_md5 = "md5"
LN_md5_sha1 = "md5-sha1"
LN_md5WithRSA = "md5WithRSA"
LN_md5WithRSAEncryption = "md5WithRSAEncryption"
LN_mdc2 = "mdc2"
LN_mdc2WithRSA = "mdc2WithRSA"
LN_member_body = "ISO Member Body"
LN_mgf1 = "mgf1"
LN_mime_mhs = "MIME MHS"
LN_mime_mhs_bodies = "mime-mhs-bodies"
LN_mime_mhs_headings = "mime-mhs-headings"
LN_mobileTelephoneNumber = "mobileTelephoneNumber"
LN_ms_code_com = "Microsoft Commercial Code Signing"
LN_ms_code_ind = "Microsoft Individual Code Signing"
LN_ms_csp_name = "Microsoft CSP Name"
LN_ms_ctl_sign = "Microsoft Trust List Signing"
LN_ms_efs = "Microsoft Encrypted File System"
LN_ms_ext_req = "Microsoft Extension Request"
LN_ms_sgc = "Microsoft Server Gated Crypto"
LN_ms_smartcard_login = "Microsoft Smartcardlogin"
LN_ms_upn = "Microsoft Universal Principal Name"
LN_mXRecord = "mXRecord"
LN_name = "name"
LN_name_constraints = "X509v3 Name Constraints"
LN_netscape = "Netscape Communications Corp."
LN_netscape_base_url = "Netscape Base Url"
LN_netscape_ca_policy_url = "Netscape CA Policy Url"
LN_netscape_ca_revocation_url = "Netscape CA Revocation Url"
LN_netscape_cert_extension = "Netscape Certificate Extension"
LN_netscape_cert_sequence = "Netscape Certificate Sequence"
LN_netscape_cert_type = "Netscape Cert Type"
LN_netscape_comment = "Netscape Comment"
LN_netscape_data_type = "Netscape Data Type"
LN_netscape_renewal_url = "Netscape Renewal Url"
LN_netscape_revocation_url = "Netscape Revocation Url"
LN_netscape_ssl_server_name = "Netscape SSL Server Name"
LN_no_rev_avail = "X509v3 No Revocation Available"
LN_ns_sgc = "Netscape Server Gated Crypto"
LN_nSRecord = "nSRecord"
LN_OCSP_sign = "OCSP Signing"
LN_org = "org"
LN_organizationalStatus = "organizationalStatus"
LN_organizationalUnitName = "organizationalUnitName"
LN_organizationName = "organizationName"
LN_otherMailbox = "otherMailbox"
LN_pagerTelephoneNumber = "pagerTelephoneNumber"
LN_pbe_WithSHA1And128BitRC2_CBC = "pbeWithSHA1And128BitRC2-CBC"
LN_pbe_WithSHA1And128BitRC4 = "pbeWithSHA1And128BitRC4"
LN_pbe_WithSHA1And2_Key_TripleDES_CBC = "pbeWithSHA1And2-KeyTripleDES-CBC"
LN_pbe_WithSHA1And3_Key_TripleDES_CBC = "pbeWithSHA1And3-KeyTripleDES-CBC"
LN_pbe_WithSHA1And40BitRC2_CBC = "pbeWithSHA1And40BitRC2-CBC"
LN_pbe_WithSHA1And40BitRC4 = "pbeWithSHA1And40BitRC4"
LN_pbes2 = "PBES2"
LN_pbeWithMD2AndDES_CBC = "pbeWithMD2AndDES-CBC"
LN_pbeWithMD2AndRC2_CBC = "pbeWithMD2AndRC2-CBC"
LN_pbeWithMD5AndCast5_CBC = "pbeWithMD5AndCast5CBC"
LN_pbeWithMD5AndDES_CBC = "pbeWithMD5AndDES-CBC"
LN_pbeWithMD5AndRC2_CBC = "pbeWithMD5AndRC2-CBC"
LN_pbeWithSHA1AndDES_CBC = "pbeWithSHA1AndDES-CBC"
LN_pbeWithSHA1AndRC2_CBC = "pbeWithSHA1AndRC2-CBC"
LN_pbmac1 = "PBMAC1"
LN_personalSignature = "personalSignature"
LN_personalTitle = "personalTitle"
LN_physicalDeliveryOfficeName = "physicalDeliveryOfficeName"
LN_pilotAttributeSyntax = "pilotAttributeSyntax"
LN_pilotAttributeType = "pilotAttributeType"
LN_pilotAttributeType27 = "pilotAttributeType27"
LN_pilotDSA = "pilotDSA"
LN_pilotGroups = "pilotGroups"
LN_pilotObject = "pilotObject"
LN_pilotObjectClass = "pilotObjectClass"
LN_pilotOrganization = "pilotOrganization"
LN_pilotPerson = "pilotPerson"
LN_pkcs = "RSA Data Security, Inc. PKCS"
LN_pkcs7_data = "pkcs7-data"
LN_pkcs7_digest = "pkcs7-digestData"
LN_pkcs7_encrypted = "pkcs7-encryptedData"
LN_pkcs7_enveloped = "pkcs7-envelopedData"
LN_pkcs7_signed = "pkcs7-signedData"
LN_pkcs7_signedAndEnveloped = "pkcs7-signedAndEnvelopedData"
LN_pkcs8ShroudedKeyBag = "pkcs8ShroudedKeyBag"
LN_pkcs9_challengePassword = "challengePassword"
LN_pkcs9_contentType = "contentType"
LN_pkcs9_countersignature = "countersignature"
LN_pkcs9_emailAddress = "emailAddress"
LN_pkcs9_extCertAttributes = "extendedCertificateAttributes"
LN_pkcs9_messageDigest = "messageDigest"
LN_pkcs9_signingTime = "signingTime"
LN_pkcs9_unstructuredAddress = "unstructuredAddress"
LN_pkcs9_unstructuredName = "unstructuredName"
LN_policy_constraints = "X509v3 Policy Constraints"
LN_policy_mappings = "X509v3 Policy Mappings"
LN_postalAddress = "postalAddress"
LN_postalCode = "postalCode"
LN_postOfficeBox = "postOfficeBox"
LN_preferredDeliveryMethod = "preferredDeliveryMethod"
LN_presentationAddress = "presentationAddress"
LN_Private = "Private"
LN_private_key_usage_period = "X509v3 Private Key Usage Period"
LN_protocolInformation = "protocolInformation"
LN_proxyCertInfo = "Proxy Certificate Information"
LN_pseudonym = "pseudonym"
LN_qualityLabelledData = "qualityLabelledData"
LN_rc2_40_cbc = "rc2-40-cbc"
LN_rc2_64_cbc = "rc2-64-cbc"
LN_rc2_cbc = "rc2-cbc"
LN_rc2_cfb64 = "rc2-cfb"
LN_rc2_ecb = "rc2-ecb"
LN_rc2_ofb64 = "rc2-ofb"
LN_rc4 = "rc4"
LN_rc4_40 = "rc4-40"
LN_rc4_hmac_md5 = "rc4-hmac-md5"
LN_rc5_cbc = "rc5-cbc"
LN_rc5_cfb64 = "rc5-cfb"
LN_rc5_ecb = "rc5-ecb"
LN_rc5_ofb64 = "rc5-ofb"
LN_registeredAddress = "registeredAddress"
LN_rFC822localPart = "rFC822localPart"
LN_rfc822Mailbox = "rfc822Mailbox"
LN_ripemd160 = "ripemd160"
LN_ripemd160WithRSA = "ripemd160WithRSA"
LN_rle_compression = "run length compression"
LN_role = "role"
LN_roleOccupant = "roleOccupant"
LN_roomNumber = "roomNumber"
LN_rsa = "rsa"
LN_rsadsi = "RSA Data Security, Inc."
LN_rsaEncryption = "rsaEncryption"
LN_rsaesOaep = "rsaesOaep"
LN_rsassaPss = "rsassaPss"
LN_safeContentsBag = "safeContentsBag"
LN_sdsiCertificate = "sdsiCertificate"
LN_searchGuide = "searchGuide"
LN_secretBag = "secretBag"
LN_Security = "Security"
LN_seed_cbc = "seed-cbc"
LN_seed_cfb128 = "seed-cfb"
LN_seed_ecb = "seed-ecb"
LN_seed_ofb128 = "seed-ofb"
LN_selected_attribute_types = "Selected Attribute Types"
LN_serialNumber = "serialNumber"
LN_server_auth = "TLS Web Server Authentication"
LN_set_certExt = "certificate extensions"
LN_set_ctype = "content types"
LN_set_msgExt = "message extensions"
LN_setAttr_GenCryptgrm = "generate cryptogram"
LN_setAttr_IssCap = "issuer capabilities"
LN_setAttr_PGWYcap = "payment gateway capabilities"
LN_setAttr_SecDevSig = "secure device signature"
LN_setAttr_T2cleartxt = "cleartext track 2"
LN_setAttr_T2Enc = "encrypted track 2"
LN_setAttr_TokICCsig = "ICC or token signature"
LN_setext_cv = "additional verification"
LN_setext_genCrypt = "generic cryptogram"
LN_setext_miAuth = "merchant initiated auth"
LN_sha = "sha"
LN_sha1 = "sha1"
LN_sha1WithRSA = "sha1WithRSA"
LN_sha1WithRSAEncryption = "sha1WithRSAEncryption"
LN_sha224 = "sha224"
LN_sha224WithRSAEncryption = "sha224WithRSAEncryption"
LN_sha256 = "sha256"
LN_sha256WithRSAEncryption = "sha256WithRSAEncryption"
LN_sha384 = "sha384"
LN_sha384WithRSAEncryption = "sha384WithRSAEncryption"
LN_sha512 = "sha512"
LN_sha512WithRSAEncryption = "sha512WithRSAEncryption"
LN_shaWithRSAEncryption = "shaWithRSAEncryption"
LN_simpleSecurityObject = "simpleSecurityObject"
LN_sinfo_access = "Subject Information Access"
LN_singleLevelQuality = "singleLevelQuality"
LN_SMIME = "S/MIME"
LN_SMIMECapabilities = "S/MIME Capabilities"
LN_SNMPv2 = "SNMPv2"
LN_sOARecord = "sOARecord"
LN_stateOrProvinceName = "stateOrProvinceName"
LN_streetAddress = "streetAddress"
LN_subject_alt_name = "X509v3 Subject Alternative Name"
LN_subject_directory_attributes = "X509v3 Subject Directory Attributes"
LN_subject_key_identifier = "X509v3 Subject Key Identifier"
LN_subtreeMaximumQuality = "subtreeMaximumQuality"
LN_subtreeMinimumQuality = "subtreeMinimumQuality"
LN_supportedAlgorithms = "supportedAlgorithms"
LN_supportedApplicationContext = "supportedApplicationContext"
LN_surname = "surname"
LN_sxnet = "Strong Extranet ID"
LN_target_information = "X509v3 AC Targeting"
LN_telephoneNumber = "telephoneNumber"
LN_teletexTerminalIdentifier = "teletexTerminalIdentifier"
LN_telexNumber = "telexNumber"
LN_textEncodedORAddress = "textEncodedORAddress"
LN_time_stamp = "Time Stamping"
LN_title = "title"
LN_undef = "undefined"
LN_uniqueMember = "uniqueMember"
LN_userCertificate = "userCertificate"
LN_userClass = "userClass"
LN_userId = "userId"
LN_userPassword = "userPassword"
LN_x121Address = "x121Address"
LN_X500 = "directory services (X.500)"
LN_X500algorithms = "directory services - algorithms"
LN_x500UniqueIdentifier = "x500UniqueIdentifier"
LN_x509Certificate = "x509Certificate"
LN_x509Crl = "x509Crl"
LN_X9_57 = "X9.57"
LN_X9cm = "X9.57 CM ?"
LN_zlib_compression = "zlib compression"
MBSTRING_FLAG = 0x1000
MBSTRING_UTF8 = (MBSTRING_FLAG)
NFDBITS = __NFDBITS
NID_aaControls = 289
NID_ac_auditEntity = 287
NID_ac_proxying = 397
NID_ac_targeting = 288
NID_account = 446
NID_ad_ca_issuers = 179
NID_ad_dvcs = 364
NID_ad_OCSP = 178
NID_ad_timeStamping = 363
NID_aes_128_cbc = 419
NID_aes_128_cbc_hmac_sha1 = 916
NID_aes_128_ccm = 896
NID_aes_128_cfb1 = 650
NID_aes_128_cfb128 = 421
NID_aes_128_cfb8 = 653
NID_aes_128_ctr = 904
NID_aes_128_ecb = 418
NID_aes_128_gcm = 895
NID_aes_128_ofb128 = 420
NID_aes_128_xts = 913
NID_aes_192_cbc = 423
NID_aes_192_cbc_hmac_sha1 = 917
NID_aes_192_ccm = 899
NID_aes_192_cfb1 = 651
NID_aes_192_cfb128 = 425
NID_aes_192_cfb8 = 654
NID_aes_192_ctr = 905
NID_aes_192_ecb = 422
NID_aes_192_gcm = 898
NID_aes_192_ofb128 = 424
NID_aes_256_cbc = 427
NID_aes_256_cbc_hmac_sha1 = 918
NID_aes_256_ccm = 902
NID_aes_256_cfb1 = 652
NID_aes_256_cfb128 = 429
NID_aes_256_cfb8 = 655
NID_aes_256_ctr = 906
NID_aes_256_ecb = 426
NID_aes_256_gcm = 901
NID_aes_256_ofb128 = 428
NID_aes_256_xts = 914
NID_algorithm = 376
NID_ansi_X9_62 = 405
NID_any_policy = 746
NID_anyExtendedKeyUsage = 910
NID_aRecord = 478
NID_associatedDomain = 484
NID_associatedName = 485
NID_audio = 501
NID_authority_key_identifier = 90
NID_authorityRevocationList = 882
NID_basic_constraints = 87
NID_bf_cbc = 91
NID_bf_cfb64 = 93
NID_bf_ecb = 92
NID_bf_ofb64 = 94
NID_biometricInfo = 285
NID_buildingName = 494
NID_businessCategory = 860
NID_cACertificate = 881
NID_camellia_128_cbc = 751
NID_camellia_128_cfb1 = 760
NID_camellia_128_cfb128 = 757
NID_camellia_128_cfb8 = 763
NID_camellia_128_ecb = 754
NID_camellia_128_ofb128 = 766
NID_camellia_192_cbc = 752
NID_camellia_192_cfb1 = 761
NID_camellia_192_cfb128 = 758
NID_camellia_192_cfb8 = 764
NID_camellia_192_ecb = 755
NID_camellia_192_ofb128 = 767
NID_camellia_256_cbc = 753
NID_camellia_256_cfb1 = 762
NID_camellia_256_cfb128 = 759
NID_camellia_256_cfb8 = 765
NID_camellia_256_ecb = 756
NID_camellia_256_ofb128 = 768
NID_caRepository = 785
NID_caseIgnoreIA5StringSyntax = 443
NID_cast5_cbc = 108
NID_cast5_cfb64 = 110
NID_cast5_ecb = 109
NID_cast5_ofb64 = 111
NID_ccitt = 404
NID_certBag = 152
NID_certicom_arc = 677
NID_certificate_issuer = 771
NID_certificate_policies = 89
NID_certificateRevocationList = 883
NID_clearance = 395
NID_client_auth = 130
NID_cmac = 894
NID_cNAMERecord = 483
NID_code_sign = 131
NID_commonName = 13
NID_countryName = 14
NID_crl_distribution_points = 103
NID_crl_number = 88
NID_crl_reason = 141
NID_crlBag = 153
NID_crossCertificatePair = 884
NID_cryptocom = 806
NID_cryptopro = 805
NID_data = 434
NID_dcObject = 390
NID_delta_crl = 140
NID_deltaRevocationList = 891
NID_des_cbc = 31
NID_des_cdmf = 643
NID_des_cfb1 = 656
NID_des_cfb64 = 30
NID_des_cfb8 = 657
NID_des_ecb = 29
NID_des_ede3_cbc = 44
NID_des_ede3_cfb1 = 658
NID_des_ede3_cfb64 = 61
NID_des_ede3_cfb8 = 659
NID_des_ede3_ecb = 33
NID_des_ede3_ofb64 = 63
NID_des_ede_cbc = 43
NID_des_ede_cfb64 = 60
NID_des_ede_ecb = 32
NID_des_ede_ofb64 = 62
NID_des_ofb64 = 45
NID_description = 107
NID_destinationIndicator = 871
NID_desx_cbc = 80
NID_dhKeyAgreement = 28
NID_Directory = 382
NID_distinguishedName = 887
NID_dITRedirect = 500
NID_dmdName = 892
NID_dnQualifier = 174
NID_dNSDomain = 451
NID_document = 447
NID_documentAuthor = 471
NID_documentIdentifier = 468
NID_documentLocation = 472
NID_documentPublisher = 502
NID_documentSeries = 449
NID_documentTitle = 469
NID_documentVersion = 470
NID_dod = 380
NID_Domain = 392
NID_domainComponent = 391
NID_domainRelatedObject = 452
NID_dsa = 116
NID_dsa_2 = 67
NID_dsa_with_SHA224 = 802
NID_dsa_with_SHA256 = 803
NID_dSAQuality = 495
NID_dsaWithSHA = 66
NID_dsaWithSHA1 = 113
NID_dsaWithSHA1_2 = 70
NID_dvcs = 297
NID_ecdsa_with_Recommended = 791
NID_ecdsa_with_SHA1 = 416
NID_ecdsa_with_SHA224 = 793
NID_ecdsa_with_SHA256 = 794
NID_ecdsa_with_SHA384 = 795
NID_ecdsa_with_SHA512 = 796
NID_ecdsa_with_Specified = 792
NID_email_protect = 132
NID_enhancedSearchGuide = 885
NID_Enterprises = 389
NID_Experimental = 384
NID_ext_key_usage = 126
NID_ext_req = 172
NID_facsimileTelephoneNumber = 867
NID_favouriteDrink = 462
NID_freshest_crl = 857
NID_friendlyCountry = 453
NID_friendlyCountryName = 490
NID_friendlyName = 156
NID_generationQualifier = 509
NID_givenName = 99
NID_gost89_cnt = 814
NID_hmac = 855
NID_hmac_md5 = 780
NID_hmac_sha1 = 781
NID_hmacWithMD5 = 797
NID_hmacWithSHA1 = 163
NID_hmacWithSHA224 = 798
NID_hmacWithSHA256 = 799
NID_hmacWithSHA384 = 800
NID_hmacWithSHA512 = 801
NID_hold_instruction_call_issuer = 432
NID_hold_instruction_code = 430
NID_hold_instruction_none = 431
NID_hold_instruction_reject = 433
NID_homePostalAddress = 486
NID_homeTelephoneNumber = 473
NID_host = 466
NID_houseIdentifier = 889
NID_iA5StringSyntax = 442
NID_iana = 381
NID_id_aca = 266
NID_id_aca_accessIdentity = 355
NID_id_aca_authenticationInfo = 354
NID_id_aca_chargingIdentity = 356
NID_id_aca_encAttrs = 399
NID_id_aca_group = 357
NID_id_aca_role = 358
NID_id_ad = 176
NID_id_aes128_wrap = 788
NID_id_aes128_wrap_pad = 897
NID_id_aes192_wrap = 789
NID_id_aes192_wrap_pad = 900
NID_id_aes256_wrap = 790
NID_id_aes256_wrap_pad = 903
NID_id_alg = 262
NID_id_alg_des40 = 323
NID_id_alg_dh_pop = 326
NID_id_alg_dh_sig_hmac_sha1 = 325
NID_id_alg_noSignature = 324
NID_id_alg_PWRI_KEK = 893
NID_id_camellia128_wrap = 907
NID_id_camellia192_wrap = 908
NID_id_camellia256_wrap = 909
NID_id_cct = 268
NID_id_cct_crs = 360
NID_id_cct_PKIData = 361
NID_id_cct_PKIResponse = 362
NID_id_ce = 81
NID_id_cmc = 263
NID_id_cmc_addExtensions = 334
NID_id_cmc_confirmCertAcceptance = 346
NID_id_cmc_dataReturn = 330
NID_id_cmc_decryptedPOP = 336
NID_id_cmc_encryptedPOP = 335
NID_id_cmc_getCert = 338
NID_id_cmc_getCRL = 339
NID_id_cmc_identification = 328
NID_id_cmc_identityProof = 329
NID_id_cmc_lraPOPWitness = 337
NID_id_cmc_popLinkRandom = 344
NID_id_cmc_popLinkWitness = 345
NID_id_cmc_queryPending = 343
NID_id_cmc_recipientNonce = 333
NID_id_cmc_regInfo = 341
NID_id_cmc_responseInfo = 342
NID_id_cmc_revokeRequest = 340
NID_id_cmc_senderNonce = 332
NID_id_cmc_statusInfo = 327
NID_id_cmc_transactionId = 331
NID_id_ct_asciiTextWithCRLF = 787
NID_id_DHBasedMac = 783
NID_id_Gost28147_89 = 813
NID_id_Gost28147_89_cc = 849
NID_id_Gost28147_89_CryptoPro_A_ParamSet = 824
NID_id_Gost28147_89_CryptoPro_B_ParamSet = 825
NID_id_Gost28147_89_CryptoPro_C_ParamSet = 826
NID_id_Gost28147_89_CryptoPro_D_ParamSet = 827
NID_id_Gost28147_89_CryptoPro_KeyMeshing = 819
NID_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet = 829
NID_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet = 828
NID_id_Gost28147_89_CryptoPro_RIC_1_ParamSet = 830
NID_id_Gost28147_89_MAC = 815
NID_id_Gost28147_89_None_KeyMeshing = 820
NID_id_Gost28147_89_TestParamSet = 823
NID_id_GostR3410_2001 = 811
NID_id_GostR3410_2001_cc = 851
NID_id_GostR3410_2001_CryptoPro_A_ParamSet = 840
NID_id_GostR3410_2001_CryptoPro_B_ParamSet = 841
NID_id_GostR3410_2001_CryptoPro_C_ParamSet = 842
NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet = 843
NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet = 844
NID_id_GostR3410_2001_ParamSet_cc = 854
NID_id_GostR3410_2001_TestParamSet = 839
NID_id_GostR3410_2001DH = 817
NID_id_GostR3410_94 = 812
NID_id_GostR3410_94_a = 845
NID_id_GostR3410_94_aBis = 846
NID_id_GostR3410_94_b = 847
NID_id_GostR3410_94_bBis = 848
NID_id_GostR3410_94_cc = 850
NID_id_GostR3410_94_CryptoPro_A_ParamSet = 832
NID_id_GostR3410_94_CryptoPro_B_ParamSet = 833
NID_id_GostR3410_94_CryptoPro_C_ParamSet = 834
NID_id_GostR3410_94_CryptoPro_D_ParamSet = 835
NID_id_GostR3410_94_CryptoPro_XchA_ParamSet = 836
NID_id_GostR3410_94_CryptoPro_XchB_ParamSet = 837
NID_id_GostR3410_94_CryptoPro_XchC_ParamSet = 838
NID_id_GostR3410_94_TestParamSet = 831
NID_id_GostR3410_94DH = 818
NID_id_GostR3411_94 = 809
NID_id_GostR3411_94_CryptoProParamSet = 822
NID_id_GostR3411_94_prf = 816
NID_id_GostR3411_94_TestParamSet = 821
NID_id_GostR3411_94_with_GostR3410_2001 = 807
NID_id_GostR3411_94_with_GostR3410_2001_cc = 853
NID_id_GostR3411_94_with_GostR3410_94 = 808
NID_id_GostR3411_94_with_GostR3410_94_cc = 852
NID_id_hex_multipart_message = 508
NID_id_hex_partial_message = 507
NID_id_HMACGostR3411_94 = 810
NID_id_it = 260
NID_id_it_caKeyUpdateInfo = 302
NID_id_it_caProtEncCert = 298
NID_id_it_confirmWaitTime = 311
NID_id_it_currentCRL = 303
NID_id_it_encKeyPairTypes = 300
NID_id_it_implicitConfirm = 310
NID_id_it_keyPairParamRep = 308
NID_id_it_keyPairParamReq = 307
NID_id_it_origPKIMessage = 312
NID_id_it_preferredSymmAlg = 301
NID_id_it_revPassphrase = 309
NID_id_it_signKeyPairTypes = 299
NID_id_it_subscriptionRequest = 305
NID_id_it_subscriptionResponse = 306
NID_id_it_suppLangTags = 784
NID_id_it_unsupportedOIDs = 304
NID_id_kp = 128
NID_id_mod_attribute_cert = 280
NID_id_mod_cmc = 274
NID_id_mod_cmp = 277
NID_id_mod_cmp2000 = 284
NID_id_mod_crmf = 273
NID_id_mod_dvcs = 283
NID_id_mod_kea_profile_88 = 275
NID_id_mod_kea_profile_93 = 276
NID_id_mod_ocsp = 282
NID_id_mod_qualified_cert_88 = 278
NID_id_mod_qualified_cert_93 = 279
NID_id_mod_timestamp_protocol = 281
NID_id_on = 264
NID_id_on_permanentIdentifier = 858
NID_id_on_personalData = 347
NID_id_PasswordBasedMAC = 782
NID_id_pbkdf2 = 69
NID_id_pda = 265
NID_id_pda_countryOfCitizenship = 352
NID_id_pda_countryOfResidence = 353
NID_id_pda_dateOfBirth = 348
NID_id_pda_gender = 351
NID_id_pda_placeOfBirth = 349
NID_id_pe = 175
NID_id_pkip = 261
NID_id_pkix = 127
NID_id_pkix1_explicit_88 = 269
NID_id_pkix1_explicit_93 = 271
NID_id_pkix1_implicit_88 = 270
NID_id_pkix1_implicit_93 = 272
NID_id_pkix_mod = 258
NID_id_pkix_OCSP_acceptableResponses = 368
NID_id_pkix_OCSP_archiveCutoff = 370
NID_id_pkix_OCSP_basic = 365
NID_id_pkix_OCSP_CrlID = 367
NID_id_pkix_OCSP_extendedStatus = 372
NID_id_pkix_OCSP_noCheck = 369
NID_id_pkix_OCSP_Nonce = 366
NID_id_pkix_OCSP_path = 374
NID_id_pkix_OCSP_serviceLocator = 371
NID_id_pkix_OCSP_trustRoot = 375
NID_id_pkix_OCSP_valid = 373
NID_id_ppl = 662
NID_id_ppl_anyLanguage = 664
NID_id_ppl_inheritAll = 665
NID_id_qcs = 267
NID_id_qcs_pkixQCSyntax_v1 = 359
NID_id_qt = 259
NID_id_qt_cps = 164
NID_id_qt_unotice = 165
NID_id_regCtrl = 313
NID_id_regCtrl_authenticator = 316
NID_id_regCtrl_oldCertID = 319
NID_id_regCtrl_pkiArchiveOptions = 318
NID_id_regCtrl_pkiPublicationInfo = 317
NID_id_regCtrl_protocolEncrKey = 320
NID_id_regCtrl_regToken = 315
NID_id_regInfo = 314
NID_id_regInfo_certReq = 322
NID_id_regInfo_utf8Pairs = 321
NID_id_set = 512
NID_id_smime_aa = 191
NID_id_smime_aa_contentHint = 215
NID_id_smime_aa_contentIdentifier = 218
NID_id_smime_aa_contentReference = 221
NID_id_smime_aa_dvcs_dvc = 240
NID_id_smime_aa_encapContentType = 217
NID_id_smime_aa_encrypKeyPref = 222
NID_id_smime_aa_equivalentLabels = 220
NID_id_smime_aa_ets_archiveTimeStamp = 238
NID_id_smime_aa_ets_certCRLTimestamp = 237
NID_id_smime_aa_ets_CertificateRefs = 232
NID_id_smime_aa_ets_certValues = 234
NID_id_smime_aa_ets_commitmentType = 227
NID_id_smime_aa_ets_contentTimestamp = 231
NID_id_smime_aa_ets_escTimeStamp = 236
NID_id_smime_aa_ets_otherSigCert = 230
NID_id_smime_aa_ets_RevocationRefs = 233
NID_id_smime_aa_ets_revocationValues = 235
NID_id_smime_aa_ets_signerAttr = 229
NID_id_smime_aa_ets_signerLocation = 228
NID_id_smime_aa_ets_sigPolicyId = 226
NID_id_smime_aa_macValue = 219
NID_id_smime_aa_mlExpandHistory = 214
NID_id_smime_aa_msgSigDigest = 216
NID_id_smime_aa_receiptRequest = 212
NID_id_smime_aa_securityLabel = 213
NID_id_smime_aa_signatureType = 239
NID_id_smime_aa_signingCertificate = 223
NID_id_smime_aa_smimeEncryptCerts = 224
NID_id_smime_aa_timeStampToken = 225
NID_id_smime_alg = 192
NID_id_smime_alg_3DESwrap = 243
NID_id_smime_alg_CMS3DESwrap = 246
NID_id_smime_alg_CMSRC2wrap = 247
NID_id_smime_alg_ESDH = 245
NID_id_smime_alg_ESDHwith3DES = 241
NID_id_smime_alg_ESDHwithRC2 = 242
NID_id_smime_alg_RC2wrap = 244
NID_id_smime_cd = 193
NID_id_smime_cd_ldap = 248
NID_id_smime_ct = 190
NID_id_smime_ct_authData = 205
NID_id_smime_ct_compressedData = 786
NID_id_smime_ct_contentInfo = 209
NID_id_smime_ct_DVCSRequestData = 210
NID_id_smime_ct_DVCSResponseData = 211
NID_id_smime_ct_publishCert = 206
NID_id_smime_ct_receipt = 204
NID_id_smime_ct_TDTInfo = 208
NID_id_smime_ct_TSTInfo = 207
NID_id_smime_cti = 195
NID_id_smime_cti_ets_proofOfApproval = 255
NID_id_smime_cti_ets_proofOfCreation = 256
NID_id_smime_cti_ets_proofOfDelivery = 253
NID_id_smime_cti_ets_proofOfOrigin = 251
NID_id_smime_cti_ets_proofOfReceipt = 252
NID_id_smime_cti_ets_proofOfSender = 254
NID_id_smime_mod = 189
NID_id_smime_mod_cms = 196
NID_id_smime_mod_ess = 197
NID_id_smime_mod_ets_eSignature_88 = 200
NID_id_smime_mod_ets_eSignature_97 = 201
NID_id_smime_mod_ets_eSigPolicy_88 = 202
NID_id_smime_mod_ets_eSigPolicy_97 = 203
NID_id_smime_mod_msg_v3 = 199
NID_id_smime_mod_oid = 198
NID_id_smime_spq = 194
NID_id_smime_spq_ets_sqt_unotice = 250
NID_id_smime_spq_ets_sqt_uri = 249
NID_idea_cbc = 34
NID_idea_cfb64 = 35
NID_idea_ecb = 36
NID_idea_ofb64 = 46
NID_identified_organization = 676
NID_Independent = 667
NID_info = 461
NID_info_access = 177
NID_inhibit_any_policy = 748
NID_initials = 101
NID_international_organizations = 647
NID_internationaliSDNNumber = 869
NID_invalidity_date = 142
NID_ipsec3 = 749
NID_ipsec4 = 750
NID_ipsecEndSystem = 294
NID_ipsecTunnel = 295
NID_ipsecUser = 296
NID_iso = 181
NID_ISO_US = 183
NID_issuer_alt_name = 86
NID_issuing_distribution_point = 770
NID_itu_t = 645
NID_janetMailbox = 492
NID_joint_iso_ccitt = 393
NID_joint_iso_itu_t = 646
NID_key_usage = 83
NID_keyBag = 150
NID_kisa = 773
NID_lastModifiedBy = 477
NID_lastModifiedTime = 476
NID_localityName = 15
NID_localKeyID = 157
NID_LocalKeySet = 856
NID_Mail = 388
NID_mailPreferenceOption = 493
NID_Management = 383
NID_manager = 467
NID_md2 = 3
NID_md2WithRSAEncryption = 7
NID_md4 = 257
NID_md4WithRSAEncryption = 396
NID_md5 = 4
NID_md5_sha1 = 114
NID_md5WithRSA = 104
NID_md5WithRSAEncryption = 8
NID_mdc2 = 95
NID_mdc2WithRSA = 96
NID_member = 875
NID_member_body = 182
NID_mgf1 = 911
NID_mime_mhs = 504
NID_mime_mhs_bodies = 506
NID_mime_mhs_headings = 505
NID_mobileTelephoneNumber = 488
NID_ms_code_com = 135
NID_ms_code_ind = 134
NID_ms_csp_name = 417
NID_ms_ctl_sign = 136
NID_ms_efs = 138
NID_ms_ext_req = 171
NID_ms_sgc = 137
NID_ms_smartcard_login = 648
NID_ms_upn = 649
NID_mXRecord = 480
NID_name = 173
NID_name_constraints = 666
NID_netscape = 57
NID_netscape_base_url = 72
NID_netscape_ca_policy_url = 76
NID_netscape_ca_revocation_url = 74
NID_netscape_cert_extension = 58
NID_netscape_cert_sequence = 79
NID_netscape_cert_type = 71
NID_netscape_comment = 78
NID_netscape_data_type = 59
NID_netscape_renewal_url = 75
NID_netscape_revocation_url = 73
NID_netscape_ssl_server_name = 77
NID_no_rev_avail = 403
NID_ns_sgc = 139
NID_nSRecord = 481
NID_OCSP_sign = 180
NID_org = 379
NID_organizationalStatus = 491
NID_organizationalUnitName = 18
NID_organizationName = 17
NID_otherMailbox = 475
NID_owner = 876
NID_pagerTelephoneNumber = 489
NID_pbe_WithSHA1And128BitRC2_CBC = 148
NID_pbe_WithSHA1And128BitRC4 = 144
NID_pbe_WithSHA1And2_Key_TripleDES_CBC = 147
NID_pbe_WithSHA1And3_Key_TripleDES_CBC = 146
NID_pbe_WithSHA1And40BitRC2_CBC = 149
NID_pbe_WithSHA1And40BitRC4 = 145
NID_pbes2 = 161
NID_pbeWithMD2AndDES_CBC = 9
NID_pbeWithMD2AndRC2_CBC = 168
NID_pbeWithMD5AndCast5_CBC = 112
NID_pbeWithMD5AndDES_CBC = 10
NID_pbeWithMD5AndRC2_CBC = 169
NID_pbeWithSHA1AndDES_CBC = 170
NID_pbeWithSHA1AndRC2_CBC = 68
NID_pbmac1 = 162
NID_personalSignature = 499
NID_personalTitle = 487
NID_photo = 464
NID_physicalDeliveryOfficeName = 863
NID_pilot = 437
NID_pilotAttributeSyntax = 439
NID_pilotAttributeType = 438
NID_pilotAttributeType27 = 479
NID_pilotDSA = 456
NID_pilotGroups = 441
NID_pilotObject = 444
NID_pilotObjectClass = 440
NID_pilotOrganization = 455
NID_pilotPerson = 445
NID_pkcs = 2
NID_pkcs1 = 186
NID_pkcs3 = 27
NID_pkcs5 = 187
NID_pkcs7 = 20
NID_pkcs7_data = 21
NID_pkcs7_digest = 25
NID_pkcs7_encrypted = 26
NID_pkcs7_enveloped = 23
NID_pkcs7_signed = 22
NID_pkcs7_signedAndEnveloped = 24
NID_pkcs8ShroudedKeyBag = 151
NID_pkcs9 = 47
NID_pkcs9_challengePassword = 54
NID_pkcs9_contentType = 50
NID_pkcs9_countersignature = 53
NID_pkcs9_emailAddress = 48
NID_pkcs9_extCertAttributes = 56
NID_pkcs9_messageDigest = 51
NID_pkcs9_signingTime = 52
NID_pkcs9_unstructuredAddress = 55
NID_pkcs9_unstructuredName = 49
NID_policy_constraints = 401
NID_policy_mappings = 747
NID_postalAddress = 861
NID_postalCode = 661
NID_postOfficeBox = 862
NID_preferredDeliveryMethod = 872
NID_presentationAddress = 873
NID_Private = 385
NID_private_key_usage_period = 84
NID_protocolInformation = 886
NID_proxyCertInfo = 663
NID_pseudonym = 510
NID_pss = 435
NID_qcStatements = 286
NID_qualityLabelledData = 457
NID_rc2_40_cbc = 98
NID_rc2_64_cbc = 166
NID_rc2_cbc = 37
NID_rc2_cfb64 = 39
NID_rc2_ecb = 38
NID_rc2_ofb64 = 40
NID_rc4 = 5
NID_rc4_40 = 97
NID_rc4_hmac_md5 = 915
NID_rc5_cbc = 120
NID_rc5_cfb64 = 122
NID_rc5_ecb = 121
NID_rc5_ofb64 = 123
NID_registeredAddress = 870
NID_rFC822localPart = 450
NID_rfc822Mailbox = 460
NID_ripemd160 = 117
NID_ripemd160WithRSA = 119
NID_rle_compression = 124
NID_role = 400
NID_roleOccupant = 877
NID_room = 448
NID_roomNumber = 463
NID_rsa = 19
NID_rsadsi = 1
NID_rsaEncryption = 6
NID_rsaesOaep = 919
NID_rsaOAEPEncryptionSET = 644
NID_rsaSignature = 377
NID_rsassaPss = 912
NID_safeContentsBag = 155
NID_sbgp_autonomousSysNum = 291
NID_sbgp_ipAddrBlock = 290
NID_sbgp_routerIdentifier = 292
NID_sdsiCertificate = 159
NID_searchGuide = 859
NID_secp112r1 = 704
NID_secp112r2 = 705
NID_secp128r1 = 706
NID_secp128r2 = 707
NID_secp160k1 = 708
NID_secp160r1 = 709
NID_secp160r2 = 710
NID_secp192k1 = 711
NID_secp224k1 = 712
NID_secp224r1 = 713
NID_secp256k1 = 714
NID_secp384r1 = 715
NID_secp521r1 = 716
NID_secretary = 474
NID_secretBag = 154
NID_sect113r1 = 717
NID_sect113r2 = 718
NID_sect131r1 = 719
NID_sect131r2 = 720
NID_sect163k1 = 721
NID_sect163r1 = 722
NID_sect163r2 = 723
NID_sect193r1 = 724
NID_sect193r2 = 725
NID_sect233k1 = 726
NID_sect233r1 = 727
NID_sect239k1 = 728
NID_sect283k1 = 729
NID_sect283r1 = 730
NID_sect409k1 = 731
NID_sect409r1 = 732
NID_sect571k1 = 733
NID_sect571r1 = 734
NID_Security = 386
NID_seeAlso = 878
NID_seed_cbc = 777
NID_seed_cfb128 = 779
NID_seed_ecb = 776
NID_seed_ofb128 = 778
NID_selected_attribute_types = 394
NID_serialNumber = 105
NID_server_auth = 129
NID_set_addPolicy = 625
NID_set_attr = 515
NID_set_brand = 518
NID_set_brand_AmericanExpress = 638
NID_set_brand_Diners = 637
NID_set_brand_IATA_ATA = 636
NID_set_brand_JCB = 639
NID_set_brand_MasterCard = 641
NID_set_brand_Novus = 642
NID_set_brand_Visa = 640
NID_set_certExt = 517
NID_set_ctype = 513
NID_set_msgExt = 514
NID_set_policy = 516
NID_set_policy_root = 607
NID_set_rootKeyThumb = 624
NID_setAttr_Cert = 620
NID_setAttr_GenCryptgrm = 631
NID_setAttr_IssCap = 623
NID_setAttr_IssCap_CVM = 628
NID_setAttr_IssCap_Sig = 630
NID_setAttr_IssCap_T2 = 629
NID_setAttr_PGWYcap = 621
NID_setAttr_SecDevSig = 635
NID_setAttr_T2cleartxt = 633
NID_setAttr_T2Enc = 632
NID_setAttr_Token_B0Prime = 627
NID_setAttr_Token_EMV = 626
NID_setAttr_TokenType = 622
NID_setAttr_TokICCsig = 634
NID_setCext_cCertRequired = 611
NID_setCext_certType = 609
NID_setCext_hashedRoot = 608
NID_setCext_IssuerCapabilities = 619
NID_setCext_merchData = 610
NID_setCext_PGWYcapabilities = 615
NID_setCext_setExt = 613
NID_setCext_setQualf = 614
NID_setCext_TokenIdentifier = 616
NID_setCext_TokenType = 618
NID_setCext_Track2Data = 617
NID_setCext_tunneling = 612
NID_setct_AcqCardCodeMsg = 540
NID_setct_AcqCardCodeMsgTBE = 576
NID_setct_AuthReqTBE = 570
NID_setct_AuthReqTBS = 534
NID_setct_AuthResBaggage = 527
NID_setct_AuthResTBE = 571
NID_setct_AuthResTBEX = 572
NID_setct_AuthResTBS = 535
NID_setct_AuthResTBSX = 536
NID_setct_AuthRevReqBaggage = 528
NID_setct_AuthRevReqTBE = 577
NID_setct_AuthRevReqTBS = 541
NID_setct_AuthRevResBaggage = 529
NID_setct_AuthRevResData = 542
NID_setct_AuthRevResTBE = 578
NID_setct_AuthRevResTBEB = 579
NID_setct_AuthRevResTBS = 543
NID_setct_AuthTokenTBE = 573
NID_setct_AuthTokenTBS = 537
NID_setct_BatchAdminReqData = 558
NID_setct_BatchAdminReqTBE = 592
NID_setct_BatchAdminResData = 559
NID_setct_BatchAdminResTBE = 593
NID_setct_BCIDistributionTBS = 600
NID_setct_CapReqTBE = 580
NID_setct_CapReqTBEX = 581
NID_setct_CapReqTBS = 544
NID_setct_CapReqTBSX = 545
NID_setct_CapResData = 546
NID_setct_CapResTBE = 582
NID_setct_CapRevReqTBE = 583
NID_setct_CapRevReqTBEX = 584
NID_setct_CapRevReqTBS = 547
NID_setct_CapRevReqTBSX = 548
NID_setct_CapRevResData = 549
NID_setct_CapRevResTBE = 585
NID_setct_CapTokenData = 538
NID_setct_CapTokenSeq = 530
NID_setct_CapTokenTBE = 574
NID_setct_CapTokenTBEX = 575
NID_setct_CapTokenTBS = 539
NID_setct_CardCInitResTBS = 560
NID_setct_CertInqReqTBS = 566
NID_setct_CertReqData = 563
NID_setct_CertReqTBE = 595
NID_setct_CertReqTBEX = 596
NID_setct_CertReqTBS = 564
NID_setct_CertResData = 565
NID_setct_CertResTBE = 597
NID_setct_CredReqTBE = 586
NID_setct_CredReqTBEX = 587
NID_setct_CredReqTBS = 550
NID_setct_CredReqTBSX = 551
NID_setct_CredResData = 552
NID_setct_CredResTBE = 588
NID_setct_CredRevReqTBE = 589
NID_setct_CredRevReqTBEX = 590
NID_setct_CredRevReqTBS = 553
NID_setct_CredRevReqTBSX = 554
NID_setct_CredRevResData = 555
NID_setct_CredRevResTBE = 591
NID_setct_CRLNotificationResTBS = 599
NID_setct_CRLNotificationTBS = 598
NID_setct_ErrorTBS = 567
NID_setct_HODInput = 526
NID_setct_MeAqCInitResTBS = 561
NID_setct_OIData = 522
NID_setct_PANData = 519
NID_setct_PANOnly = 521
NID_setct_PANToken = 520
NID_setct_PCertReqData = 556
NID_setct_PCertResTBS = 557
NID_setct_PI = 523
NID_setct_PI_TBS = 532
NID_setct_PIData = 524
NID_setct_PIDataUnsigned = 525
NID_setct_PIDualSignedTBE = 568
NID_setct_PInitResData = 531
NID_setct_PIUnsignedTBE = 569
NID_setct_PResData = 533
NID_setct_RegFormReqTBE = 594
NID_setct_RegFormResTBS = 562
NID_setext_cv = 606
NID_setext_genCrypt = 601
NID_setext_miAuth = 602
NID_setext_pinAny = 604
NID_setext_pinSecure = 603
NID_setext_track2 = 605
NID_sha = 41
NID_sha1 = 64
NID_sha1WithRSA = 115
NID_sha1WithRSAEncryption = 65
NID_sha224 = 675
NID_sha224WithRSAEncryption = 671
NID_sha256 = 672
NID_sha256WithRSAEncryption = 668
NID_sha384 = 673
NID_sha384WithRSAEncryption = 669
NID_sha512 = 674
NID_sha512WithRSAEncryption = 670
NID_shaWithRSAEncryption = 42
NID_simpleSecurityObject = 454
NID_sinfo_access = 398
NID_singleLevelQuality = 496
NID_SMIME = 188
NID_SMIMECapabilities = 167
NID_SNMPv2 = 387
NID_sOARecord = 482
NID_stateOrProvinceName = 16
NID_streetAddress = 660
NID_subject_alt_name = 85
NID_subject_directory_attributes = 769
NID_subject_key_identifier = 82
NID_subtreeMaximumQuality = 498
NID_subtreeMinimumQuality = 497
NID_supportedAlgorithms = 890
NID_supportedApplicationContext = 874
NID_surname = 100
NID_sxnet = 143
NID_target_information = 402
NID_telephoneNumber = 864
NID_teletexTerminalIdentifier = 866
NID_telexNumber = 865
NID_textEncodedORAddress = 459
NID_textNotice = 293
NID_time_stamp = 133
NID_title = 106
NID_ucl = 436
NID_undef = 0
NID_uniqueMember = 888
NID_userCertificate = 880
NID_userClass = 465
NID_userId = 458
NID_userPassword = 879
NID_wap = 678
NID_wap_wsg = 679
NID_wap_wsg_idm_ecid_wtls1 = 735
NID_wap_wsg_idm_ecid_wtls10 = 743
NID_wap_wsg_idm_ecid_wtls11 = 744
NID_wap_wsg_idm_ecid_wtls12 = 745
NID_wap_wsg_idm_ecid_wtls3 = 736
NID_wap_wsg_idm_ecid_wtls4 = 737
NID_wap_wsg_idm_ecid_wtls5 = 738
NID_wap_wsg_idm_ecid_wtls6 = 739
NID_wap_wsg_idm_ecid_wtls7 = 740
NID_wap_wsg_idm_ecid_wtls8 = 741
NID_wap_wsg_idm_ecid_wtls9 = 742
NID_whirlpool = 804
NID_x121Address = 868
NID_X500 = 11
NID_X500algorithms = 378
NID_x500UniqueIdentifier = 503
NID_X509 = 12
NID_x509Certificate = 158
NID_x509Crl = 160
NID_X9_57 = 184
NID_X9_62_c2onb191v4 = 691
NID_X9_62_c2onb191v5 = 692
NID_X9_62_c2onb239v4 = 697
NID_X9_62_c2onb239v5 = 698
NID_X9_62_c2pnb163v1 = 684
NID_X9_62_c2pnb163v2 = 685
NID_X9_62_c2pnb163v3 = 686
NID_X9_62_c2pnb176v1 = 687
NID_X9_62_c2pnb208w1 = 693
NID_X9_62_c2pnb272w1 = 699
NID_X9_62_c2pnb304w1 = 700
NID_X9_62_c2pnb368w1 = 702
NID_X9_62_c2tnb191v1 = 688
NID_X9_62_c2tnb191v2 = 689
NID_X9_62_c2tnb191v3 = 690
NID_X9_62_c2tnb239v1 = 694
NID_X9_62_c2tnb239v2 = 695
NID_X9_62_c2tnb239v3 = 696
NID_X9_62_c2tnb359v1 = 701
NID_X9_62_c2tnb431r1 = 703
NID_X9_62_characteristic_two_field = 407
NID_X9_62_id_characteristic_two_basis = 680
NID_X9_62_id_ecPublicKey = 408
NID_X9_62_onBasis = 681
NID_X9_62_ppBasis = 683
NID_X9_62_prime192v1 = 409
NID_X9_62_prime192v2 = 410
NID_X9_62_prime192v3 = 411
NID_X9_62_prime239v1 = 412
NID_X9_62_prime239v2 = 413
NID_X9_62_prime239v3 = 414
NID_X9_62_prime256v1 = 415
NID_X9_62_prime_field = 406
NID_X9_62_tpBasis = 682
NID_X9cm = 185
NID_zlib_compression = 125
OPENSSL_DH_MAX_MODULUS_BITS = 10000
OPENSSL_DSA_MAX_MODULUS_BITS = 10000
OPENSSL_EC_NAMED_CURVE = 0x001
OPENSSL_ECC_MAX_FIELD_BITS = 661
OPENSSL_EXPORT = extern
OPENSSL_EXTERN = OPENSSL_IMPORT
OPENSSL_freeFunc = CRYPTO_free
OPENSSL_IMPORT = extern
OPENSSL_NPN_NEGOTIATED = 1
OPENSSL_NPN_NO_OVERLAP = 2
OPENSSL_NPN_UNSUPPORTED = 0
OPENSSL_RSA_MAX_MODULUS_BITS = 16384
OPENSSL_RSA_MAX_PUBEXP_BITS = 64
OPENSSL_RSA_SMALL_MODULUS_BITS = 3072
OPENSSL_VERSION_NUMBER = 0x1000103f
OPENSSL_VERSION_TEXT = "OpenSSL 1.0.1c 10 May 2012"
OPENSSL_VERSION_PTEXT = " part of " .. OPENSSL_VERSION_TEXT
PDP_ENDIAN = __PDP_ENDIAN
PKCS5_DEFAULT_ITER = 2048
PKCS5_SALT_LEN = 8
PKCS7_BINARY = 0x80
PKCS7_CRLFEOL = 0x800
PKCS7_DETACHED = 0x40
PKCS7_F_B64_READ_PKCS7 = 120
PKCS7_F_B64_WRITE_PKCS7 = 121
PKCS7_F_DO_PKCS7_SIGNED_ATTRIB = 136
PKCS7_F_I2D_PKCS7_BIO_STREAM = 140
PKCS7_F_PKCS7_ADD0_ATTRIB_SIGNING_TIME = 135
PKCS7_F_PKCS7_ADD_ATTRIB_SMIMECAP = 118
PKCS7_F_PKCS7_ADD_CERTIFICATE = 100
PKCS7_F_PKCS7_ADD_CRL = 101
PKCS7_F_PKCS7_ADD_RECIPIENT_INFO = 102
PKCS7_F_PKCS7_ADD_SIGNATURE = 131
PKCS7_F_PKCS7_ADD_SIGNER = 103
PKCS7_F_PKCS7_BIO_ADD_DIGEST = 125
PKCS7_F_PKCS7_COPY_EXISTING_DIGEST = 138
PKCS7_F_PKCS7_CTRL = 104
PKCS7_F_PKCS7_DATADECODE = 112
PKCS7_F_PKCS7_DATAFINAL = 128
PKCS7_F_PKCS7_DATAINIT = 105
PKCS7_F_PKCS7_DATASIGN = 106
PKCS7_F_PKCS7_DATAVERIFY = 107
PKCS7_F_PKCS7_DECRYPT = 114
PKCS7_F_PKCS7_DECRYPT_RINFO = 133
PKCS7_F_PKCS7_ENCODE_RINFO = 132
PKCS7_F_PKCS7_ENCRYPT = 115
PKCS7_F_PKCS7_FINAL = 134
PKCS7_F_PKCS7_FIND_DIGEST = 127
PKCS7_F_PKCS7_GET0_SIGNERS = 124
PKCS7_F_PKCS7_RECIP_INFO_SET = 130
PKCS7_F_PKCS7_SET_CIPHER = 108
PKCS7_F_PKCS7_SET_CONTENT = 109
PKCS7_F_PKCS7_SET_DIGEST = 126
PKCS7_F_PKCS7_SET_TYPE = 110
PKCS7_F_PKCS7_SIGN = 116
PKCS7_F_PKCS7_SIGN_ADD_SIGNER = 137
PKCS7_F_PKCS7_SIGNATUREVERIFY = 113
PKCS7_F_PKCS7_SIGNER_INFO_SET = 129
PKCS7_F_PKCS7_SIGNER_INFO_SIGN = 139
PKCS7_F_PKCS7_SIMPLE_SMIMECAP = 119
PKCS7_F_PKCS7_VERIFY = 117
PKCS7_F_SMIME_READ_PKCS7 = 122
PKCS7_F_SMIME_TEXT = 123
PKCS7_NOATTR = 0x100
PKCS7_NOCERTS = 0x2
PKCS7_NOCHAIN = 0x8
PKCS7_NOCRL = 0x2000
PKCS7_NOINTERN = 0x10
PKCS7_NOOLDMIMETYPE = 0x400
PKCS7_NOSIGS = 0x4
PKCS7_NOSMIMECAP = 0x200
PKCS7_NOVERIFY = 0x20
PKCS7_OP_GET_DETACHED_SIGNATURE = 2
PKCS7_OP_SET_DETACHED_SIGNATURE = 1
PKCS7_PARTIAL = 0x4000
PKCS7_R_CERTIFICATE_VERIFY_ERROR = 117
PKCS7_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER = 144
PKCS7_R_CIPHER_NOT_INITIALIZED = 116
PKCS7_R_CONTENT_AND_DATA_PRESENT = 118
PKCS7_R_CTRL_ERROR = 152
PKCS7_R_DECODE_ERROR = 130
PKCS7_R_DECRYPT_ERROR = 119
PKCS7_R_DECRYPTED_KEY_IS_WRONG_LENGTH = 100
PKCS7_R_DIGEST_FAILURE = 101
PKCS7_R_ENCRYPTION_CTRL_FAILURE = 149
PKCS7_R_ENCRYPTION_NOT_SUPPORTED_FOR_THIS_KEY_TYPE = 150
PKCS7_R_ERROR_ADDING_RECIPIENT = 120
PKCS7_R_ERROR_SETTING_CIPHER = 121
PKCS7_R_INVALID_MIME_TYPE = 131
PKCS7_R_INVALID_NULL_POINTER = 143
PKCS7_R_MIME_NO_CONTENT_TYPE = 132
PKCS7_R_MIME_PARSE_ERROR = 133
PKCS7_R_MIME_SIG_PARSE_ERROR = 134
PKCS7_R_MISSING_CERIPEND_INFO = 103
PKCS7_R_NO_CONTENT = 122
PKCS7_R_NO_CONTENT_TYPE = 135
PKCS7_R_NO_DEFAULT_DIGEST = 151
PKCS7_R_NO_MATCHING_DIGEST_TYPE_FOUND = 154
PKCS7_R_NO_MULTIPART_BODY_FAILURE = 136
PKCS7_R_NO_MULTIPART_BOUNDARY = 137
PKCS7_R_NO_RECIPIENT_MATCHES_CERTIFICATE = 115
PKCS7_R_NO_RECIPIENT_MATCHES_KEY = 146
PKCS7_R_NO_SIG_CONTENT_TYPE = 138
PKCS7_R_NO_SIGNATURES_ON_DATA = 123
PKCS7_R_NO_SIGNERS = 142
PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE = 104
PKCS7_R_PKCS7_ADD_SIGNATURE_ERROR = 124
PKCS7_R_PKCS7_ADD_SIGNER_ERROR = 153
PKCS7_R_PKCS7_DATAFINAL = 126
PKCS7_R_PKCS7_DATAFINAL_ERROR = 125
PKCS7_R_PKCS7_DATASIGN = 145
PKCS7_R_PKCS7_PARSE_ERROR = 139
PKCS7_R_PKCS7_SIG_PARSE_ERROR = 140
PKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE = 127
PKCS7_R_SIG_INVALID_MIME_TYPE = 141
PKCS7_R_SIGNATURE_FAILURE = 105
PKCS7_R_SIGNER_CERTIFICATE_NOT_FOUND = 128
PKCS7_R_SIGNING_CTRL_FAILURE = 147
PKCS7_R_SIGNING_NOT_SUPPORTED_FOR_THIS_KEY_TYPE = 148
PKCS7_R_SMIME_TEXT_ERROR = 129
PKCS7_R_UNABLE_TO_FIND_CERTIFICATE = 106
PKCS7_R_UNABLE_TO_FIND_MEM_BIO = 107
PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST = 108
PKCS7_R_UNKNOWN_DIGEST_TYPE = 109
PKCS7_R_UNKNOWN_OPERATION = 110
PKCS7_R_UNSUPPORTED_CIPHER_TYPE = 111
PKCS7_R_UNSUPPORTED_CONTENT_TYPE = 112
PKCS7_R_WRONG_CONTENT_TYPE = 113
PKCS7_R_WRONG_PKCS7_TYPE = 114
PKCS7_REUSE_DIGEST = 0x8000
PKCS7_S_BODY = 1
PKCS7_S_HEADER = 0
PKCS7_S_TAIL = 2
PKCS7_STREAM = 0x1000
PKCS7_TEXT = 0x1
PKCS8_EMBEDDED_PARAM = 2
PKCS8_NEG_PRIVKEY = 4
PKCS8_NO_OCTET = 1
PKCS8_NS_DB = 3
PKCS8_OK = 0
PSK_MAX_IDENTITY_LEN = 128
PSK_MAX_PSK_LEN = 256
session_ctx = initial_ctx
SHA_LBLOCK = 16
SHA_CBLOCK = (SHA_LBLOCK*4)
SHA224_DIGEST_LENGTH = 28
SHA256_CBLOCK = (SHA_LBLOCK*4)
SHA256_DIGEST_LENGTH = 32
SHA384_DIGEST_LENGTH = 48
SHA512_CBLOCK = (SHA_LBLOCK*8)
SHA512_DIGEST_LENGTH = 64
SHA_DIGEST_LENGTH = 20
SHA_LAST_BLOCK = (SHA_CBLOCK-8)
SHLIB_VERSION_HISTORY = ""
SHLIB_VERSION_NUMBER = "1.0.0"
SMIME_BINARY = PKCS7_BINARY
SMIME_CRLFEOL = 0x800
SMIME_DETACHED = PKCS7_DETACHED
SMIME_NOATTR = PKCS7_NOATTR
SMIME_NOCERTS = PKCS7_NOCERTS
SMIME_NOCHAIN = PKCS7_NOCHAIN
SMIME_NOINTERN = PKCS7_NOINTERN
SMIME_NOSIGS = PKCS7_NOSIGS
SMIME_NOVERIFY = PKCS7_NOVERIFY
SMIME_OLDMIME = 0x400
SMIME_STREAM = 0x1000
SMIME_TEXT = PKCS7_TEXT
SN_aaControls = "aaControls"
SN_ac_auditEntity = "ac-auditEntity"
SN_ac_proxying = "ac-proxying"
SN_ac_targeting = "ac-targeting"
SN_account = "account"
SN_ad_ca_issuers = "caIssuers"
SN_ad_dvcs = "AD_DVCS"
SN_ad_OCSP = "OCSP"
SN_ad_timeStamping = "ad_timestamping"
SN_aes_128_cbc = "AES-128-CBC"
SN_aes_128_cbc_hmac_sha1 = "AES-128-CBC-HMAC-SHA1"
SN_aes_128_ccm = "id-aes128-CCM"
SN_aes_128_cfb1 = "AES-128-CFB1"
SN_aes_128_cfb128 = "AES-128-CFB"
SN_aes_128_cfb8 = "AES-128-CFB8"
SN_aes_128_ctr = "AES-128-CTR"
SN_aes_128_ecb = "AES-128-ECB"
SN_aes_128_gcm = "id-aes128-GCM"
SN_aes_128_ofb128 = "AES-128-OFB"
SN_aes_128_xts = "AES-128-XTS"
SN_aes_192_cbc = "AES-192-CBC"
SN_aes_192_cbc_hmac_sha1 = "AES-192-CBC-HMAC-SHA1"
SN_aes_192_ccm = "id-aes192-CCM"
SN_aes_192_cfb1 = "AES-192-CFB1"
SN_aes_192_cfb128 = "AES-192-CFB"
SN_aes_192_cfb8 = "AES-192-CFB8"
SN_aes_192_ctr = "AES-192-CTR"
SN_aes_192_ecb = "AES-192-ECB"
SN_aes_192_gcm = "id-aes192-GCM"
SN_aes_192_ofb128 = "AES-192-OFB"
SN_aes_256_cbc = "AES-256-CBC"
SN_aes_256_cbc_hmac_sha1 = "AES-256-CBC-HMAC-SHA1"
SN_aes_256_ccm = "id-aes256-CCM"
SN_aes_256_cfb1 = "AES-256-CFB1"
SN_aes_256_cfb128 = "AES-256-CFB"
SN_aes_256_cfb8 = "AES-256-CFB8"
SN_aes_256_ctr = "AES-256-CTR"
SN_aes_256_ecb = "AES-256-ECB"
SN_aes_256_gcm = "id-aes256-GCM"
SN_aes_256_ofb128 = "AES-256-OFB"
SN_aes_256_xts = "AES-256-XTS"
SN_algorithm = "algorithm"
SN_ansi_X9_62 = "ansi-X9-62"
SN_any_policy = "anyPolicy"
SN_anyExtendedKeyUsage = "anyExtendedKeyUsage"
SN_audio = "audio"
SN_authority_key_identifier = "authorityKeyIdentifier"
SN_basic_constraints = "basicConstraints"
SN_bf_cbc = "BF-CBC"
SN_bf_cfb64 = "BF-CFB"
SN_bf_ecb = "BF-ECB"
SN_bf_ofb64 = "BF-OFB"
SN_biometricInfo = "biometricInfo"
SN_camellia_128_cbc = "CAMELLIA-128-CBC"
SN_camellia_128_cfb1 = "CAMELLIA-128-CFB1"
SN_camellia_128_cfb128 = "CAMELLIA-128-CFB"
SN_camellia_128_cfb8 = "CAMELLIA-128-CFB8"
SN_camellia_128_ecb = "CAMELLIA-128-ECB"
SN_camellia_128_ofb128 = "CAMELLIA-128-OFB"
SN_camellia_192_cbc = "CAMELLIA-192-CBC"
SN_camellia_192_cfb1 = "CAMELLIA-192-CFB1"
SN_camellia_192_cfb128 = "CAMELLIA-192-CFB"
SN_camellia_192_cfb8 = "CAMELLIA-192-CFB8"
SN_camellia_192_ecb = "CAMELLIA-192-ECB"
SN_camellia_192_ofb128 = "CAMELLIA-192-OFB"
SN_camellia_256_cbc = "CAMELLIA-256-CBC"
SN_camellia_256_cfb1 = "CAMELLIA-256-CFB1"
SN_camellia_256_cfb128 = "CAMELLIA-256-CFB"
SN_camellia_256_cfb8 = "CAMELLIA-256-CFB8"
SN_camellia_256_ecb = "CAMELLIA-256-ECB"
SN_camellia_256_ofb128 = "CAMELLIA-256-OFB"
SN_caRepository = "caRepository"
SN_cast5_cbc = "CAST5-CBC"
SN_cast5_cfb64 = "CAST5-CFB"
SN_cast5_ecb = "CAST5-ECB"
SN_cast5_ofb64 = "CAST5-OFB"
SN_certicom_arc = "certicom-arc"
SN_certificate_issuer = "certificateIssuer"
SN_certificate_policies = "certificatePolicies"
SN_clearance = "clearance"
SN_client_auth = "clientAuth"
SN_cmac = "CMAC"
SN_code_sign = "codeSigning"
SN_commonName = "CN"
SN_countryName = "C"
SN_crl_distribution_points = "crlDistributionPoints"
SN_crl_number = "crlNumber"
SN_crl_reason = "CRLReason"
SN_cryptocom = "cryptocom"
SN_cryptopro = "cryptopro"
SN_data = "data"
SN_dcObject = "dcobject"
SN_delta_crl = "deltaCRL"
SN_des_cbc = "DES-CBC"
SN_des_cdmf = "DES-CDMF"
SN_des_cfb1 = "DES-CFB1"
SN_des_cfb64 = "DES-CFB"
SN_des_cfb8 = "DES-CFB8"
SN_des_ecb = "DES-ECB"
SN_des_ede3_cbc = "DES-EDE3-CBC"
SN_des_ede3_cfb1 = "DES-EDE3-CFB1"
SN_des_ede3_cfb64 = "DES-EDE3-CFB"
SN_des_ede3_cfb8 = "DES-EDE3-CFB8"
SN_des_ede3_ecb = "DES-EDE3"
SN_des_ede3_ofb64 = "DES-EDE3-OFB"
SN_des_ede_cbc = "DES-EDE-CBC"
SN_des_ede_cfb64 = "DES-EDE-CFB"
SN_des_ede_ecb = "DES-EDE"
SN_des_ede_ofb64 = "DES-EDE-OFB"
SN_des_ofb64 = "DES-OFB"
SN_desx_cbc = "DESX-CBC"
SN_Directory = "directory"
SN_dmdName = "dmdName"
SN_dnQualifier = "dnQualifier"
SN_document = "document"
SN_dod = "DOD"
SN_Domain = "domain"
SN_domainComponent = "DC"
SN_dsa = "DSA"
SN_dsa_2 = "DSA-old"
SN_dsa_with_SHA224 = "dsa_with_SHA224"
SN_dsa_with_SHA256 = "dsa_with_SHA256"
SN_dsaWithSHA = "DSA-SHA"
SN_dsaWithSHA1 = "DSA-SHA1"
SN_dsaWithSHA1_2 = "DSA-SHA1-old"
SN_dvcs = "DVCS"
SN_ecdsa_with_Recommended = "ecdsa-with-Recommended"
SN_ecdsa_with_SHA1 = "ecdsa-with-SHA1"
SN_ecdsa_with_SHA224 = "ecdsa-with-SHA224"
SN_ecdsa_with_SHA256 = "ecdsa-with-SHA256"
SN_ecdsa_with_SHA384 = "ecdsa-with-SHA384"
SN_ecdsa_with_SHA512 = "ecdsa-with-SHA512"
SN_ecdsa_with_Specified = "ecdsa-with-Specified"
SN_email_protect = "emailProtection"
SN_Enterprises = "enterprises"
SN_Experimental = "experimental"
SN_ext_key_usage = "extendedKeyUsage"
SN_ext_req = "extReq"
SN_freshest_crl = "freshestCRL"
SN_givenName = "GN"
SN_gost89_cnt = "gost89-cnt"
SN_hmac = "HMAC"
SN_hmac_md5 = "HMAC-MD5"
SN_hmac_sha1 = "HMAC-SHA1"
SN_hold_instruction_call_issuer = "holdInstructionCallIssuer"
SN_hold_instruction_code = "holdInstructionCode"
SN_hold_instruction_none = "holdInstructionNone"
SN_hold_instruction_reject = "holdInstructionReject"
SN_host = "host"
SN_iana = "IANA"
SN_id_aca = "id-aca"
SN_id_aca_accessIdentity = "id-aca-accessIdentity"
SN_id_aca_authenticationInfo = "id-aca-authenticationInfo"
SN_id_aca_chargingIdentity = "id-aca-chargingIdentity"
SN_id_aca_encAttrs = "id-aca-encAttrs"
SN_id_aca_group = "id-aca-group"
SN_id_aca_role = "id-aca-role"
SN_id_ad = "id-ad"
SN_id_aes128_wrap = "id-aes128-wrap"
SN_id_aes128_wrap_pad = "id-aes128-wrap-pad"
SN_id_aes192_wrap = "id-aes192-wrap"
SN_id_aes192_wrap_pad = "id-aes192-wrap-pad"
SN_id_aes256_wrap = "id-aes256-wrap"
SN_id_aes256_wrap_pad = "id-aes256-wrap-pad"
SN_id_alg = "id-alg"
SN_id_alg_des40 = "id-alg-des40"
SN_id_alg_dh_pop = "id-alg-dh-pop"
SN_id_alg_dh_sig_hmac_sha1 = "id-alg-dh-sig-hmac-sha1"
SN_id_alg_noSignature = "id-alg-noSignature"
SN_id_alg_PWRI_KEK = "id-alg-PWRI-KEK"
SN_id_camellia128_wrap = "id-camellia128-wrap"
SN_id_camellia192_wrap = "id-camellia192-wrap"
SN_id_camellia256_wrap = "id-camellia256-wrap"
SN_id_cct = "id-cct"
SN_id_cct_crs = "id-cct-crs"
SN_id_cct_PKIData = "id-cct-PKIData"
SN_id_cct_PKIResponse = "id-cct-PKIResponse"
SN_id_ce = "id-ce"
SN_id_cmc = "id-cmc"
SN_id_cmc_addExtensions = "id-cmc-addExtensions"
SN_id_cmc_confirmCertAcceptance = "id-cmc-confirmCertAcceptance"
SN_id_cmc_dataReturn = "id-cmc-dataReturn"
SN_id_cmc_decryptedPOP = "id-cmc-decryptedPOP"
SN_id_cmc_encryptedPOP = "id-cmc-encryptedPOP"
SN_id_cmc_getCert = "id-cmc-getCert"
SN_id_cmc_getCRL = "id-cmc-getCRL"
SN_id_cmc_identification = "id-cmc-identification"
SN_id_cmc_identityProof = "id-cmc-identityProof"
SN_id_cmc_lraPOPWitness = "id-cmc-lraPOPWitness"
SN_id_cmc_popLinkRandom = "id-cmc-popLinkRandom"
SN_id_cmc_popLinkWitness = "id-cmc-popLinkWitness"
SN_id_cmc_queryPending = "id-cmc-queryPending"
SN_id_cmc_recipientNonce = "id-cmc-recipientNonce"
SN_id_cmc_regInfo = "id-cmc-regInfo"
SN_id_cmc_responseInfo = "id-cmc-responseInfo"
SN_id_cmc_revokeRequest = "id-cmc-revokeRequest"
SN_id_cmc_senderNonce = "id-cmc-senderNonce"
SN_id_cmc_statusInfo = "id-cmc-statusInfo"
SN_id_cmc_transactionId = "id-cmc-transactionId"
SN_id_ct_asciiTextWithCRLF = "id-ct-asciiTextWithCRLF"
SN_id_DHBasedMac = "id-DHBasedMac"
SN_id_Gost28147_89 = "gost89"
SN_id_Gost28147_89_cc = "id-Gost28147-89-cc"
SN_id_Gost28147_89_CryptoPro_A_ParamSet = "id-Gost28147-89-CryptoPro-A-ParamSet"
SN_id_Gost28147_89_CryptoPro_B_ParamSet = "id-Gost28147-89-CryptoPro-B-ParamSet"
SN_id_Gost28147_89_CryptoPro_C_ParamSet = "id-Gost28147-89-CryptoPro-C-ParamSet"
SN_id_Gost28147_89_CryptoPro_D_ParamSet = "id-Gost28147-89-CryptoPro-D-ParamSet"
SN_id_Gost28147_89_CryptoPro_KeyMeshing = "id-Gost28147-89-CryptoPro-KeyMeshing"
SN_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet = "id-Gost28147-89-CryptoPro-Oscar-1-0-ParamSet"
SN_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet = "id-Gost28147-89-CryptoPro-Oscar-1-1-ParamSet"
SN_id_Gost28147_89_CryptoPro_RIC_1_ParamSet = "id-Gost28147-89-CryptoPro-RIC-1-ParamSet"
SN_id_Gost28147_89_MAC = "gost-mac"
SN_id_Gost28147_89_None_KeyMeshing = "id-Gost28147-89-None-KeyMeshing"
SN_id_Gost28147_89_TestParamSet = "id-Gost28147-89-TestParamSet"
SN_id_GostR3410_2001 = "gost2001"
SN_id_GostR3410_2001_cc = "gost2001cc"
SN_id_GostR3410_2001_CryptoPro_A_ParamSet = "id-GostR3410-2001-CryptoPro-A-ParamSet"
SN_id_GostR3410_2001_CryptoPro_B_ParamSet = "id-GostR3410-2001-CryptoPro-B-ParamSet"
SN_id_GostR3410_2001_CryptoPro_C_ParamSet = "id-GostR3410-2001-CryptoPro-C-ParamSet"
SN_id_GostR3410_2001_CryptoPro_XchA_ParamSet = "id-GostR3410-2001-CryptoPro-XchA-ParamSet"
SN_id_GostR3410_2001_CryptoPro_XchB_ParamSet = "id-GostR3410-2001-CryptoPro-XchB-ParamSet"
SN_id_GostR3410_2001_ParamSet_cc = "id-GostR3410-2001-ParamSet-cc"
SN_id_GostR3410_2001_TestParamSet = "id-GostR3410-2001-TestParamSet"
SN_id_GostR3410_2001DH = "id-GostR3410-2001DH"
SN_id_GostR3410_94 = "gost94"
SN_id_GostR3410_94_a = "id-GostR3410-94-a"
SN_id_GostR3410_94_aBis = "id-GostR3410-94-aBis"
SN_id_GostR3410_94_b = "id-GostR3410-94-b"
SN_id_GostR3410_94_bBis = "id-GostR3410-94-bBis"
SN_id_GostR3410_94_cc = "gost94cc"
SN_id_GostR3410_94_CryptoPro_A_ParamSet = "id-GostR3410-94-CryptoPro-A-ParamSet"
SN_id_GostR3410_94_CryptoPro_B_ParamSet = "id-GostR3410-94-CryptoPro-B-ParamSet"
SN_id_GostR3410_94_CryptoPro_C_ParamSet = "id-GostR3410-94-CryptoPro-C-ParamSet"
SN_id_GostR3410_94_CryptoPro_D_ParamSet = "id-GostR3410-94-CryptoPro-D-ParamSet"
SN_id_GostR3410_94_CryptoPro_XchA_ParamSet = "id-GostR3410-94-CryptoPro-XchA-ParamSet"
SN_id_GostR3410_94_CryptoPro_XchB_ParamSet = "id-GostR3410-94-CryptoPro-XchB-ParamSet"
SN_id_GostR3410_94_CryptoPro_XchC_ParamSet = "id-GostR3410-94-CryptoPro-XchC-ParamSet"
SN_id_GostR3410_94_TestParamSet = "id-GostR3410-94-TestParamSet"
SN_id_GostR3410_94DH = "id-GostR3410-94DH"
SN_id_GostR3411_94 = "md_gost94"
SN_id_GostR3411_94_CryptoProParamSet = "id-GostR3411-94-CryptoProParamSet"
SN_id_GostR3411_94_prf = "prf-gostr3411-94"
SN_id_GostR3411_94_TestParamSet = "id-GostR3411-94-TestParamSet"
SN_id_GostR3411_94_with_GostR3410_2001 = "id-GostR3411-94-with-GostR3410-2001"
SN_id_GostR3411_94_with_GostR3410_2001_cc = "id-GostR3411-94-with-GostR3410-2001-cc"
SN_id_GostR3411_94_with_GostR3410_94 = "id-GostR3411-94-with-GostR3410-94"
SN_id_GostR3411_94_with_GostR3410_94_cc = "id-GostR3411-94-with-GostR3410-94-cc"
SN_id_hex_multipart_message = "id-hex-multipart-message"
SN_id_hex_partial_message = "id-hex-partial-message"
SN_id_HMACGostR3411_94 = "id-HMACGostR3411-94"
SN_id_it = "id-it"
SN_id_it_caKeyUpdateInfo = "id-it-caKeyUpdateInfo"
SN_id_it_caProtEncCert = "id-it-caProtEncCert"
SN_id_it_confirmWaitTime = "id-it-confirmWaitTime"
SN_id_it_currentCRL = "id-it-currentCRL"
SN_id_it_encKeyPairTypes = "id-it-encKeyPairTypes"
SN_id_it_implicitConfirm = "id-it-implicitConfirm"
SN_id_it_keyPairParamRep = "id-it-keyPairParamRep"
SN_id_it_keyPairParamReq = "id-it-keyPairParamReq"
SN_id_it_origPKIMessage = "id-it-origPKIMessage"
SN_id_it_preferredSymmAlg = "id-it-preferredSymmAlg"
SN_id_it_revPassphrase = "id-it-revPassphrase"
SN_id_it_signKeyPairTypes = "id-it-signKeyPairTypes"
SN_id_it_subscriptionRequest = "id-it-subscriptionRequest"
SN_id_it_subscriptionResponse = "id-it-subscriptionResponse"
SN_id_it_suppLangTags = "id-it-suppLangTags"
SN_id_it_unsupportedOIDs = "id-it-unsupportedOIDs"
SN_id_kp = "id-kp"
SN_id_mod_attribute_cert = "id-mod-attribute-cert"
SN_id_mod_cmc = "id-mod-cmc"
SN_id_mod_cmp = "id-mod-cmp"
SN_id_mod_cmp2000 = "id-mod-cmp2000"
SN_id_mod_crmf = "id-mod-crmf"
SN_id_mod_dvcs = "id-mod-dvcs"
SN_id_mod_kea_profile_88 = "id-mod-kea-profile-88"
SN_id_mod_kea_profile_93 = "id-mod-kea-profile-93"
SN_id_mod_ocsp = "id-mod-ocsp"
SN_id_mod_qualified_cert_88 = "id-mod-qualified-cert-88"
SN_id_mod_qualified_cert_93 = "id-mod-qualified-cert-93"
SN_id_mod_timestamp_protocol = "id-mod-timestamp-protocol"
SN_id_on = "id-on"
SN_id_on_permanentIdentifier = "id-on-permanentIdentifier"
SN_id_on_personalData = "id-on-personalData"
SN_id_PasswordBasedMAC = "id-PasswordBasedMAC"
SN_id_pda = "id-pda"
SN_id_pda_countryOfCitizenship = "id-pda-countryOfCitizenship"
SN_id_pda_countryOfResidence = "id-pda-countryOfResidence"
SN_id_pda_dateOfBirth = "id-pda-dateOfBirth"
SN_id_pda_gender = "id-pda-gender"
SN_id_pda_placeOfBirth = "id-pda-placeOfBirth"
SN_id_pe = "id-pe"
SN_id_pkip = "id-pkip"
SN_id_pkix = "PKIX"
SN_id_pkix1_explicit_88 = "id-pkix1-explicit-88"
SN_id_pkix1_explicit_93 = "id-pkix1-explicit-93"
SN_id_pkix1_implicit_88 = "id-pkix1-implicit-88"
SN_id_pkix1_implicit_93 = "id-pkix1-implicit-93"
SN_id_pkix_mod = "id-pkix-mod"
SN_id_pkix_OCSP_acceptableResponses = "acceptableResponses"
SN_id_pkix_OCSP_archiveCutoff = "archiveCutoff"
SN_id_pkix_OCSP_basic = "basicOCSPResponse"
SN_id_pkix_OCSP_CrlID = "CrlID"
SN_id_pkix_OCSP_extendedStatus = "extendedStatus"
SN_id_pkix_OCSP_noCheck = "noCheck"
SN_id_pkix_OCSP_Nonce = "Nonce"
SN_id_pkix_OCSP_path = "path"
SN_id_pkix_OCSP_serviceLocator = "serviceLocator"
SN_id_pkix_OCSP_trustRoot = "trustRoot"
SN_id_pkix_OCSP_valid = "valid"
SN_id_ppl = "id-ppl"
SN_id_ppl_anyLanguage = "id-ppl-anyLanguage"
SN_id_ppl_inheritAll = "id-ppl-inheritAll"
SN_id_qcs = "id-qcs"
SN_id_qcs_pkixQCSyntax_v1 = "id-qcs-pkixQCSyntax-v1"
SN_id_qt = "id-qt"
SN_id_qt_cps = "id-qt-cps"
SN_id_qt_unotice = "id-qt-unotice"
SN_id_regCtrl = "id-regCtrl"
SN_id_regCtrl_authenticator = "id-regCtrl-authenticator"
SN_id_regCtrl_oldCertID = "id-regCtrl-oldCertID"
SN_id_regCtrl_pkiArchiveOptions = "id-regCtrl-pkiArchiveOptions"
SN_id_regCtrl_pkiPublicationInfo = "id-regCtrl-pkiPublicationInfo"
SN_id_regCtrl_protocolEncrKey = "id-regCtrl-protocolEncrKey"
SN_id_regCtrl_regToken = "id-regCtrl-regToken"
SN_id_regInfo = "id-regInfo"
SN_id_regInfo_certReq = "id-regInfo-certReq"
SN_id_regInfo_utf8Pairs = "id-regInfo-utf8Pairs"
SN_id_set = "id-set"
SN_id_smime_aa = "id-smime-aa"
SN_id_smime_aa_contentHint = "id-smime-aa-contentHint"
SN_id_smime_aa_contentIdentifier = "id-smime-aa-contentIdentifier"
SN_id_smime_aa_contentReference = "id-smime-aa-contentReference"
SN_id_smime_aa_dvcs_dvc = "id-smime-aa-dvcs-dvc"
SN_id_smime_aa_encapContentType = "id-smime-aa-encapContentType"
SN_id_smime_aa_encrypKeyPref = "id-smime-aa-encrypKeyPref"
SN_id_smime_aa_equivalentLabels = "id-smime-aa-equivalentLabels"
SN_id_smime_aa_ets_archiveTimeStamp = "id-smime-aa-ets-archiveTimeStamp"
SN_id_smime_aa_ets_certCRLTimestamp = "id-smime-aa-ets-certCRLTimestamp"
SN_id_smime_aa_ets_CertificateRefs = "id-smime-aa-ets-CertificateRefs"
SN_id_smime_aa_ets_certValues = "id-smime-aa-ets-certValues"
SN_id_smime_aa_ets_commitmentType = "id-smime-aa-ets-commitmentType"
SN_id_smime_aa_ets_contentTimestamp = "id-smime-aa-ets-contentTimestamp"
SN_id_smime_aa_ets_escTimeStamp = "id-smime-aa-ets-escTimeStamp"
SN_id_smime_aa_ets_otherSigCert = "id-smime-aa-ets-otherSigCert"
SN_id_smime_aa_ets_RevocationRefs = "id-smime-aa-ets-RevocationRefs"
SN_id_smime_aa_ets_revocationValues = "id-smime-aa-ets-revocationValues"
SN_id_smime_aa_ets_signerAttr = "id-smime-aa-ets-signerAttr"
SN_id_smime_aa_ets_signerLocation = "id-smime-aa-ets-signerLocation"
SN_id_smime_aa_ets_sigPolicyId = "id-smime-aa-ets-sigPolicyId"
SN_id_smime_aa_macValue = "id-smime-aa-macValue"
SN_id_smime_aa_mlExpandHistory = "id-smime-aa-mlExpandHistory"
SN_id_smime_aa_msgSigDigest = "id-smime-aa-msgSigDigest"
SN_id_smime_aa_receiptRequest = "id-smime-aa-receiptRequest"
SN_id_smime_aa_securityLabel = "id-smime-aa-securityLabel"
SN_id_smime_aa_signatureType = "id-smime-aa-signatureType"
SN_id_smime_aa_signingCertificate = "id-smime-aa-signingCertificate"
SN_id_smime_aa_smimeEncryptCerts = "id-smime-aa-smimeEncryptCerts"
SN_id_smime_aa_timeStampToken = "id-smime-aa-timeStampToken"
SN_id_smime_alg = "id-smime-alg"
SN_id_smime_alg_3DESwrap = "id-smime-alg-3DESwrap"
SN_id_smime_alg_CMS3DESwrap = "id-smime-alg-CMS3DESwrap"
SN_id_smime_alg_CMSRC2wrap = "id-smime-alg-CMSRC2wrap"
SN_id_smime_alg_ESDH = "id-smime-alg-ESDH"
SN_id_smime_alg_ESDHwith3DES = "id-smime-alg-ESDHwith3DES"
SN_id_smime_alg_ESDHwithRC2 = "id-smime-alg-ESDHwithRC2"
SN_id_smime_alg_RC2wrap = "id-smime-alg-RC2wrap"
SN_id_smime_cd = "id-smime-cd"
SN_id_smime_cd_ldap = "id-smime-cd-ldap"
SN_id_smime_ct = "id-smime-ct"
SN_id_smime_ct_authData = "id-smime-ct-authData"
SN_id_smime_ct_compressedData = "id-smime-ct-compressedData"
SN_id_smime_ct_contentInfo = "id-smime-ct-contentInfo"
SN_id_smime_ct_DVCSRequestData = "id-smime-ct-DVCSRequestData"
SN_id_smime_ct_DVCSResponseData = "id-smime-ct-DVCSResponseData"
SN_id_smime_ct_publishCert = "id-smime-ct-publishCert"
SN_id_smime_ct_receipt = "id-smime-ct-receipt"
SN_id_smime_ct_TDTInfo = "id-smime-ct-TDTInfo"
SN_id_smime_ct_TSTInfo = "id-smime-ct-TSTInfo"
SN_id_smime_cti = "id-smime-cti"
SN_id_smime_cti_ets_proofOfApproval = "id-smime-cti-ets-proofOfApproval"
SN_id_smime_cti_ets_proofOfCreation = "id-smime-cti-ets-proofOfCreation"
SN_id_smime_cti_ets_proofOfDelivery = "id-smime-cti-ets-proofOfDelivery"
SN_id_smime_cti_ets_proofOfOrigin = "id-smime-cti-ets-proofOfOrigin"
SN_id_smime_cti_ets_proofOfReceipt = "id-smime-cti-ets-proofOfReceipt"
SN_id_smime_cti_ets_proofOfSender = "id-smime-cti-ets-proofOfSender"
SN_id_smime_mod = "id-smime-mod"
SN_id_smime_mod_cms = "id-smime-mod-cms"
SN_id_smime_mod_ess = "id-smime-mod-ess"
SN_id_smime_mod_ets_eSignature_88 = "id-smime-mod-ets-eSignature-88"
SN_id_smime_mod_ets_eSignature_97 = "id-smime-mod-ets-eSignature-97"
SN_id_smime_mod_ets_eSigPolicy_88 = "id-smime-mod-ets-eSigPolicy-88"
SN_id_smime_mod_ets_eSigPolicy_97 = "id-smime-mod-ets-eSigPolicy-97"
SN_id_smime_mod_msg_v3 = "id-smime-mod-msg-v3"
SN_id_smime_mod_oid = "id-smime-mod-oid"
SN_id_smime_spq = "id-smime-spq"
SN_id_smime_spq_ets_sqt_unotice = "id-smime-spq-ets-sqt-unotice"
SN_id_smime_spq_ets_sqt_uri = "id-smime-spq-ets-sqt-uri"
SN_idea_cbc = "IDEA-CBC"
SN_idea_cfb64 = "IDEA-CFB"
SN_idea_ecb = "IDEA-ECB"
SN_idea_ofb64 = "IDEA-OFB"
SN_identified_organization = "identified-organization"
SN_Independent = "id-ppl-independent"
SN_info = "info"
SN_info_access = "authorityInfoAccess"
SN_inhibit_any_policy = "inhibitAnyPolicy"
SN_initials = "initials"
SN_international_organizations = "international-organizations"
SN_invalidity_date = "invalidityDate"
SN_ipsec3 = "Oakley-EC2N-3"
SN_ipsec4 = "Oakley-EC2N-4"
SN_ipsecEndSystem = "ipsecEndSystem"
SN_ipsecTunnel = "ipsecTunnel"
SN_ipsecUser = "ipsecUser"
SN_iso = "ISO"
SN_ISO_US = "ISO-US"
SN_issuer_alt_name = "issuerAltName"
SN_issuing_distribution_point = "issuingDistributionPoint"
SN_itu_t = "ITU-T"
SN_joint_iso_itu_t = "JOINT-ISO-ITU-T"
SN_key_usage = "keyUsage"
SN_kisa = "KISA"
SN_localityName = "L"
SN_LocalKeySet = "LocalKeySet"
SN_Management = "mgmt"
SN_manager = "manager"
SN_md2 = "MD2"
SN_md2WithRSAEncryption = "RSA-MD2"
SN_md4 = "MD4"
SN_md4WithRSAEncryption = "RSA-MD4"
SN_md5 = "MD5"
SN_md5_sha1 = "MD5-SHA1"
SN_md5WithRSA = "RSA-NP-MD5"
SN_md5WithRSAEncryption = "RSA-MD5"
SN_mdc2 = "MDC2"
SN_mdc2WithRSA = "RSA-MDC2"
SN_member = "member"
SN_member_body = "member-body"
SN_mgf1 = "MGF1"
SN_mime_mhs = "mime-mhs"
SN_mime_mhs_bodies = "mime-mhs-bodies"
SN_mime_mhs_headings = "mime-mhs-headings"
SN_ms_code_com = "msCodeCom"
SN_ms_code_ind = "msCodeInd"
SN_ms_csp_name = "CSPName"
SN_ms_ctl_sign = "msCTLSign"
SN_ms_efs = "msEFS"
SN_ms_ext_req = "msExtReq"
SN_ms_sgc = "msSGC"
SN_ms_smartcard_login = "msSmartcardLogin"
SN_ms_upn = "msUPN"
SN_name = "name"
SN_name_constraints = "nameConstraints"
SN_netscape = "Netscape"
SN_netscape_base_url = "nsBaseUrl"
SN_netscape_ca_policy_url = "nsCaPolicyUrl"
SN_netscape_ca_revocation_url = "nsCaRevocationUrl"
SN_netscape_cert_extension = "nsCertExt"
SN_netscape_cert_sequence = "nsCertSequence"
SN_netscape_cert_type = "nsCertType"
SN_netscape_comment = "nsComment"
SN_netscape_data_type = "nsDataType"
SN_netscape_renewal_url = "nsRenewalUrl"
SN_netscape_revocation_url = "nsRevocationUrl"
SN_netscape_ssl_server_name = "nsSslServerName"
SN_no_rev_avail = "noRevAvail"
SN_ns_sgc = "nsSGC"
SN_OCSP_sign = "OCSPSigning"
SN_org = "ORG"
SN_organizationalUnitName = "OU"
SN_organizationName = "O"
SN_owner = "owner"
SN_pbe_WithSHA1And128BitRC2_CBC = "PBE-SHA1-RC2-128"
SN_pbe_WithSHA1And128BitRC4 = "PBE-SHA1-RC4-128"
SN_pbe_WithSHA1And2_Key_TripleDES_CBC = "PBE-SHA1-2DES"
SN_pbe_WithSHA1And3_Key_TripleDES_CBC = "PBE-SHA1-3DES"
SN_pbe_WithSHA1And40BitRC2_CBC = "PBE-SHA1-RC2-40"
SN_pbe_WithSHA1And40BitRC4 = "PBE-SHA1-RC4-40"
SN_pbeWithMD2AndDES_CBC = "PBE-MD2-DES"
SN_pbeWithMD2AndRC2_CBC = "PBE-MD2-RC2-64"
SN_pbeWithMD5AndDES_CBC = "PBE-MD5-DES"
SN_pbeWithMD5AndRC2_CBC = "PBE-MD5-RC2-64"
SN_pbeWithSHA1AndDES_CBC = "PBE-SHA1-DES"
SN_pbeWithSHA1AndRC2_CBC = "PBE-SHA1-RC2-64"
SN_photo = "photo"
SN_pilot = "pilot"
SN_pkcs = "pkcs"
SN_pkcs1 = "pkcs1"
SN_pkcs3 = "pkcs3"
SN_pkcs5 = "pkcs5"
SN_pkcs7 = "pkcs7"
SN_pkcs9 = "pkcs9"
SN_policy_constraints = "policyConstraints"
SN_policy_mappings = "policyMappings"
SN_Private = "private"
SN_private_key_usage_period = "privateKeyUsagePeriod"
SN_proxyCertInfo = "proxyCertInfo"
SN_pss = "pss"
SN_qcStatements = "qcStatements"
SN_rc2_40_cbc = "RC2-40-CBC"
SN_rc2_64_cbc = "RC2-64-CBC"
SN_rc2_cbc = "RC2-CBC"
SN_rc2_cfb64 = "RC2-CFB"
SN_rc2_ecb = "RC2-ECB"
SN_rc2_ofb64 = "RC2-OFB"
SN_rc4 = "RC4"
SN_rc4_40 = "RC4-40"
SN_rc4_hmac_md5 = "RC4-HMAC-MD5"
SN_rc5_cbc = "RC5-CBC"
SN_rc5_cfb64 = "RC5-CFB"
SN_rc5_ecb = "RC5-ECB"
SN_rc5_ofb64 = "RC5-OFB"
SN_rfc822Mailbox = "mail"
SN_ripemd160 = "RIPEMD160"
SN_ripemd160WithRSA = "RSA-RIPEMD160"
SN_rle_compression = "RLE"
SN_role = "role"
SN_room = "room"
SN_rsa = "RSA"
SN_rsadsi = "rsadsi"
SN_rsaesOaep = "RSAES-OAEP"
SN_rsaOAEPEncryptionSET = "rsaOAEPEncryptionSET"
SN_rsaSignature = "rsaSignature"
SN_rsassaPss = "RSASSA-PSS"
SN_sbgp_autonomousSysNum = "sbgp-autonomousSysNum"
SN_sbgp_ipAddrBlock = "sbgp-ipAddrBlock"
SN_sbgp_routerIdentifier = "sbgp-routerIdentifier"
SN_secp112r1 = "secp112r1"
SN_secp112r2 = "secp112r2"
SN_secp128r1 = "secp128r1"
SN_secp128r2 = "secp128r2"
SN_secp160k1 = "secp160k1"
SN_secp160r1 = "secp160r1"
SN_secp160r2 = "secp160r2"
SN_secp192k1 = "secp192k1"
SN_secp224k1 = "secp224k1"
SN_secp224r1 = "secp224r1"
SN_secp256k1 = "secp256k1"
SN_secp384r1 = "secp384r1"
SN_secp521r1 = "secp521r1"
SN_secretary = "secretary"
SN_sect113r1 = "sect113r1"
SN_sect113r2 = "sect113r2"
SN_sect131r1 = "sect131r1"
SN_sect131r2 = "sect131r2"
SN_sect163k1 = "sect163k1"
SN_sect163r1 = "sect163r1"
SN_sect163r2 = "sect163r2"
SN_sect193r1 = "sect193r1"
SN_sect193r2 = "sect193r2"
SN_sect233k1 = "sect233k1"
SN_sect233r1 = "sect233r1"
SN_sect239k1 = "sect239k1"
SN_sect283k1 = "sect283k1"
SN_sect283r1 = "sect283r1"
SN_sect409k1 = "sect409k1"
SN_sect409r1 = "sect409r1"
SN_sect571k1 = "sect571k1"
SN_sect571r1 = "sect571r1"
SN_Security = "security"
SN_seeAlso = "seeAlso"
SN_seed_cbc = "SEED-CBC"
SN_seed_cfb128 = "SEED-CFB"
SN_seed_ecb = "SEED-ECB"
SN_seed_ofb128 = "SEED-OFB"
SN_selected_attribute_types = "selected-attribute-types"
SN_server_auth = "serverAuth"
SN_set_addPolicy = "set-addPolicy"
SN_set_attr = "set-attr"
SN_set_brand = "set-brand"
SN_set_brand_AmericanExpress = "set-brand-AmericanExpress"
SN_set_brand_Diners = "set-brand-Diners"
SN_set_brand_IATA_ATA = "set-brand-IATA-ATA"
SN_set_brand_JCB = "set-brand-JCB"
SN_set_brand_MasterCard = "set-brand-MasterCard"
SN_set_brand_Novus = "set-brand-Novus"
SN_set_brand_Visa = "set-brand-Visa"
SN_set_certExt = "set-certExt"
SN_set_ctype = "set-ctype"
SN_set_msgExt = "set-msgExt"
SN_set_policy = "set-policy"
SN_set_policy_root = "set-policy-root"
SN_set_rootKeyThumb = "set-rootKeyThumb"
SN_setAttr_Cert = "setAttr-Cert"
SN_setAttr_GenCryptgrm = "setAttr-GenCryptgrm"
SN_setAttr_IssCap = "setAttr-IssCap"
SN_setAttr_IssCap_CVM = "setAttr-IssCap-CVM"
SN_setAttr_IssCap_Sig = "setAttr-IssCap-Sig"
SN_setAttr_IssCap_T2 = "setAttr-IssCap-T2"
SN_setAttr_PGWYcap = "setAttr-PGWYcap"
SN_setAttr_SecDevSig = "setAttr-SecDevSig"
SN_setAttr_T2cleartxt = "setAttr-T2cleartxt"
SN_setAttr_T2Enc = "setAttr-T2Enc"
SN_setAttr_Token_B0Prime = "setAttr-Token-B0Prime"
SN_setAttr_Token_EMV = "setAttr-Token-EMV"
SN_setAttr_TokenType = "setAttr-TokenType"
SN_setAttr_TokICCsig = "setAttr-TokICCsig"
SN_setCext_cCertRequired = "setCext-cCertRequired"
SN_setCext_certType = "setCext-certType"
SN_setCext_hashedRoot = "setCext-hashedRoot"
SN_setCext_IssuerCapabilities = "setCext-IssuerCapabilities"
SN_setCext_merchData = "setCext-merchData"
SN_setCext_PGWYcapabilities = "setCext-PGWYcapabilities"
SN_setCext_setExt = "setCext-setExt"
SN_setCext_setQualf = "setCext-setQualf"
SN_setCext_TokenIdentifier = "setCext-TokenIdentifier"
SN_setCext_TokenType = "setCext-TokenType"
SN_setCext_Track2Data = "setCext-Track2Data"
SN_setCext_tunneling = "setCext-tunneling"
SN_setct_AcqCardCodeMsg = "setct-AcqCardCodeMsg"
SN_setct_AcqCardCodeMsgTBE = "setct-AcqCardCodeMsgTBE"
SN_setct_AuthReqTBE = "setct-AuthReqTBE"
SN_setct_AuthReqTBS = "setct-AuthReqTBS"
SN_setct_AuthResBaggage = "setct-AuthResBaggage"
SN_setct_AuthResTBE = "setct-AuthResTBE"
SN_setct_AuthResTBEX = "setct-AuthResTBEX"
SN_setct_AuthResTBS = "setct-AuthResTBS"
SN_setct_AuthResTBSX = "setct-AuthResTBSX"
SN_setct_AuthRevReqBaggage = "setct-AuthRevReqBaggage"
SN_setct_AuthRevReqTBE = "setct-AuthRevReqTBE"
SN_setct_AuthRevReqTBS = "setct-AuthRevReqTBS"
SN_setct_AuthRevResBaggage = "setct-AuthRevResBaggage"
SN_setct_AuthRevResData = "setct-AuthRevResData"
SN_setct_AuthRevResTBE = "setct-AuthRevResTBE"
SN_setct_AuthRevResTBEB = "setct-AuthRevResTBEB"
SN_setct_AuthRevResTBS = "setct-AuthRevResTBS"
SN_setct_AuthTokenTBE = "setct-AuthTokenTBE"
SN_setct_AuthTokenTBS = "setct-AuthTokenTBS"
SN_setct_BatchAdminReqData = "setct-BatchAdminReqData"
SN_setct_BatchAdminReqTBE = "setct-BatchAdminReqTBE"
SN_setct_BatchAdminResData = "setct-BatchAdminResData"
SN_setct_BatchAdminResTBE = "setct-BatchAdminResTBE"
SN_setct_BCIDistributionTBS = "setct-BCIDistributionTBS"
SN_setct_CapReqTBE = "setct-CapReqTBE"
SN_setct_CapReqTBEX = "setct-CapReqTBEX"
SN_setct_CapReqTBS = "setct-CapReqTBS"
SN_setct_CapReqTBSX = "setct-CapReqTBSX"
SN_setct_CapResData = "setct-CapResData"
SN_setct_CapResTBE = "setct-CapResTBE"
SN_setct_CapRevReqTBE = "setct-CapRevReqTBE"
SN_setct_CapRevReqTBEX = "setct-CapRevReqTBEX"
SN_setct_CapRevReqTBS = "setct-CapRevReqTBS"
SN_setct_CapRevReqTBSX = "setct-CapRevReqTBSX"
SN_setct_CapRevResData = "setct-CapRevResData"
SN_setct_CapRevResTBE = "setct-CapRevResTBE"
SN_setct_CapTokenData = "setct-CapTokenData"
SN_setct_CapTokenSeq = "setct-CapTokenSeq"
SN_setct_CapTokenTBE = "setct-CapTokenTBE"
SN_setct_CapTokenTBEX = "setct-CapTokenTBEX"
SN_setct_CapTokenTBS = "setct-CapTokenTBS"
SN_setct_CardCInitResTBS = "setct-CardCInitResTBS"
SN_setct_CertInqReqTBS = "setct-CertInqReqTBS"
SN_setct_CertReqData = "setct-CertReqData"
SN_setct_CertReqTBE = "setct-CertReqTBE"
SN_setct_CertReqTBEX = "setct-CertReqTBEX"
SN_setct_CertReqTBS = "setct-CertReqTBS"
SN_setct_CertResData = "setct-CertResData"
SN_setct_CertResTBE = "setct-CertResTBE"
SN_setct_CredReqTBE = "setct-CredReqTBE"
SN_setct_CredReqTBEX = "setct-CredReqTBEX"
SN_setct_CredReqTBS = "setct-CredReqTBS"
SN_setct_CredReqTBSX = "setct-CredReqTBSX"
SN_setct_CredResData = "setct-CredResData"
SN_setct_CredResTBE = "setct-CredResTBE"
SN_setct_CredRevReqTBE = "setct-CredRevReqTBE"
SN_setct_CredRevReqTBEX = "setct-CredRevReqTBEX"
SN_setct_CredRevReqTBS = "setct-CredRevReqTBS"
SN_setct_CredRevReqTBSX = "setct-CredRevReqTBSX"
SN_setct_CredRevResData = "setct-CredRevResData"
SN_setct_CredRevResTBE = "setct-CredRevResTBE"
SN_setct_CRLNotificationResTBS = "setct-CRLNotificationResTBS"
SN_setct_CRLNotificationTBS = "setct-CRLNotificationTBS"
SN_setct_ErrorTBS = "setct-ErrorTBS"
SN_setct_HODInput = "setct-HODInput"
SN_setct_MeAqCInitResTBS = "setct-MeAqCInitResTBS"
SN_setct_OIData = "setct-OIData"
SN_setct_PANData = "setct-PANData"
SN_setct_PANOnly = "setct-PANOnly"
SN_setct_PANToken = "setct-PANToken"
SN_setct_PCertReqData = "setct-PCertReqData"
SN_setct_PCertResTBS = "setct-PCertResTBS"
SN_setct_PI = "setct-PI"
SN_setct_PI_TBS = "setct-PI-TBS"
SN_setct_PIData = "setct-PIData"
SN_setct_PIDataUnsigned = "setct-PIDataUnsigned"
SN_setct_PIDualSignedTBE = "setct-PIDualSignedTBE"
SN_setct_PInitResData = "setct-PInitResData"
SN_setct_PIUnsignedTBE = "setct-PIUnsignedTBE"
SN_setct_PResData = "setct-PResData"
SN_setct_RegFormReqTBE = "setct-RegFormReqTBE"
SN_setct_RegFormResTBS = "setct-RegFormResTBS"
SN_setext_cv = "setext-cv"
SN_setext_genCrypt = "setext-genCrypt"
SN_setext_miAuth = "setext-miAuth"
SN_setext_pinAny = "setext-pinAny"
SN_setext_pinSecure = "setext-pinSecure"
SN_setext_track2 = "setext-track2"
SN_sha = "SHA"
SN_sha1 = "SHA1"
SN_sha1WithRSA = "RSA-SHA1-2"
SN_sha1WithRSAEncryption = "RSA-SHA1"
SN_sha224 = "SHA224"
SN_sha224WithRSAEncryption = "RSA-SHA224"
SN_sha256 = "SHA256"
SN_sha256WithRSAEncryption = "RSA-SHA256"
SN_sha384 = "SHA384"
SN_sha384WithRSAEncryption = "RSA-SHA384"
SN_sha512 = "SHA512"
SN_sha512WithRSAEncryption = "RSA-SHA512"
SN_shaWithRSAEncryption = "RSA-SHA"
SN_sinfo_access = "subjectInfoAccess"
SN_SMIME = "SMIME"
SN_SMIMECapabilities = "SMIME-CAPS"
SN_SNMPv2 = "snmpv2"
SN_stateOrProvinceName = "ST"
SN_streetAddress = "street"
SN_subject_alt_name = "subjectAltName"
SN_subject_directory_attributes = "subjectDirectoryAttributes"
SN_subject_key_identifier = "subjectKeyIdentifier"
SN_surname = "SN"
SN_sxnet = "SXNetID"
SN_target_information = "targetInformation"
SN_textNotice = "textNotice"
SN_time_stamp = "timeStamping"
SN_title = "title"
SN_ucl = "ucl"
SN_undef = "UNDEF"
SN_userId = "UID"
SN_wap = "wap"
SN_wap_wsg = "wap-wsg"
SN_wap_wsg_idm_ecid_wtls1 = "wap-wsg-idm-ecid-wtls1"
SN_wap_wsg_idm_ecid_wtls10 = "wap-wsg-idm-ecid-wtls10"
SN_wap_wsg_idm_ecid_wtls11 = "wap-wsg-idm-ecid-wtls11"
SN_wap_wsg_idm_ecid_wtls12 = "wap-wsg-idm-ecid-wtls12"
SN_wap_wsg_idm_ecid_wtls3 = "wap-wsg-idm-ecid-wtls3"
SN_wap_wsg_idm_ecid_wtls4 = "wap-wsg-idm-ecid-wtls4"
SN_wap_wsg_idm_ecid_wtls5 = "wap-wsg-idm-ecid-wtls5"
SN_wap_wsg_idm_ecid_wtls6 = "wap-wsg-idm-ecid-wtls6"
SN_wap_wsg_idm_ecid_wtls7 = "wap-wsg-idm-ecid-wtls7"
SN_wap_wsg_idm_ecid_wtls8 = "wap-wsg-idm-ecid-wtls8"
SN_wap_wsg_idm_ecid_wtls9 = "wap-wsg-idm-ecid-wtls9"
SN_whirlpool = "whirlpool"
SN_X500 = "X500"
SN_X500algorithms = "X500algorithms"
SN_X509 = "X509"
SN_X9_57 = "X9-57"
SN_X9_62_c2onb191v4 = "c2onb191v4"
SN_X9_62_c2onb191v5 = "c2onb191v5"
SN_X9_62_c2onb239v4 = "c2onb239v4"
SN_X9_62_c2onb239v5 = "c2onb239v5"
SN_X9_62_c2pnb163v1 = "c2pnb163v1"
SN_X9_62_c2pnb163v2 = "c2pnb163v2"
SN_X9_62_c2pnb163v3 = "c2pnb163v3"
SN_X9_62_c2pnb176v1 = "c2pnb176v1"
SN_X9_62_c2pnb208w1 = "c2pnb208w1"
SN_X9_62_c2pnb272w1 = "c2pnb272w1"
SN_X9_62_c2pnb304w1 = "c2pnb304w1"
SN_X9_62_c2pnb368w1 = "c2pnb368w1"
SN_X9_62_c2tnb191v1 = "c2tnb191v1"
SN_X9_62_c2tnb191v2 = "c2tnb191v2"
SN_X9_62_c2tnb191v3 = "c2tnb191v3"
SN_X9_62_c2tnb239v1 = "c2tnb239v1"
SN_X9_62_c2tnb239v2 = "c2tnb239v2"
SN_X9_62_c2tnb239v3 = "c2tnb239v3"
SN_X9_62_c2tnb359v1 = "c2tnb359v1"
SN_X9_62_c2tnb431r1 = "c2tnb431r1"
SN_X9_62_characteristic_two_field = "characteristic-two-field"
SN_X9_62_id_characteristic_two_basis = "id-characteristic-two-basis"
SN_X9_62_id_ecPublicKey = "id-ecPublicKey"
SN_X9_62_onBasis = "onBasis"
SN_X9_62_ppBasis = "ppBasis"
SN_X9_62_prime192v1 = "prime192v1"
SN_X9_62_prime192v2 = "prime192v2"
SN_X9_62_prime192v3 = "prime192v3"
SN_X9_62_prime239v1 = "prime239v1"
SN_X9_62_prime239v2 = "prime239v2"
SN_X9_62_prime239v3 = "prime239v3"
SN_X9_62_prime256v1 = "prime256v1"
SN_X9_62_prime_field = "prime-field"
SN_X9_62_tpBasis = "tpBasis"
SN_X9cm = "X9cm"
SN_zlib_compression = "ZLIB"
SRTP_AES128_CM_SHA1_32 = 0x0002
SRTP_AES128_CM_SHA1_80 = 0x0001
SRTP_AES128_F8_SHA1_32 = 0x0004
SRTP_AES128_F8_SHA1_80 = 0x0003
SRTP_NULL_SHA1_32 = 0x0006
SRTP_NULL_SHA1_80 = 0x0005
SSL2_AT_MD5_WITH_RSA_ENCRYPTION = 0x01
SSL2_CF_5_BYTE_ENC = 0x01
SSL2_CF_8_BYTE_ENC = 0x02
SSL2_CHALLENGE_LENGTH = 16
SSL2_CK_DES_192_EDE3_CBC_WITH_MD5 = 0x020700c0
SSL2_CK_DES_192_EDE3_CBC_WITH_SHA = 0x020701c0
SSL2_CK_DES_64_CBC_WITH_MD5 = 0x02060040
SSL2_CK_DES_64_CBC_WITH_SHA = 0x02060140
SSL2_CK_DES_64_CFB64_WITH_MD5_1 = 0x02ff0800
SSL2_CK_IDEA_128_CBC_WITH_MD5 = 0x02050080
SSL2_CK_NULL = 0x02ff0810
SSL2_CK_NULL_WITH_MD5 = 0x02000000
SSL2_CK_RC2_128_CBC_EXPORT40_WITH_MD5 = 0x02040080
SSL2_CK_RC2_128_CBC_WITH_MD5 = 0x02030080
SSL2_CK_RC4_128_EXPORT40_WITH_MD5 = 0x02020080
SSL2_CK_RC4_128_WITH_MD5 = 0x02010080
SSL2_CK_RC4_64_WITH_MD5 = 0x02080080
SSL2_CONNECTION_ID_LENGTH = 16
SSL2_CT_X509_CERTIFICATE = 0x01
SSL2_MAX_CERT_CHALLENGE_LENGTH = 32
SSL2_MAX_CHALLENGE_LENGTH = 32
SSL2_MAX_CONNECTION_ID_LENGTH = 16
SSL2_MAX_KEY_MATERIAL_LENGTH = 24
SSL2_MAX_MASTER_KEY_LENGTH_IN_BITS = 256
SSL2_MAX_RECORD_LENGTH_2_BYTE_HEADER = 32767
SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER = 16383
SSL2_MAX_SSL_SESSION_ID_LENGTH = 32
SSL2_MIN_CERT_CHALLENGE_LENGTH = 16
SSL2_MIN_CHALLENGE_LENGTH = 16
SSL2_MT_CLIENT_CERTIFICATE = 8
SSL2_MT_CLIENT_FINISHED = 3
SSL2_MT_CLIENT_HELLO = 1
SSL2_MT_CLIENT_MASTER_KEY = 2
SSL2_MT_ERROR = 0
SSL2_MT_REQUEST_CERTIFICATE = 7
SSL2_MT_SERVER_FINISHED = 6
SSL2_MT_SERVER_HELLO = 4
SSL2_MT_SERVER_VERIFY = 5
SSL2_PE_BAD_CERTIFICATE = 0x0004
SSL2_PE_NO_CERTIFICATE = 0x0002
SSL2_PE_NO_CIPHER = 0x0001
SSL2_PE_UNDEFINED_ERROR = 0x0000
SSL2_PE_UNSUPPORTED_CERTIFICATE_TYPE = 0x0006
SSL2_SSL_SESSION_ID_LENGTH = 16
SSL2_TXT_DES_192_EDE3_CBC_WITH_MD5 = "DES-CBC3-MD5"
SSL2_TXT_DES_192_EDE3_CBC_WITH_SHA = "DES-CBC3-SHA"
SSL2_TXT_DES_64_CBC_WITH_MD5 = "DES-CBC-MD5"
SSL2_TXT_DES_64_CBC_WITH_SHA = "DES-CBC-SHA"
SSL2_TXT_DES_64_CFB64_WITH_MD5_1 = "DES-CFB-M1"
SSL2_TXT_IDEA_128_CBC_WITH_MD5 = "IDEA-CBC-MD5"
SSL2_TXT_NULL = "NULL"
SSL2_TXT_NULL_WITH_MD5 = "NULL-MD5"
SSL2_TXT_RC2_128_CBC_EXPORT40_WITH_MD5 = "EXP-RC2-CBC-MD5"
SSL2_TXT_RC2_128_CBC_WITH_MD5 = "RC2-CBC-MD5"
SSL2_TXT_RC4_128_EXPORT40_WITH_MD5 = "EXP-RC4-MD5"
SSL2_TXT_RC4_128_WITH_MD5 = "RC4-MD5"
SSL2_TXT_RC4_64_WITH_MD5 = "RC4-64-MD5"
SSL2_VERSION = 0x0002
SSL2_VERSION_MAJOR = 0x00
SSL2_VERSION_MINOR = 0x02
SSL3_AD_BAD_CERTIFICATE = 42
SSL3_AD_BAD_RECORD_MAC = 20
SSL3_AD_CERTIFICATE_EXPIRED = 45
SSL3_AD_CERTIFICATE_REVOKED = 44
SSL3_AD_CERTIFICATE_UNKNOWN = 46
SSL3_AD_CLOSE_NOTIFY = 0
SSL3_AD_DECOMPRESSION_FAILURE = 30
SSL3_AD_HANDSHAKE_FAILURE = 40
SSL3_AD_ILLEGAL_PARAMETER = 47
SSL3_AD_NO_CERTIFICATE = 41
SSL3_AD_UNEXPECTED_MESSAGE = 10
SSL3_AD_UNSUPPORTED_CERTIFICATE = 43
SSL3_AL_FATAL = 2
SSL3_AL_WARNING = 1
SSL3_ALIGN_PAYLOAD = 8
SSL3_CC_CLIENT = 0x10
SSL3_CC_READ = 0x01
SSL3_CC_SERVER = 0x20
SSL3_CC_WRITE = 0x02
SSL3_CK_ADH_DES_192_CBC_SHA = 0x0300001B
SSL3_CK_ADH_DES_40_CBC_SHA = 0x03000019
SSL3_CK_ADH_DES_64_CBC_SHA = 0x0300001A
SSL3_CK_ADH_RC4_128_MD5 = 0x03000018
SSL3_CK_ADH_RC4_40_MD5 = 0x03000017
SSL3_CK_DH_DSS_DES_192_CBC3_SHA = 0x0300000D
SSL3_CK_DH_DSS_DES_40_CBC_SHA = 0x0300000B
SSL3_CK_DH_DSS_DES_64_CBC_SHA = 0x0300000C
SSL3_CK_DH_RSA_DES_192_CBC3_SHA = 0x03000010
SSL3_CK_DH_RSA_DES_40_CBC_SHA = 0x0300000E
SSL3_CK_DH_RSA_DES_64_CBC_SHA = 0x0300000F
SSL3_CK_EDH_DSS_DES_192_CBC3_SHA = 0x03000013
SSL3_CK_EDH_DSS_DES_40_CBC_SHA = 0x03000011
SSL3_CK_EDH_DSS_DES_64_CBC_SHA = 0x03000012
SSL3_CK_EDH_RSA_DES_192_CBC3_SHA = 0x03000016
SSL3_CK_EDH_RSA_DES_40_CBC_SHA = 0x03000014
SSL3_CK_EDH_RSA_DES_64_CBC_SHA = 0x03000015
SSL3_CK_KRB5_DES_192_CBC3_MD5 = 0x03000023
SSL3_CK_KRB5_DES_192_CBC3_SHA = 0x0300001F
SSL3_CK_KRB5_DES_40_CBC_MD5 = 0x03000029
SSL3_CK_KRB5_DES_40_CBC_SHA = 0x03000026
SSL3_CK_KRB5_DES_64_CBC_MD5 = 0x03000022
SSL3_CK_KRB5_DES_64_CBC_SHA = 0x0300001E
SSL3_CK_KRB5_IDEA_128_CBC_MD5 = 0x03000025
SSL3_CK_KRB5_IDEA_128_CBC_SHA = 0x03000021
SSL3_CK_KRB5_RC2_40_CBC_MD5 = 0x0300002A
SSL3_CK_KRB5_RC2_40_CBC_SHA = 0x03000027
SSL3_CK_KRB5_RC4_128_MD5 = 0x03000024
SSL3_CK_KRB5_RC4_128_SHA = 0x03000020
SSL3_CK_KRB5_RC4_40_MD5 = 0x0300002B
SSL3_CK_KRB5_RC4_40_SHA = 0x03000028
SSL3_CK_RSA_DES_192_CBC3_SHA = 0x0300000A
SSL3_CK_RSA_DES_40_CBC_SHA = 0x03000008
SSL3_CK_RSA_DES_64_CBC_SHA = 0x03000009
SSL3_CK_RSA_IDEA_128_SHA = 0x03000007
SSL3_CK_RSA_NULL_MD5 = 0x03000001
SSL3_CK_RSA_NULL_SHA = 0x03000002
SSL3_CK_RSA_RC2_40_MD5 = 0x03000006
SSL3_CK_RSA_RC4_128_MD5 = 0x03000004
SSL3_CK_RSA_RC4_128_SHA = 0x03000005
SSL3_CK_RSA_RC4_40_MD5 = 0x03000003
SSL3_CK_SCSV = 0x030000FF
SSL3_CT_DSS_EPHEMERAL_DH = 6
SSL3_CT_DSS_FIXED_DH = 4
SSL3_CT_DSS_SIGN = 2
SSL3_CT_FORTEZZA_DMS = 20
SSL3_CT_NUMBER = 9
SSL3_CT_RSA_EPHEMERAL_DH = 5
SSL3_CT_RSA_FIXED_DH = 3
SSL3_CT_RSA_SIGN = 1
SSL3_FLAGS_DELAY_CLIENT_FINISHED = 0x0002
SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS = 0x0001
SSL3_FLAGS_POP_BUFFER = 0x0004
SSL3_FLAGS_SGC_RESTART_DONE = 0x0040
SSL3_MASTER_SECRET_SIZE = 48
SSL3_MAX_SSL_SESSION_ID_LENGTH = 32
SSL3_MD_CLIENT_FINISHED_CONST = "\x43\x4C\x4E\x54"
SSL3_MD_SERVER_FINISHED_CONST = "\x53\x52\x56\x52"
SSL3_MT_CCS = 1
SSL3_MT_CERTIFICATE = 11
SSL3_MT_CERTIFICATE_REQUEST = 13
SSL3_MT_CERTIFICATE_STATUS = 22
SSL3_MT_CERTIFICATE_VERIFY = 15
SSL3_MT_CLIENT_HELLO = 1
SSL3_MT_CLIENT_KEY_EXCHANGE = 16
SSL3_MT_FINISHED = 20
SSL3_MT_HELLO_REQUEST = 0
SSL3_MT_NEWSESSION_TICKET = 4
SSL3_MT_NEXT_PROTO = 67
SSL3_MT_SERVER_DONE = 14
SSL3_MT_SERVER_HELLO = 2
SSL3_MT_SERVER_KEY_EXCHANGE = 12
SSL3_RANDOM_SIZE = 32
SSL3_RT_ALERT = 21
SSL3_RT_APPLICATION_DATA = 23
SSL3_RT_CHANGE_CIPHER_SPEC = 20
SSL3_RT_HANDSHAKE = 22
SSL3_RT_HEADER_LENGTH = 5
SSL3_RT_MAX_COMPRESSED_OVERHEAD = 1024
SSL3_RT_MAX_MD_SIZE = 64
SSL3_RT_MAX_EXTRA = (16384)
SSL3_RT_MAX_PLAIN_LENGTH = 16384
SSL3_SESSION_ID_SIZE = 32
SSL3_SSL_SESSION_ID_LENGTH = 32
SSL3_TXT_ADH_DES_192_CBC_SHA = "ADH-DES-CBC3-SHA"
SSL3_TXT_ADH_DES_40_CBC_SHA = "EXP-ADH-DES-CBC-SHA"
SSL3_TXT_ADH_DES_64_CBC_SHA = "ADH-DES-CBC-SHA"
SSL3_TXT_ADH_RC4_128_MD5 = "ADH-RC4-MD5"
SSL3_TXT_ADH_RC4_40_MD5 = "EXP-ADH-RC4-MD5"
SSL3_TXT_DH_DSS_DES_192_CBC3_SHA = "DH-DSS-DES-CBC3-SHA"
SSL3_TXT_DH_DSS_DES_40_CBC_SHA = "EXP-DH-DSS-DES-CBC-SHA"
SSL3_TXT_DH_DSS_DES_64_CBC_SHA = "DH-DSS-DES-CBC-SHA"
SSL3_TXT_DH_RSA_DES_192_CBC3_SHA = "DH-RSA-DES-CBC3-SHA"
SSL3_TXT_DH_RSA_DES_40_CBC_SHA = "EXP-DH-RSA-DES-CBC-SHA"
SSL3_TXT_DH_RSA_DES_64_CBC_SHA = "DH-RSA-DES-CBC-SHA"
SSL3_TXT_EDH_DSS_DES_192_CBC3_SHA = "EDH-DSS-DES-CBC3-SHA"
SSL3_TXT_EDH_DSS_DES_40_CBC_SHA = "EXP-EDH-DSS-DES-CBC-SHA"
SSL3_TXT_EDH_DSS_DES_64_CBC_SHA = "EDH-DSS-DES-CBC-SHA"
SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA = "EDH-RSA-DES-CBC3-SHA"
SSL3_TXT_EDH_RSA_DES_40_CBC_SHA = "EXP-EDH-RSA-DES-CBC-SHA"
SSL3_TXT_EDH_RSA_DES_64_CBC_SHA = "EDH-RSA-DES-CBC-SHA"
SSL3_TXT_KRB5_DES_192_CBC3_MD5 = "KRB5-DES-CBC3-MD5"
SSL3_TXT_KRB5_DES_192_CBC3_SHA = "KRB5-DES-CBC3-SHA"
SSL3_TXT_KRB5_DES_40_CBC_MD5 = "EXP-KRB5-DES-CBC-MD5"
SSL3_TXT_KRB5_DES_40_CBC_SHA = "EXP-KRB5-DES-CBC-SHA"
SSL3_TXT_KRB5_DES_64_CBC_MD5 = "KRB5-DES-CBC-MD5"
SSL3_TXT_KRB5_DES_64_CBC_SHA = "KRB5-DES-CBC-SHA"
SSL3_TXT_KRB5_IDEA_128_CBC_MD5 = "KRB5-IDEA-CBC-MD5"
SSL3_TXT_KRB5_IDEA_128_CBC_SHA = "KRB5-IDEA-CBC-SHA"
SSL3_TXT_KRB5_RC2_40_CBC_MD5 = "EXP-KRB5-RC2-CBC-MD5"
SSL3_TXT_KRB5_RC2_40_CBC_SHA = "EXP-KRB5-RC2-CBC-SHA"
SSL3_TXT_KRB5_RC4_128_MD5 = "KRB5-RC4-MD5"
SSL3_TXT_KRB5_RC4_128_SHA = "KRB5-RC4-SHA"
SSL3_TXT_KRB5_RC4_40_MD5 = "EXP-KRB5-RC4-MD5"
SSL3_TXT_KRB5_RC4_40_SHA = "EXP-KRB5-RC4-SHA"
SSL3_TXT_RSA_DES_192_CBC3_SHA = "DES-CBC3-SHA"
SSL3_TXT_RSA_DES_40_CBC_SHA = "EXP-DES-CBC-SHA"
SSL3_TXT_RSA_DES_64_CBC_SHA = "DES-CBC-SHA"
SSL3_TXT_RSA_IDEA_128_SHA = "IDEA-CBC-SHA"
SSL3_TXT_RSA_NULL_MD5 = "NULL-MD5"
SSL3_TXT_RSA_NULL_SHA = "NULL-SHA"
SSL3_TXT_RSA_RC2_40_MD5 = "EXP-RC2-CBC-MD5"
SSL3_TXT_RSA_RC4_128_MD5 = "RC4-MD5"
SSL3_TXT_RSA_RC4_128_SHA = "RC4-SHA"
SSL3_TXT_RSA_RC4_40_MD5 = "EXP-RC4-MD5"
SSL3_VERSION = 0x0300
SSL3_VERSION_MAJOR = 0x03
SSL3_VERSION_MINOR = 0x00
SSL_AD_ACCESS_DENIED = TLS1_AD_ACCESS_DENIED
SSL_AD_BAD_CERTIFICATE = SSL3_AD_BAD_CERTIFICATE
SSL_AD_BAD_CERTIFICATE_HASH_VALUE = TLS1_AD_BAD_CERTIFICATE_HASH_VALUE
SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE = TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE
SSL_AD_BAD_RECORD_MAC = SSL3_AD_BAD_RECORD_MAC
SSL_AD_CERTIFICATE_EXPIRED = SSL3_AD_CERTIFICATE_EXPIRED
SSL_AD_CERTIFICATE_REVOKED = SSL3_AD_CERTIFICATE_REVOKED
SSL_AD_CERTIFICATE_UNKNOWN = SSL3_AD_CERTIFICATE_UNKNOWN
SSL_AD_CERTIFICATE_UNOBTAINABLE = TLS1_AD_CERTIFICATE_UNOBTAINABLE
SSL_AD_CLOSE_NOTIFY = SSL3_AD_CLOSE_NOTIFY
SSL_AD_DECODE_ERROR = TLS1_AD_DECODE_ERROR
SSL_AD_DECOMPRESSION_FAILURE = SSL3_AD_DECOMPRESSION_FAILURE
SSL_AD_DECRYPT_ERROR = TLS1_AD_DECRYPT_ERROR
SSL_AD_DECRYPTION_FAILED = TLS1_AD_DECRYPTION_FAILED
SSL_AD_EXPORT_RESTRICTION = TLS1_AD_EXPORT_RESTRICTION
SSL_AD_HANDSHAKE_FAILURE = SSL3_AD_HANDSHAKE_FAILURE
SSL_AD_ILLEGAL_PARAMETER = SSL3_AD_ILLEGAL_PARAMETER
SSL_AD_INSUFFICIENT_SECURITY = TLS1_AD_INSUFFICIENT_SECURITY
SSL_AD_INTERNAL_ERROR = TLS1_AD_INTERNAL_ERROR
SSL_AD_NO_CERTIFICATE = SSL3_AD_NO_CERTIFICATE
SSL_AD_NO_RENEGOTIATION = TLS1_AD_NO_RENEGOTIATION
SSL_AD_PROTOCOL_VERSION = TLS1_AD_PROTOCOL_VERSION
SSL_AD_REASON_OFFSET = 1000
SSL_AD_RECORD_OVERFLOW = TLS1_AD_RECORD_OVERFLOW
SSL_AD_UNEXPECTED_MESSAGE = SSL3_AD_UNEXPECTED_MESSAGE
SSL_AD_UNKNOWN_CA = TLS1_AD_UNKNOWN_CA
SSL_AD_UNKNOWN_PSK_IDENTITY = TLS1_AD_UNKNOWN_PSK_IDENTITY
SSL_AD_UNRECOGNIZED_NAME = TLS1_AD_UNRECOGNIZED_NAME
SSL_AD_UNSUPPORTED_CERTIFICATE = SSL3_AD_UNSUPPORTED_CERTIFICATE
SSL_AD_UNSUPPORTED_EXTENSION = TLS1_AD_UNSUPPORTED_EXTENSION
SSL_AD_USER_CANCELLED = TLS1_AD_USER_CANCELLED
SSL_CB_ALERT = 0x4000
SSL_CB_EXIT = 0x02
SSL_CB_HANDSHAKE_DONE = 0x20
SSL_CB_HANDSHAKE_START = 0x10
SSL_CB_LOOP = 0x01
SSL_CB_READ = 0x04
SSL_CB_WRITE = 0x08
SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS = 83
SSL_CTRL_CLEAR_MODE = 78
SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS = 11
SSL_CTRL_CLEAR_OPTIONS = 77
SSL_CTRL_EXTRA_CHAIN_CERT = 14
SSL_CTRL_GET_CLIENT_CERT_REQUEST = 9
SSL_CTRL_GET_EXTRA_CHAIN_CERTS = 82
SSL_CTRL_GET_FLAGS = 13
SSL_CTRL_GET_MAX_CERT_LIST = 50
SSL_CTRL_GET_NUM_RENEGOTIATIONS = 10
SSL_CTRL_GET_READ_AHEAD = 40
SSL_CTRL_GET_RI_SUPPORT = 76
SSL_CTRL_GET_SESS_CACHE_MODE = 45
SSL_CTRL_GET_SESS_CACHE_SIZE = 43
SSL_CTRL_GET_SESSION_REUSED = 8
SSL_CTRL_GET_TLS_EXT_HEARTBEAT_PENDING = 86
SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS = 66
SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS = 68
SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP = 70
SSL_CTRL_GET_TLSEXT_TICKET_KEYS = 58
SSL_CTRL_GET_TOTAL_RENEGOTIATIONS = 12
SSL_CTRL_MODE = 33
SSL_CTRL_NEED_TMP_RSA = 1
SSL_CTRL_OPTIONS = 32
SSL_CTRL_SESS_ACCEPT = 24
SSL_CTRL_SESS_ACCEPT_GOOD = 25
SSL_CTRL_SESS_ACCEPT_RENEGOTIATE = 26
SSL_CTRL_SESS_CACHE_FULL = 31
SSL_CTRL_SESS_CB_HIT = 28
SSL_CTRL_SESS_CONNECT = 21
SSL_CTRL_SESS_CONNECT_GOOD = 22
SSL_CTRL_SESS_CONNECT_RENEGOTIATE = 23
SSL_CTRL_SESS_HIT = 27
SSL_CTRL_SESS_MISSES = 29
SSL_CTRL_SESS_NUMBER = 20
SSL_CTRL_SESS_TIMEOUTS = 30
SSL_CTRL_SET_MAX_CERT_LIST = 51
SSL_CTRL_SET_MAX_SEND_FRAGMENT = 52
SSL_CTRL_SET_MSG_CALLBACK = 15
SSL_CTRL_SET_MSG_CALLBACK_ARG = 16
SSL_CTRL_SET_MTU = 17
SSL_CTRL_SET_READ_AHEAD = 41
SSL_CTRL_SET_SESS_CACHE_MODE = 44
SSL_CTRL_SET_SESS_CACHE_SIZE = 42
SSL_CTRL_SET_SRP_ARG = 78
SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB = 77
SSL_CTRL_SET_SRP_VERIFY_PARAM_CB = 76
SSL_CTRL_SET_TLS_EXT_HEARTBEAT_NO_REQUESTS = 87
SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD = 81
SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH = 80
SSL_CTRL_SET_TLS_EXT_SRP_USERNAME = 79
SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB = 75
SSL_CTRL_SET_TLSEXT_DEBUG_ARG = 57
SSL_CTRL_SET_TLSEXT_DEBUG_CB = 56
SSL_CTRL_SET_TLSEXT_HOSTNAME = 55
SSL_CTRL_SET_TLSEXT_OPAQUE_PRF_INPUT = 60
SSL_CTRL_SET_TLSEXT_OPAQUE_PRF_INPUT_CB = 61
SSL_CTRL_SET_TLSEXT_OPAQUE_PRF_INPUT_CB_ARG = 62
SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG = 54
SSL_CTRL_SET_TLSEXT_SERVERNAME_CB = 53
SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB = 63
SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG = 64
SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS = 67
SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS = 69
SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP = 71
SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE = 65
SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB = 72
SSL_CTRL_SET_TLSEXT_TICKET_KEYS = 59
SSL_CTRL_SET_TMP_DH = 3
SSL_CTRL_SET_TMP_DH_CB = 6
SSL_CTRL_SET_TMP_ECDH = 4
SSL_CTRL_SET_TMP_ECDH_CB = 7
SSL_CTRL_SET_TMP_RSA = 2
SSL_CTRL_SET_TMP_RSA_CB = 5
SSL_CTRL_TLS_EXT_SEND_HEARTBEAT = 85
SSL_DEFAULT_CIPHER_LIST = "ALL:!aNULL:!eNULL:!SSLv2"
SSL_ERROR_NONE = 0
SSL_ERROR_SSL = 1
SSL_ERROR_SYSCALL = 5
SSL_ERROR_WANT_ACCEPT = 8
SSL_ERROR_WANT_CONNECT = 7
SSL_ERROR_WANT_READ = 2
SSL_ERROR_WANT_WRITE = 3
SSL_ERROR_WANT_X509_LOOKUP = 4
SSL_ERROR_ZERO_RETURN = 6
SSL_F_CLIENT_CERTIFICATE = 100
SSL_F_CLIENT_FINISHED = 167
SSL_F_CLIENT_HELLO = 101
SSL_F_CLIENT_MASTER_KEY = 102
SSL_F_D2I_SSL_SESSION = 103
SSL_F_DO_DTLS1_WRITE = 245
SSL_F_DO_SSL3_WRITE = 104
SSL_F_DTLS1_ACCEPT = 246
SSL_F_DTLS1_ADD_CERT_TO_BUF = 295
SSL_F_DTLS1_BUFFER_RECORD = 247
SSL_F_DTLS1_CHECK_TIMEOUT_NUM = 316
SSL_F_DTLS1_CLIENT_HELLO = 248
SSL_F_DTLS1_CONNECT = 249
SSL_F_DTLS1_ENC = 250
SSL_F_DTLS1_GET_HELLO_VERIFY = 251
SSL_F_DTLS1_GET_MESSAGE = 252
SSL_F_DTLS1_GET_MESSAGE_FRAGMENT = 253
SSL_F_DTLS1_GET_RECORD = 254
SSL_F_DTLS1_HANDLE_TIMEOUT = 297
SSL_F_DTLS1_HEARTBEAT = 305
SSL_F_DTLS1_OUTPUT_CERT_CHAIN = 255
SSL_F_DTLS1_PREPROCESS_FRAGMENT = 288
SSL_F_DTLS1_PROCESS_OUT_OF_SEQ_MESSAGE = 256
SSL_F_DTLS1_PROCESS_RECORD = 257
SSL_F_DTLS1_READ_BYTES = 258
SSL_F_DTLS1_READ_FAILED = 259
SSL_F_DTLS1_SEND_CERTIFICATE_REQUEST = 260
SSL_F_DTLS1_SEND_CLIENT_CERTIFICATE = 261
SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE = 262
SSL_F_DTLS1_SEND_CLIENT_VERIFY = 263
SSL_F_DTLS1_SEND_HELLO_VERIFY_REQUEST = 264
SSL_F_DTLS1_SEND_SERVER_CERTIFICATE = 265
SSL_F_DTLS1_SEND_SERVER_HELLO = 266
SSL_F_DTLS1_SEND_SERVER_KEY_EXCHANGE = 267
SSL_F_DTLS1_WRITE_APP_DATA_BYTES = 268
SSL_F_GET_CLIENT_FINISHED = 105
SSL_F_GET_CLIENT_HELLO = 106
SSL_F_GET_CLIENT_MASTER_KEY = 107
SSL_F_GET_SERVER_FINISHED = 108
SSL_F_GET_SERVER_HELLO = 109
SSL_F_GET_SERVER_VERIFY = 110
SSL_F_I2D_SSL_SESSION = 111
SSL_F_READ_N = 112
SSL_F_REQUEST_CERTIFICATE = 113
SSL_F_SERVER_FINISH = 239
SSL_F_SERVER_HELLO = 114
SSL_F_SERVER_VERIFY = 240
SSL_F_SSL23_ACCEPT = 115
SSL_F_SSL23_CLIENT_HELLO = 116
SSL_F_SSL23_CONNECT = 117
SSL_F_SSL23_GET_CLIENT_HELLO = 118
SSL_F_SSL23_GET_SERVER_HELLO = 119
SSL_F_SSL23_PEEK = 237
SSL_F_SSL23_READ = 120
SSL_F_SSL23_WRITE = 121
SSL_F_SSL2_ACCEPT = 122
SSL_F_SSL2_CONNECT = 123
SSL_F_SSL2_ENC_INIT = 124
SSL_F_SSL2_GENERATE_KEY_MATERIAL = 241
SSL_F_SSL2_PEEK = 234
SSL_F_SSL2_READ = 125
SSL_F_SSL2_READ_INTERNAL = 236
SSL_F_SSL2_SET_CERTIFICATE = 126
SSL_F_SSL2_WRITE = 127
SSL_F_SSL3_ACCEPT = 128
SSL_F_SSL3_ADD_CERT_TO_BUF = 296
SSL_F_SSL3_CALLBACK_CTRL = 233
SSL_F_SSL3_CHANGE_CIPHER_STATE = 129
SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM = 130
SSL_F_SSL3_CHECK_CLIENT_HELLO = 304
SSL_F_SSL3_CLIENT_HELLO = 131
SSL_F_SSL3_CONNECT = 132
SSL_F_SSL3_CTRL = 213
SSL_F_SSL3_CTX_CTRL = 133
SSL_F_SSL3_DIGEST_CACHED_RECORDS = 293
SSL_F_SSL3_DO_CHANGE_CIPHER_SPEC = 292
SSL_F_SSL3_ENC = 134
SSL_F_SSL3_GENERATE_KEY_BLOCK = 238
SSL_F_SSL3_GET_CERT_STATUS = 289
SSL_F_SSL3_GET_CERT_VERIFY = 136
SSL_F_SSL3_GET_CERTIFICATE_REQUEST = 135
SSL_F_SSL3_GET_CLIENT_CERTIFICATE = 137
SSL_F_SSL3_GET_CLIENT_HELLO = 138
SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE = 139
SSL_F_SSL3_GET_FINISHED = 140
SSL_F_SSL3_GET_KEY_EXCHANGE = 141
SSL_F_SSL3_GET_MESSAGE = 142
SSL_F_SSL3_GET_NEW_SESSION_TICKET = 283
SSL_F_SSL3_GET_NEXT_PROTO = 306
SSL_F_SSL3_GET_RECORD = 143
SSL_F_SSL3_GET_SERVER_CERTIFICATE = 144
SSL_F_SSL3_GET_SERVER_DONE = 145
SSL_F_SSL3_GET_SERVER_HELLO = 146
SSL_F_SSL3_HANDSHAKE_MAC = 285
SSL_F_SSL3_NEW_SESSION_TICKET = 287
SSL_F_SSL3_OUTPUT_CERT_CHAIN = 147
SSL_F_SSL3_PEEK = 235
SSL_F_SSL3_READ_BYTES = 148
SSL_F_SSL3_READ_N = 149
SSL_F_SSL3_SEND_CERTIFICATE_REQUEST = 150
SSL_F_SSL3_SEND_CLIENT_CERTIFICATE = 151
SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE = 152
SSL_F_SSL3_SEND_CLIENT_VERIFY = 153
SSL_F_SSL3_SEND_SERVER_CERTIFICATE = 154
SSL_F_SSL3_SEND_SERVER_HELLO = 242
SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE = 155
SSL_F_SSL3_SETUP_KEY_BLOCK = 157
SSL_F_SSL3_SETUP_READ_BUFFER = 156
SSL_F_SSL3_SETUP_WRITE_BUFFER = 291
SSL_F_SSL3_WRITE_BYTES = 158
SSL_F_SSL3_WRITE_PENDING = 159
SSL_F_SSL_ADD_CLIENTHELLO_RENEGOTIATE_EXT = 298
SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT = 277
SSL_F_SSL_ADD_CLIENTHELLO_USE_SRTP_EXT = 307
SSL_F_SSL_ADD_DIR_CERT_SUBJECTS_TO_STACK = 215
SSL_F_SSL_ADD_FILE_CERT_SUBJECTS_TO_STACK = 216
SSL_F_SSL_ADD_SERVERHELLO_RENEGOTIATE_EXT = 299
SSL_F_SSL_ADD_SERVERHELLO_TLSEXT = 278
SSL_F_SSL_ADD_SERVERHELLO_USE_SRTP_EXT = 308
SSL_F_SSL_BAD_METHOD = 160
SSL_F_SSL_BYTES_TO_CIPHER_LIST = 161
SSL_F_SSL_CERT_DUP = 221
SSL_F_SSL_CERT_INST = 222
SSL_F_SSL_CERT_INSTANTIATE = 214
SSL_F_SSL_CERT_NEW = 162
SSL_F_SSL_CHECK_PRIVATE_KEY = 163
SSL_F_SSL_CHECK_SERVERHELLO_TLSEXT = 280
SSL_F_SSL_CHECK_SRVR_ECC_CERT_AND_ALG = 279
SSL_F_SSL_CIPHER_PROCESS_RULESTR = 230
SSL_F_SSL_CIPHER_STRENGTH_SORT = 231
SSL_F_SSL_CLEAR = 164
SSL_F_SSL_COMP_ADD_COMPRESSION_METHOD = 165
SSL_F_SSL_CREATE_CIPHER_LIST = 166
SSL_F_SSL_CTRL = 232
SSL_F_SSL_CTX_CHECK_PRIVATE_KEY = 168
SSL_F_SSL_CTX_MAKE_PROFILES = 309
SSL_F_SSL_CTX_NEW = 169
SSL_F_SSL_CTX_SET_CIPHER_LIST = 269
SSL_F_SSL_CTX_SET_CLIENT_CERT_ENGINE = 290
SSL_F_SSL_CTX_SET_PURPOSE = 226
SSL_F_SSL_CTX_SET_SESSION_ID_CONTEXT = 219
SSL_F_SSL_CTX_SET_SSL_VERSION = 170
SSL_F_SSL_CTX_SET_TRUST = 229
SSL_F_SSL_CTX_USE_CERTIFICATE = 171
SSL_F_SSL_CTX_USE_CERTIFICATE_ASN1 = 172
SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE = 220
SSL_F_SSL_CTX_USE_CERTIFICATE_FILE = 173
SSL_F_SSL_CTX_USE_PRIVATEKEY = 174
SSL_F_SSL_CTX_USE_PRIVATEKEY_ASN1 = 175
SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE = 176
SSL_F_SSL_CTX_USE_PSK_IDENTITY_HINT = 272
SSL_F_SSL_CTX_USE_RSAPRIVATEKEY = 177
SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_ASN1 = 178
SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE = 179
SSL_F_SSL_DO_HANDSHAKE = 180
SSL_F_SSL_GET_NEW_SESSION = 181
SSL_F_SSL_GET_PREV_SESSION = 217
SSL_F_SSL_GET_SERVER_SEND_CERT = 182
SSL_F_SSL_GET_SIGN_PKEY = 183
SSL_F_SSL_INIT_WBIO_BUFFER = 184
SSL_F_SSL_LOAD_CLIENT_CA_FILE = 185
SSL_F_SSL_NEW = 186
SSL_F_SSL_PARSE_CLIENTHELLO_RENEGOTIATE_EXT = 300
SSL_F_SSL_PARSE_CLIENTHELLO_TLSEXT = 302
SSL_F_SSL_PARSE_CLIENTHELLO_USE_SRTP_EXT = 310
SSL_F_SSL_PARSE_SERVERHELLO_RENEGOTIATE_EXT = 301
SSL_F_SSL_PARSE_SERVERHELLO_TLSEXT = 303
SSL_F_SSL_PARSE_SERVERHELLO_USE_SRTP_EXT = 311
SSL_F_SSL_PEEK = 270
SSL_F_SSL_PREPARE_CLIENTHELLO_TLSEXT = 281
SSL_F_SSL_PREPARE_SERVERHELLO_TLSEXT = 282
SSL_F_SSL_READ = 223
SSL_F_SSL_RSA_PRIVATE_DECRYPT = 187
SSL_F_SSL_RSA_PUBLIC_ENCRYPT = 188
SSL_F_SSL_SESS_CERT_NEW = 225
SSL_F_SSL_SESSION_NEW = 189
SSL_F_SSL_SESSION_PRINT_FP = 190
SSL_F_SSL_SESSION_SET1_ID_CONTEXT = 312
SSL_F_SSL_SET_CERT = 191
SSL_F_SSL_SET_CIPHER_LIST = 271
SSL_F_SSL_SET_FD = 192
SSL_F_SSL_SET_PKEY = 193
SSL_F_SSL_SET_PURPOSE = 227
SSL_F_SSL_SET_RFD = 194
SSL_F_SSL_SET_SESSION = 195
SSL_F_SSL_SET_SESSION_ID_CONTEXT = 218
SSL_F_SSL_SET_SESSION_TICKET_EXT = 294
SSL_F_SSL_SET_TRUST = 228
SSL_F_SSL_SET_WFD = 196
SSL_F_SSL_SHUTDOWN = 224
SSL_F_SSL_SRP_CTX_INIT = 313
SSL_F_SSL_UNDEFINED_CONST_FUNCTION = 243
SSL_F_SSL_UNDEFINED_FUNCTION = 197
SSL_F_SSL_UNDEFINED_VOID_FUNCTION = 244
SSL_F_SSL_USE_CERTIFICATE = 198
SSL_F_SSL_USE_CERTIFICATE_ASN1 = 199
SSL_F_SSL_USE_CERTIFICATE_FILE = 200
SSL_F_SSL_USE_PRIVATEKEY = 201
SSL_F_SSL_USE_PRIVATEKEY_ASN1 = 202
SSL_F_SSL_USE_PRIVATEKEY_FILE = 203
SSL_F_SSL_USE_PSK_IDENTITY_HINT = 273
SSL_F_SSL_USE_RSAPRIVATEKEY = 204
SSL_F_SSL_USE_RSAPRIVATEKEY_ASN1 = 205
SSL_F_SSL_USE_RSAPRIVATEKEY_FILE = 206
SSL_F_SSL_VERIFY_CERT_CHAIN = 207
SSL_F_SSL_WRITE = 208
SSL_F_TLS1_CERT_VERIFY_MAC = 286
SSL_F_TLS1_CHANGE_CIPHER_STATE = 209
SSL_F_TLS1_CHECK_SERVERHELLO_TLSEXT = 274
SSL_F_TLS1_ENC = 210
SSL_F_TLS1_EXPORT_KEYING_MATERIAL = 314
SSL_F_TLS1_HEARTBEAT = 315
SSL_F_TLS1_PREPARE_CLIENTHELLO_TLSEXT = 275
SSL_F_TLS1_PREPARE_SERVERHELLO_TLSEXT = 276
SSL_F_TLS1_PRF = 284
SSL_F_TLS1_SETUP_KEY_BLOCK = 211
SSL_F_WRITE_PENDING = 212
SSL_MAC_FLAG_READ_MAC_STREAM = 1
SSL_MAC_FLAG_WRITE_MAC_STREAM = 2
SSL_MAX_BUF_FREELIST_LEN_DEFAULT = 32
SSL_MAX_CERT_LIST_DEFAULT = 1024*100
SSL_MAX_KEY_ARG_LENGTH = 8
SSL_MAX_KRB5_PRINCIPAL_LENGTH = 256
SSL_MAX_MASTER_KEY_LENGTH = 48
SSL_MAX_SID_CTX_LENGTH = 32
SSL_MAX_SSL_SESSION_ID_LENGTH = 32
SSL_MIN_RSA_MODULUS_LENGTH_IN_BYTES = (512/8)
SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = 0x00000002
SSL_MODE_AUTO_RETRY = 0x00000004
SSL_MODE_ENABLE_PARTIAL_WRITE = 0x00000001
SSL_MODE_NO_AUTO_CHAIN = 0x00000008
SSL_MODE_RELEASE_BUFFERS = 0x00000010
SSL_NOTHING = 1
SSL_OP_ALL = 0x80000BFF
SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION = 0x00040000
SSL_OP_CIPHER_SERVER_PREFERENCE = 0x00400000
SSL_OP_CISCO_ANYCONNECT = 0x00008000
SSL_OP_COOKIE_EXCHANGE = 0x00002000
SSL_OP_CRYPTOPRO_TLSEXT_BUG = 0x80000000
SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS = 0x00000800
SSL_OP_EPHEMERAL_RSA = 0x00200000
SSL_OP_LEGACY_SERVER_CONNECT = 0x00000004
SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER = 0x00000020
SSL_OP_MICROSOFT_SESS_ID_BUG = 0x00000001
SSL_OP_MSIE_SSLV2_RSA_PADDING = 0x00000040
SSL_OP_NETSCAPE_CA_DN_BUG = 0x20000000
SSL_OP_NETSCAPE_CHALLENGE_BUG = 0x00000002
SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG = 0x40000000
SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG = 0x00000008
SSL_OP_NO_COMPRESSION = 0x00020000
SSL_OP_NO_QUERY_MTU = 0x00001000
SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION = 0x00010000
SSL_OP_NO_SSLv2 = 0x01000000
SSL_OP_NO_SSLv3 = 0x02000000
SSL_OP_NO_TICKET = 0x00004000
SSL_OP_NO_TLSv1 = 0x04000000
SSL_OP_NO_TLSv1_1 = 0x10000000
SSL_OP_NO_TLSv1_2 = 0x08000000
SSL_OP_PKCS1_CHECK_1 = 0x0
SSL_OP_PKCS1_CHECK_2 = 0x0
SSL_OP_SINGLE_DH_USE = 0x00100000
SSL_OP_SINGLE_ECDH_USE = 0x00080000
SSL_OP_SSLEAY_080_CLIENT_DH_BUG = 0x00000080
SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG = 0x00000010
SSL_OP_TLS_BLOCK_PADDING_BUG = 0x00000200
SSL_OP_TLS_D5_BUG = 0x00000100
SSL_OP_TLS_ROLLBACK_BUG = 0x00800000
SSL_R_APP_DATA_IN_HANDSHAKE = 100
SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT = 272
SSL_R_BAD_ALERT_RECORD = 101
SSL_R_BAD_AUTHENTICATION_TYPE = 102
SSL_R_BAD_CHANGE_CIPHER_SPEC = 103
SSL_R_BAD_CHECKSUM = 104
SSL_R_BAD_DATA_RETURNED_BY_CALLBACK = 106
SSL_R_BAD_DECOMPRESSION = 107
SSL_R_BAD_DH_G_LENGTH = 108
SSL_R_BAD_DH_P_LENGTH = 110
SSL_R_BAD_DH_PUB_KEY_LENGTH = 109
SSL_R_BAD_DIGEST_LENGTH = 111
SSL_R_BAD_DSA_SIGNATURE = 112
SSL_R_BAD_ECC_CERT = 304
SSL_R_BAD_ECDSA_SIGNATURE = 305
SSL_R_BAD_ECPOINT = 306
SSL_R_BAD_HANDSHAKE_LENGTH = 332
SSL_R_BAD_HELLO_REQUEST = 105
SSL_R_BAD_LENGTH = 271
SSL_R_BAD_MAC_DECODE = 113
SSL_R_BAD_MAC_LENGTH = 333
SSL_R_BAD_MESSAGE_TYPE = 114
SSL_R_BAD_PACKET_LENGTH = 115
SSL_R_BAD_PROTOCOL_VERSION_NUMBER = 116
SSL_R_BAD_PSK_IDENTITY_HINT_LENGTH = 316
SSL_R_BAD_RESPONSE_ARGUMENT = 117
SSL_R_BAD_RSA_DECRYPT = 118
SSL_R_BAD_RSA_E_LENGTH = 120
SSL_R_BAD_RSA_ENCRYPT = 119
SSL_R_BAD_RSA_MODULUS_LENGTH = 121
SSL_R_BAD_RSA_SIGNATURE = 122
SSL_R_BAD_SIGNATURE = 123
SSL_R_BAD_SRP_A_LENGTH = 347
SSL_R_BAD_SRP_B_LENGTH = 348
SSL_R_BAD_SRP_G_LENGTH = 349
SSL_R_BAD_SRP_N_LENGTH = 350
SSL_R_BAD_SRP_S_LENGTH = 351
SSL_R_BAD_SRTP_MKI_VALUE = 352
SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST = 353
SSL_R_BAD_SSL_FILETYPE = 124
SSL_R_BAD_SSL_SESSION_ID_LENGTH = 125
SSL_R_BAD_STATE = 126
SSL_R_BAD_WRITE_RETRY = 127
SSL_R_BIO_NOT_SET = 128
SSL_R_BLOCK_CIPHER_PAD_IS_WRONG = 129
SSL_R_BN_LIB = 130
SSL_R_CA_DN_LENGTH_MISMATCH = 131
SSL_R_CA_DN_TOO_LONG = 132
SSL_R_CCS_RECEIVED_EARLY = 133
SSL_R_CERT_LENGTH_MISMATCH = 135
SSL_R_CERTIFICATE_VERIFY_FAILED = 134
SSL_R_CHALLENGE_IS_DIFFERENT = 136
SSL_R_CIPHER_CODE_WRONG_LENGTH = 137
SSL_R_CIPHER_OR_HASH_UNAVAILABLE = 138
SSL_R_CIPHER_TABLE_SRC_ERROR = 139
SSL_R_CLIENTHELLO_TLSEXT = 226
SSL_R_COMPRESSED_LENGTH_TOO_LONG = 140
SSL_R_COMPRESSION_DISABLED = 343
SSL_R_COMPRESSION_FAILURE = 141
SSL_R_COMPRESSION_ID_NOT_WITHIN_PRIVATE_RANGE = 307
SSL_R_COMPRESSION_LIBRARY_ERROR = 142
SSL_R_CONNECTION_ID_IS_DIFFERENT = 143
SSL_R_CONNECTION_TYPE_NOT_SET = 144
SSL_R_COOKIE_MISMATCH = 308
SSL_R_DATA_BETWEEN_CCS_AND_FINISHED = 145
SSL_R_DATA_LENGTH_TOO_LONG = 146
SSL_R_DECRYPTION_FAILED = 147
SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC = 281
SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG = 148
SSL_R_DIGEST_CHECK_FAILED = 149
SSL_R_DTLS_MESSAGE_TOO_BIG = 334
SSL_R_DUPLICATE_COMPRESSION_ID = 309
SSL_R_ECC_CERT_NOT_FOR_KEY_AGREEMENT = 317
SSL_R_ECC_CERT_NOT_FOR_SIGNING = 318
SSL_R_ECC_CERT_SHOULD_HAVE_RSA_SIGNATURE = 322
SSL_R_ECC_CERT_SHOULD_HAVE_SHA1_SIGNATURE = 323
SSL_R_ECGROUP_TOO_LARGE_FOR_CIPHER = 310
SSL_R_EMPTY_SRTP_PROTECTION_PROFILE_LIST = 354
SSL_R_ENCRYPTED_LENGTH_TOO_LONG = 150
SSL_R_ERROR_GENERATING_TMP_RSA_KEY = 282
SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST = 151
SSL_R_EXCESSIVE_MESSAGE_SIZE = 152
SSL_R_EXTRA_DATA_IN_MESSAGE = 153
SSL_R_GOT_A_FIN_BEFORE_A_CCS = 154
SSL_R_GOT_NEXT_PROTO_BEFORE_A_CCS = 355
SSL_R_GOT_NEXT_PROTO_WITHOUT_EXTENSION = 356
SSL_R_HTTP_REQUEST = 156
SSL_R_HTTPS_PROXY_REQUEST = 155
SSL_R_ILLEGAL_PADDING = 283
SSL_R_INCONSISTENT_COMPRESSION = 340
SSL_R_INVALID_CHALLENGE_LENGTH = 158
SSL_R_INVALID_COMMAND = 280
SSL_R_INVALID_COMPRESSION_ALGORITHM = 341
SSL_R_INVALID_PURPOSE = 278
SSL_R_INVALID_SRP_USERNAME = 357
SSL_R_INVALID_STATUS_RESPONSE = 328
SSL_R_INVALID_TICKET_KEYS_LENGTH = 325
SSL_R_INVALID_TRUST = 279
SSL_R_KEY_ARG_TOO_LONG = 284
SSL_R_KRB5 = 285
SSL_R_KRB5_C_CC_PRINC = 286
SSL_R_KRB5_C_GET_CRED = 287
SSL_R_KRB5_C_INIT = 288
SSL_R_KRB5_C_MK_REQ = 289
SSL_R_KRB5_S_BAD_TICKET = 290
SSL_R_KRB5_S_INIT = 291
SSL_R_KRB5_S_RD_REQ = 292
SSL_R_KRB5_S_TKT_EXPIRED = 293
SSL_R_KRB5_S_TKT_NYV = 294
SSL_R_KRB5_S_TKT_SKEW = 295
SSL_R_LENGTH_MISMATCH = 159
SSL_R_LENGTH_TOO_SHORT = 160
SSL_R_LIBRARY_BUG = 274
SSL_R_LIBRARY_HAS_NO_CIPHERS = 161
SSL_R_MESSAGE_TOO_LONG = 296
SSL_R_MISSING_DH_DSA_CERT = 162
SSL_R_MISSING_DH_KEY = 163
SSL_R_MISSING_DH_RSA_CERT = 164
SSL_R_MISSING_DSA_SIGNING_CERT = 165
SSL_R_MISSING_EXPORT_TMP_DH_KEY = 166
SSL_R_MISSING_EXPORT_TMP_RSA_KEY = 167
SSL_R_MISSING_RSA_CERTIFICATE = 168
SSL_R_MISSING_RSA_ENCRYPTING_CERT = 169
SSL_R_MISSING_RSA_SIGNING_CERT = 170
SSL_R_MISSING_SRP_PARAM = 358
SSL_R_MISSING_TMP_DH_KEY = 171
SSL_R_MISSING_TMP_ECDH_KEY = 311
SSL_R_MISSING_TMP_RSA_KEY = 172
SSL_R_MISSING_TMP_RSA_PKEY = 173
SSL_R_MISSING_VERIFY_MESSAGE = 174
SSL_R_MULTIPLE_SGC_RESTARTS = 346
SSL_R_NO_CERTIFICATE_ASSIGNED = 177
SSL_R_NO_CERTIFICATE_RETURNED = 178
SSL_R_NO_CERTIFICATE_SET = 179
SSL_R_NO_CERTIFICATE_SPECIFIED = 180
SSL_R_NO_CERTIFICATES_RETURNED = 176
SSL_R_NO_CIPHER_LIST = 184
SSL_R_NO_CIPHER_MATCH = 185
SSL_R_NO_CIPHERS_AVAILABLE = 181
SSL_R_NO_CIPHERS_PASSED = 182
SSL_R_NO_CIPHERS_SPECIFIED = 183
SSL_R_NO_CLIENT_CERT_METHOD = 331
SSL_R_NO_CLIENT_CERT_RECEIVED = 186
SSL_R_NO_COMPRESSION_SPECIFIED = 187
SSL_R_NO_GOST_CERTIFICATE_SENT_BY_PEER = 330
SSL_R_NO_METHOD_SPECIFIED = 188
SSL_R_NO_PRIVATE_KEY_ASSIGNED = 190
SSL_R_NO_PRIVATEKEY = 189
SSL_R_NO_PROTOCOLS_AVAILABLE = 191
SSL_R_NO_PUBLICKEY = 192
SSL_R_NO_RENEGOTIATION = 339
SSL_R_NO_REQUIRED_DIGEST = 324
SSL_R_NO_SHARED_CIPHER = 193
SSL_R_NO_SRTP_PROFILES = 359
SSL_R_NO_VERIFY_CALLBACK = 194
SSL_R_NON_SSLV2_INITIAL_PACKET = 175
SSL_R_NULL_SSL_CTX = 195
SSL_R_NULL_SSL_METHOD_PASSED = 196
SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED = 197
SSL_R_OLD_SESSION_COMPRESSION_ALGORITHM_NOT_RETURNED = 344
SSL_R_ONLY_TLS_ALLOWED_IN_FIPS_MODE = 297
SSL_R_OPAQUE_PRF_INPUT_TOO_LONG = 327
SSL_R_PACKET_LENGTH_TOO_LONG = 198
SSL_R_PARSE_TLSEXT = 227
SSL_R_PATH_TOO_LONG = 270
SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE = 199
SSL_R_PEER_ERROR = 200
SSL_R_PEER_ERROR_CERTIFICATE = 201
SSL_R_PEER_ERROR_NO_CERTIFICATE = 202
SSL_R_PEER_ERROR_NO_CIPHER = 203
SSL_R_PEER_ERROR_UNSUPPORTED_CERTIFICATE_TYPE = 204
SSL_R_PRE_MAC_LENGTH_TOO_LONG = 205
SSL_R_PROBLEMS_MAPPING_CIPHER_FUNCTIONS = 206
SSL_R_PROTOCOL_IS_SHUTDOWN = 207
SSL_R_PSK_IDENTITY_NOT_FOUND = 223
SSL_R_PSK_NO_CLIENT_CB = 224
SSL_R_PSK_NO_SERVER_CB = 225
SSL_R_PUBLIC_KEY_ENCRYPT_ERROR = 208
SSL_R_PUBLIC_KEY_IS_NOT_RSA = 209
SSL_R_PUBLIC_KEY_NOT_RSA = 210
SSL_R_READ_BIO_NOT_SET = 211
SSL_R_READ_TIMEOUT_EXPIRED = 312
SSL_R_READ_WRONG_PACKET_TYPE = 212
SSL_R_RECORD_LENGTH_MISMATCH = 213
SSL_R_RECORD_TOO_LARGE = 214
SSL_R_RECORD_TOO_SMALL = 298
SSL_R_RENEGOTIATE_EXT_TOO_LONG = 335
SSL_R_RENEGOTIATION_ENCODING_ERR = 336
SSL_R_RENEGOTIATION_MISMATCH = 337
SSL_R_REQUIRED_CIPHER_MISSING = 215
SSL_R_REQUIRED_COMPRESSSION_ALGORITHM_MISSING = 342
SSL_R_REUSE_CERT_LENGTH_NOT_ZERO = 216
SSL_R_REUSE_CERT_TYPE_NOT_ZERO = 217
SSL_R_REUSE_CIPHER_LIST_NOT_ZERO = 218
SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING = 345
SSL_R_SERVERHELLO_TLSEXT = 275
SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED = 277
SSL_R_SHORT_READ = 219
SSL_R_SIGNATURE_ALGORITHMS_ERROR = 360
SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE = 220
SSL_R_SRP_A_CALC = 361
SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES = 362
SSL_R_SRTP_PROTECTION_PROFILE_LIST_TOO_LONG = 363
SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE = 364
SSL_R_SSL23_DOING_SESSION_ID_REUSE = 221
SSL_R_SSL2_CONNECTION_ID_TOO_LONG = 299
SSL_R_SSL3_EXT_INVALID_ECPOINTFORMAT = 321
SSL_R_SSL3_EXT_INVALID_SERVERNAME = 319
SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE = 320
SSL_R_SSL3_SESSION_ID_TOO_LONG = 300
SSL_R_SSL3_SESSION_ID_TOO_SHORT = 222
SSL_R_SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION = 228
SSL_R_SSL_HANDSHAKE_FAILURE = 229
SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS = 230
SSL_R_SSL_SESSION_ID_CALLBACK_FAILED = 301
SSL_R_SSL_SESSION_ID_CONFLICT = 302
SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG = 273
SSL_R_SSL_SESSION_ID_HAS_BAD_LENGTH = 303
SSL_R_SSL_SESSION_ID_IS_DIFFERENT = 231
SSL_R_SSLV3_ALERT_BAD_CERTIFICATE = 1042
SSL_R_SSLV3_ALERT_BAD_RECORD_MAC = 1020
SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED = 1045
SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED = 1044
SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN = 1046
SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE = 1030
SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE = 1040
SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER = 1047
SSL_R_SSLV3_ALERT_NO_CERTIFICATE = 1041
SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE = 1010
SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE = 1043
SSL_R_TLS_CLIENT_CERT_REQ_WITH_ANON_CIPHER = 232
SSL_R_TLS_HEARTBEAT_PEER_DOESNT_ACCEPT = 365
SSL_R_TLS_HEARTBEAT_PENDING = 366
SSL_R_TLS_ILLEGAL_EXPORTER_LABEL = 367
SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST = 157
SSL_R_TLS_PEER_DID_NOT_RESPOND_WITH_CERTIFICATE_LIST = 233
SSL_R_TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG = 234
SSL_R_TLSV1_ALERT_ACCESS_DENIED = 1049
SSL_R_TLSV1_ALERT_DECODE_ERROR = 1050
SSL_R_TLSV1_ALERT_DECRYPT_ERROR = 1051
SSL_R_TLSV1_ALERT_DECRYPTION_FAILED = 1021
SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION = 1060
SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY = 1071
SSL_R_TLSV1_ALERT_INTERNAL_ERROR = 1080
SSL_R_TLSV1_ALERT_NO_RENEGOTIATION = 1100
SSL_R_TLSV1_ALERT_PROTOCOL_VERSION = 1070
SSL_R_TLSV1_ALERT_RECORD_OVERFLOW = 1022
SSL_R_TLSV1_ALERT_UNKNOWN_CA = 1048
SSL_R_TLSV1_ALERT_USER_CANCELLED = 1090
SSL_R_TLSV1_BAD_CERTIFICATE_HASH_VALUE = 1114
SSL_R_TLSV1_BAD_CERTIFICATE_STATUS_RESPONSE = 1113
SSL_R_TLSV1_CERTIFICATE_UNOBTAINABLE = 1111
SSL_R_TLSV1_UNRECOGNIZED_NAME = 1112
SSL_R_TLSV1_UNSUPPORTED_EXTENSION = 1110
SSL_R_TRIED_TO_USE_UNSUPPORTED_CIPHER = 235
SSL_R_UNABLE_TO_DECODE_DH_CERTS = 236
SSL_R_UNABLE_TO_DECODE_ECDH_CERTS = 313
SSL_R_UNABLE_TO_EXTRACT_PUBLIC_KEY = 237
SSL_R_UNABLE_TO_FIND_DH_PARAMETERS = 238
SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS = 314
SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS = 239
SSL_R_UNABLE_TO_FIND_SSL_METHOD = 240
SSL_R_UNABLE_TO_LOAD_SSL2_MD5_ROUTINES = 241
SSL_R_UNABLE_TO_LOAD_SSL3_MD5_ROUTINES = 242
SSL_R_UNABLE_TO_LOAD_SSL3_SHA1_ROUTINES = 243
SSL_R_UNEXPECTED_MESSAGE = 244
SSL_R_UNEXPECTED_RECORD = 245
SSL_R_UNINITIALIZED = 276
SSL_R_UNKNOWN_ALERT_TYPE = 246
SSL_R_UNKNOWN_CERTIFICATE_TYPE = 247
SSL_R_UNKNOWN_CIPHER_RETURNED = 248
SSL_R_UNKNOWN_CIPHER_TYPE = 249
SSL_R_UNKNOWN_DIGEST = 368
SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE = 250
SSL_R_UNKNOWN_PKEY_TYPE = 251
SSL_R_UNKNOWN_PROTOCOL = 252
SSL_R_UNKNOWN_REMOTE_ERROR_TYPE = 253
SSL_R_UNKNOWN_SSL_VERSION = 254
SSL_R_UNKNOWN_STATE = 255
SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED = 338
SSL_R_UNSUPPORTED_CIPHER = 256
SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM = 257
SSL_R_UNSUPPORTED_DIGEST_TYPE = 326
SSL_R_UNSUPPORTED_ELLIPTIC_CURVE = 315
SSL_R_UNSUPPORTED_PROTOCOL = 258
SSL_R_UNSUPPORTED_SSL_VERSION = 259
SSL_R_UNSUPPORTED_STATUS_TYPE = 329
SSL_R_USE_SRTP_NOT_NEGOTIATED = 369
SSL_R_WRITE_BIO_NOT_SET = 260
SSL_R_WRONG_CIPHER_RETURNED = 261
SSL_R_WRONG_MESSAGE_TYPE = 262
SSL_R_WRONG_NUMBER_OF_KEY_BITS = 263
SSL_R_WRONG_SIGNATURE_LENGTH = 264
SSL_R_WRONG_SIGNATURE_SIZE = 265
SSL_R_WRONG_SIGNATURE_TYPE = 370
SSL_R_WRONG_SSL_VERSION = 266
SSL_R_WRONG_VERSION_NUMBER = 267
SSL_R_X509_LIB = 268
SSL_R_X509_VERIFICATION_SETUP_PROBLEMS = 269
SSL_READING = 3
SSL_RECEIVED_SHUTDOWN = 2
SSL_RT_MAX_CIPHER_BLOCK_SIZE = 16
SSL_SENT_SHUTDOWN = 1
SSL_SESS_CACHE_CLIENT = 0x0001
SSL_SESS_CACHE_NO_AUTO_CLEAR = 0x0080
SSL_SESS_CACHE_NO_INTERNAL_LOOKUP = 0x0100
SSL_SESS_CACHE_NO_INTERNAL_STORE = 0x0200
SSL_SESS_CACHE_OFF = 0x0000
SSL_SESS_CACHE_SERVER = 0x0002
SSL_SESSION_ASN1_VERSION = 0x0001
SSL_SESSION_CACHE_MAX_SIZE_DEFAULT = (1024*20)
SSL_ST_ACCEPT = 0x2000
SSL_ST_BEFORE = 0x4000
SSL_ST_CONNECT = 0x1000
SSL_ST_MASK = 0x0FFF
SSL_ST_OK = 0x03
SSL_ST_READ_BODY = 0xF1
SSL_ST_READ_DONE = 0xF2
SSL_ST_READ_HEADER = 0xF0
SSL_TLSEXT_ERR_ALERT_FATAL = 2
SSL_TLSEXT_ERR_ALERT_WARNING = 1
SSL_TLSEXT_ERR_NOACK = 3
SSL_TLSEXT_ERR_OK = 0
SSL_TLSEXT_HB_DONT_RECV_REQUESTS = 0x04
SSL_TLSEXT_HB_DONT_SEND_REQUESTS = 0x02
SSL_TLSEXT_HB_ENABLED = 0x01
SSL_TXT_3DES = "3DES"
SSL_TXT_aDH = "aDH"
SSL_TXT_ADH = "ADH"
SSL_TXT_aDSS = "aDSS"
SSL_TXT_aECDH = "aECDH"
SSL_TXT_AECDH = "AECDH"
SSL_TXT_aECDSA = "aECDSA"
SSL_TXT_AES = "AES"
SSL_TXT_AES128 = "AES128"
SSL_TXT_AES256 = "AES256"
SSL_TXT_AES_GCM = "AESGCM"
SSL_TXT_aFZA = "aFZA"
SSL_TXT_aGOST = "aGOST"
SSL_TXT_aGOST01 = "aGOST01"
SSL_TXT_aGOST94 = "aGOST94"
SSL_TXT_aKRB5 = "aKRB5"
SSL_TXT_ALL = "ALL"
SSL_TXT_aNULL = "aNULL"
SSL_TXT_aPSK = "aPSK"
SSL_TXT_aRSA = "aRSA"
SSL_TXT_CAMELLIA = "CAMELLIA"
SSL_TXT_CAMELLIA128 = "CAMELLIA128"
SSL_TXT_CAMELLIA256 = "CAMELLIA256"
SSL_TXT_CMPALL = "COMPLEMENTOFALL"
SSL_TXT_CMPDEF = "COMPLEMENTOFDEFAULT"
SSL_TXT_DES = "DES"
SSL_TXT_DES_192_EDE3_CBC_WITH_MD5 = SSL2_TXT_DES_192_EDE3_CBC_WITH_MD5
SSL_TXT_DES_192_EDE3_CBC_WITH_SHA = SSL2_TXT_DES_192_EDE3_CBC_WITH_SHA
SSL_TXT_DES_64_CBC_WITH_MD5 = SSL2_TXT_DES_64_CBC_WITH_MD5
SSL_TXT_DES_64_CBC_WITH_SHA = SSL2_TXT_DES_64_CBC_WITH_SHA
SSL_TXT_DH = "DH"
SSL_TXT_DSS = "DSS"
SSL_TXT_ECDH = "ECDH"
SSL_TXT_ECDSA = "ECDSA"
SSL_TXT_EDH = "EDH"
SSL_TXT_EECDH = "EECDH"
SSL_TXT_eFZA = "eFZA"
SSL_TXT_eNULL = "eNULL"
SSL_TXT_EXP = "EXP"
SSL_TXT_EXP40 = "EXPORT40"
SSL_TXT_EXP56 = "EXPORT56"
SSL_TXT_EXPORT = "EXPORT"
SSL_TXT_FIPS = "FIPS"
SSL_TXT_FZA = "FZA"
SSL_TXT_GOST89MAC = "GOST89MAC"
SSL_TXT_GOST94 = "GOST94"
SSL_TXT_HIGH = "HIGH"
SSL_TXT_IDEA = "IDEA"
SSL_TXT_IDEA_128_CBC_WITH_MD5 = SSL2_TXT_IDEA_128_CBC_WITH_MD5
SSL_TXT_kDH = "kDH"
SSL_TXT_kDHd = "kDHd"
SSL_TXT_kDHr = "kDHr"
SSL_TXT_kECDH = "kECDH"
SSL_TXT_kECDHe = "kECDHe"
SSL_TXT_kECDHr = "kECDHr"
SSL_TXT_kEDH = "kEDH"
SSL_TXT_kEECDH = "kEECDH"
SSL_TXT_kFZA = "kFZA"
SSL_TXT_kGOST = "kGOST"
SSL_TXT_kKRB5 = "kKRB5"
SSL_TXT_kPSK = "kPSK"
SSL_TXT_KRB5 = "KRB5"
SSL_TXT_KRB5_DES_192_CBC3_MD5 = SSL3_TXT_KRB5_DES_192_CBC3_MD5
SSL_TXT_KRB5_DES_192_CBC3_SHA = SSL3_TXT_KRB5_DES_192_CBC3_SHA
SSL_TXT_KRB5_DES_40_CBC_MD5 = SSL3_TXT_KRB5_DES_40_CBC_MD5
SSL_TXT_KRB5_DES_40_CBC_SHA = SSL3_TXT_KRB5_DES_40_CBC_SHA
SSL_TXT_KRB5_DES_64_CBC_MD5 = SSL3_TXT_KRB5_DES_64_CBC_MD5
SSL_TXT_KRB5_DES_64_CBC_SHA = SSL3_TXT_KRB5_DES_64_CBC_SHA
SSL_TXT_KRB5_IDEA_128_CBC_MD5 = SSL3_TXT_KRB5_IDEA_128_CBC_MD5
SSL_TXT_KRB5_IDEA_128_CBC_SHA = SSL3_TXT_KRB5_IDEA_128_CBC_SHA
SSL_TXT_KRB5_RC2_40_CBC_MD5 = SSL3_TXT_KRB5_RC2_40_CBC_MD5
SSL_TXT_KRB5_RC2_40_CBC_SHA = SSL3_TXT_KRB5_RC2_40_CBC_SHA
SSL_TXT_KRB5_RC4_128_MD5 = SSL3_TXT_KRB5_RC4_128_MD5
SSL_TXT_KRB5_RC4_128_SHA = SSL3_TXT_KRB5_RC4_128_SHA
SSL_TXT_KRB5_RC4_40_MD5 = SSL3_TXT_KRB5_RC4_40_MD5
SSL_TXT_KRB5_RC4_40_SHA = SSL3_TXT_KRB5_RC4_40_SHA
SSL_TXT_kRSA = "kRSA"
SSL_TXT_kSRP = "kSRP"
SSL_TXT_LOW = "LOW"
SSL_TXT_MD5 = "MD5"
SSL_TXT_MEDIUM = "MEDIUM"
SSL_TXT_NULL = "NULL"
SSL_TXT_NULL_WITH_MD5 = SSL2_TXT_NULL_WITH_MD5
SSL_TXT_PSK = "PSK"
SSL_TXT_RC2 = "RC2"
SSL_TXT_RC2_128_CBC_EXPORT40_WITH_MD5 = SSL2_TXT_RC2_128_CBC_EXPORT40_WITH_MD5
SSL_TXT_RC2_128_CBC_WITH_MD5 = SSL2_TXT_RC2_128_CBC_WITH_MD5
SSL_TXT_RC4 = "RC4"
SSL_TXT_RC4_128_EXPORT40_WITH_MD5 = SSL2_TXT_RC4_128_EXPORT40_WITH_MD5
SSL_TXT_RC4_128_WITH_MD5 = SSL2_TXT_RC4_128_WITH_MD5
SSL_TXT_RSA = "RSA"
SSL_TXT_SEED = "SEED"
SSL_TXT_SHA = "SHA"
SSL_TXT_SHA1 = "SHA1"
SSL_TXT_SHA256 = "SHA256"
SSL_TXT_SHA384 = "SHA384"
SSL_TXT_SRP = "SRP"
SSL_TXT_SSLV2 = "SSLv2"
SSL_TXT_SSLV3 = "SSLv3"
SSL_TXT_TLSV1 = "TLSv1"
SSL_TXT_TLSV1_1 = "TLSv1.1"
SSL_TXT_TLSV1_2 = "TLSv1.2"
SSL_VERIFY_CLIENT_ONCE = 0x04
SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02
SSL_VERIFY_NONE = 0x00
SSL_VERIFY_PEER = 0x01
SSL_WRITING = 2
SSL_X509_LOOKUP = 4
SSLEAY_BUILT_ON = 3
SSLEAY_CFLAGS = 2
SSLEAY_DIR = 5
SSLEAY_PLATFORM = 4
SSLEAY_VERSION = 0
SSLEAY_VERSION_NUMBER = OPENSSL_VERSION_NUMBER
STABLE_FLAGS_MALLOC = 0x01
STABLE_NO_MASK = 0x02
TIMER_ABSTIME = 1
TLS1_1_VERSION = 0x0302
TLS1_1_VERSION_MAJOR = 0x03
TLS1_1_VERSION_MINOR = 0x02
TLS1_2_VERSION = 0x0303
TLS1_2_VERSION_MAJOR = 0x03
TLS1_2_VERSION_MINOR = 0x03
TLS1_AD_ACCESS_DENIED = 49
TLS1_AD_BAD_CERTIFICATE_HASH_VALUE = 114
TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE = 113
TLS1_AD_CERTIFICATE_UNOBTAINABLE = 111
TLS1_AD_DECODE_ERROR = 50
TLS1_AD_DECRYPT_ERROR = 51
TLS1_AD_DECRYPTION_FAILED = 21
TLS1_AD_EXPORT_RESTRICTION = 60
TLS1_AD_INSUFFICIENT_SECURITY = 71
TLS1_AD_INTERNAL_ERROR = 80
TLS1_AD_NO_RENEGOTIATION = 100
TLS1_AD_PROTOCOL_VERSION = 70
TLS1_AD_RECORD_OVERFLOW = 22
TLS1_AD_UNKNOWN_CA = 48
TLS1_AD_UNKNOWN_PSK_IDENTITY = 115
TLS1_AD_UNRECOGNIZED_NAME = 112
TLS1_AD_UNSUPPORTED_EXTENSION = 110
TLS1_AD_USER_CANCELLED = 90
TLS1_ALLOW_EXPERIMENTAL_CIPHERSUITES = 0
TLS1_CK_ADH_WITH_AES_128_GCM_SHA256 = 0x030000A6
TLS1_CK_ADH_WITH_AES_128_SHA = 0x03000034
TLS1_CK_ADH_WITH_AES_128_SHA256 = 0x0300006C
TLS1_CK_ADH_WITH_AES_256_GCM_SHA384 = 0x030000A7
TLS1_CK_ADH_WITH_AES_256_SHA = 0x0300003A
TLS1_CK_ADH_WITH_AES_256_SHA256 = 0x0300006D
TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA = 0x03000046
TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA = 0x03000089
TLS1_CK_ADH_WITH_SEED_SHA = 0x0300009B
TLS1_CK_DH_DSS_WITH_AES_128_GCM_SHA256 = 0x030000A4
TLS1_CK_DH_DSS_WITH_AES_128_SHA = 0x03000030
TLS1_CK_DH_DSS_WITH_AES_128_SHA256 = 0x0300003E
TLS1_CK_DH_DSS_WITH_AES_256_GCM_SHA384 = 0x030000A5
TLS1_CK_DH_DSS_WITH_AES_256_SHA = 0x03000036
TLS1_CK_DH_DSS_WITH_AES_256_SHA256 = 0x03000068
TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x03000042
TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x03000085
TLS1_CK_DH_DSS_WITH_SEED_SHA = 0x03000097
TLS1_CK_DH_RSA_WITH_AES_128_GCM_SHA256 = 0x030000A0
TLS1_CK_DH_RSA_WITH_AES_128_SHA = 0x03000031
TLS1_CK_DH_RSA_WITH_AES_128_SHA256 = 0x0300003F
TLS1_CK_DH_RSA_WITH_AES_256_GCM_SHA384 = 0x030000A1
TLS1_CK_DH_RSA_WITH_AES_256_SHA = 0x03000037
TLS1_CK_DH_RSA_WITH_AES_256_SHA256 = 0x03000069
TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x03000043
TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x03000086
TLS1_CK_DH_RSA_WITH_SEED_SHA = 0x03000098
TLS1_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA = 0x03000063
TLS1_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA = 0x03000065
TLS1_CK_DHE_DSS_WITH_AES_128_GCM_SHA256 = 0x030000A2
TLS1_CK_DHE_DSS_WITH_AES_128_SHA = 0x03000032
TLS1_CK_DHE_DSS_WITH_AES_128_SHA256 = 0x03000040
TLS1_CK_DHE_DSS_WITH_AES_256_GCM_SHA384 = 0x030000A3
TLS1_CK_DHE_DSS_WITH_AES_256_SHA = 0x03000038
TLS1_CK_DHE_DSS_WITH_AES_256_SHA256 = 0x0300006A
TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x03000044
TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x03000087
TLS1_CK_DHE_DSS_WITH_RC4_128_SHA = 0x03000066
TLS1_CK_DHE_DSS_WITH_SEED_SHA = 0x03000099
TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x0300009E
TLS1_CK_DHE_RSA_WITH_AES_128_SHA = 0x03000033
TLS1_CK_DHE_RSA_WITH_AES_128_SHA256 = 0x03000067
TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x0300009F
TLS1_CK_DHE_RSA_WITH_AES_256_SHA = 0x03000039
TLS1_CK_DHE_RSA_WITH_AES_256_SHA256 = 0x0300006B
TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x03000045
TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x03000088
TLS1_CK_DHE_RSA_WITH_SEED_SHA = 0x0300009A
TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA = 0x0300C018
TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA = 0x0300C019
TLS1_CK_ECDH_anon_WITH_DES_192_CBC3_SHA = 0x0300C017
TLS1_CK_ECDH_anon_WITH_NULL_SHA = 0x0300C015
TLS1_CK_ECDH_anon_WITH_RC4_128_SHA = 0x0300C016
TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 0x0300C004
TLS1_CK_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = 0x0300C02D
TLS1_CK_ECDH_ECDSA_WITH_AES_128_SHA256 = 0x0300C025
TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0x0300C005
TLS1_CK_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = 0x0300C02E
TLS1_CK_ECDH_ECDSA_WITH_AES_256_SHA384 = 0x0300C026
TLS1_CK_ECDH_ECDSA_WITH_DES_192_CBC3_SHA = 0x0300C003
TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA = 0x0300C001
TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA = 0x0300C002
TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA = 0x0300C00E
TLS1_CK_ECDH_RSA_WITH_AES_128_GCM_SHA256 = 0x0300C031
TLS1_CK_ECDH_RSA_WITH_AES_128_SHA256 = 0x0300C029
TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA = 0x0300C00F
TLS1_CK_ECDH_RSA_WITH_AES_256_GCM_SHA384 = 0x0300C032
TLS1_CK_ECDH_RSA_WITH_AES_256_SHA384 = 0x0300C02A
TLS1_CK_ECDH_RSA_WITH_DES_192_CBC3_SHA = 0x0300C00D
TLS1_CK_ECDH_RSA_WITH_NULL_SHA = 0x0300C00B
TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA = 0x0300C00C
TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0x0300C009
TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0x0300C02B
TLS1_CK_ECDHE_ECDSA_WITH_AES_128_SHA256 = 0x0300C023
TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0x0300C00A
TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0x0300C02C
TLS1_CK_ECDHE_ECDSA_WITH_AES_256_SHA384 = 0x0300C024
TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA = 0x0300C008
TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA = 0x0300C006
TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA = 0x0300C007
TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0x0300C013
TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0x0300C02F
TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256 = 0x0300C027
TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0x0300C014
TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0x0300C030
TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384 = 0x0300C028
TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA = 0x0300C012
TLS1_CK_ECDHE_RSA_WITH_NULL_SHA = 0x0300C010
TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA = 0x0300C011
TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA = 0x0300008B
TLS1_CK_PSK_WITH_AES_128_CBC_SHA = 0x0300008C
TLS1_CK_PSK_WITH_AES_256_CBC_SHA = 0x0300008D
TLS1_CK_PSK_WITH_RC4_128_SHA = 0x0300008A
TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA = 0x03000062
TLS1_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 = 0x03000061
TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5 = 0x03000060
TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA = 0x03000064
TLS1_CK_RSA_WITH_AES_128_GCM_SHA256 = 0x0300009C
TLS1_CK_RSA_WITH_AES_128_SHA = 0x0300002F
TLS1_CK_RSA_WITH_AES_128_SHA256 = 0x0300003C
TLS1_CK_RSA_WITH_AES_256_GCM_SHA384 = 0x0300009D
TLS1_CK_RSA_WITH_AES_256_SHA = 0x03000035
TLS1_CK_RSA_WITH_AES_256_SHA256 = 0x0300003D
TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x03000041
TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x03000084
TLS1_CK_RSA_WITH_NULL_SHA256 = 0x0300003B
TLS1_CK_RSA_WITH_SEED_SHA = 0x03000096
TLS1_CK_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = 0x0300C01C
TLS1_CK_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = 0x0300C01F
TLS1_CK_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = 0x0300C022
TLS1_CK_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = 0x0300C01B
TLS1_CK_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = 0x0300C01E
TLS1_CK_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 0x0300C021
TLS1_CK_SRP_SHA_WITH_3DES_EDE_CBC_SHA = 0x0300C01A
TLS1_CK_SRP_SHA_WITH_AES_128_CBC_SHA = 0x0300C01D
TLS1_CK_SRP_SHA_WITH_AES_256_CBC_SHA = 0x0300C020
TLS1_FINISH_MAC_LENGTH = 12
TLS1_FLAGS_KEEP_HANDSHAKE = 0x0020
TLS1_FLAGS_SKIP_CERT_VERIFY = 0x0010
TLS1_FLAGS_TLS_PADDING_BUG = 0x0008
TLS1_HB_REQUEST = 1
TLS1_HB_RESPONSE = 2
TLS1_RT_HEARTBEAT = 24
TLS1_TXT_ADH_WITH_AES_128_GCM_SHA256 = "ADH-AES128-GCM-SHA256"
TLS1_TXT_ADH_WITH_AES_128_SHA = "ADH-AES128-SHA"
TLS1_TXT_ADH_WITH_AES_128_SHA256 = "ADH-AES128-SHA256"
TLS1_TXT_ADH_WITH_AES_256_GCM_SHA384 = "ADH-AES256-GCM-SHA384"
TLS1_TXT_ADH_WITH_AES_256_SHA = "ADH-AES256-SHA"
TLS1_TXT_ADH_WITH_AES_256_SHA256 = "ADH-AES256-SHA256"
TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA = "ADH-CAMELLIA128-SHA"
TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA = "ADH-CAMELLIA256-SHA"
TLS1_TXT_ADH_WITH_SEED_SHA = "ADH-SEED-SHA"
TLS1_TXT_DH_DSS_WITH_AES_128_GCM_SHA256 = "DH-DSS-AES128-GCM-SHA256"
TLS1_TXT_DH_DSS_WITH_AES_128_SHA = "DH-DSS-AES128-SHA"
TLS1_TXT_DH_DSS_WITH_AES_128_SHA256 = "DH-DSS-AES128-SHA256"
TLS1_TXT_DH_DSS_WITH_AES_256_GCM_SHA384 = "DH-DSS-AES256-GCM-SHA384"
TLS1_TXT_DH_DSS_WITH_AES_256_SHA = "DH-DSS-AES256-SHA"
TLS1_TXT_DH_DSS_WITH_AES_256_SHA256 = "DH-DSS-AES256-SHA256"
TLS1_TXT_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = "DH-DSS-CAMELLIA128-SHA"
TLS1_TXT_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = "DH-DSS-CAMELLIA256-SHA"
TLS1_TXT_DH_DSS_WITH_SEED_SHA = "DH-DSS-SEED-SHA"
TLS1_TXT_DH_RSA_WITH_AES_128_GCM_SHA256 = "DH-RSA-AES128-GCM-SHA256"
TLS1_TXT_DH_RSA_WITH_AES_128_SHA = "DH-RSA-AES128-SHA"
TLS1_TXT_DH_RSA_WITH_AES_128_SHA256 = "DH-RSA-AES128-SHA256"
TLS1_TXT_DH_RSA_WITH_AES_256_GCM_SHA384 = "DH-RSA-AES256-GCM-SHA384"
TLS1_TXT_DH_RSA_WITH_AES_256_SHA = "DH-RSA-AES256-SHA"
TLS1_TXT_DH_RSA_WITH_AES_256_SHA256 = "DH-RSA-AES256-SHA256"
TLS1_TXT_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = "DH-RSA-CAMELLIA128-SHA"
TLS1_TXT_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = "DH-RSA-CAMELLIA256-SHA"
TLS1_TXT_DH_RSA_WITH_SEED_SHA = "DH-RSA-SEED-SHA"
TLS1_TXT_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA = "EXP1024-DHE-DSS-DES-CBC-SHA"
TLS1_TXT_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA = "EXP1024-DHE-DSS-RC4-SHA"
TLS1_TXT_DHE_DSS_WITH_AES_128_GCM_SHA256 = "DHE-DSS-AES128-GCM-SHA256"
TLS1_TXT_DHE_DSS_WITH_AES_128_SHA = "DHE-DSS-AES128-SHA"
TLS1_TXT_DHE_DSS_WITH_AES_128_SHA256 = "DHE-DSS-AES128-SHA256"
TLS1_TXT_DHE_DSS_WITH_AES_256_GCM_SHA384 = "DHE-DSS-AES256-GCM-SHA384"
TLS1_TXT_DHE_DSS_WITH_AES_256_SHA = "DHE-DSS-AES256-SHA"
TLS1_TXT_DHE_DSS_WITH_AES_256_SHA256 = "DHE-DSS-AES256-SHA256"
TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = "DHE-DSS-CAMELLIA128-SHA"
TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = "DHE-DSS-CAMELLIA256-SHA"
TLS1_TXT_DHE_DSS_WITH_RC4_128_SHA = "DHE-DSS-RC4-SHA"
TLS1_TXT_DHE_DSS_WITH_SEED_SHA = "DHE-DSS-SEED-SHA"
TLS1_TXT_DHE_RSA_WITH_AES_128_GCM_SHA256 = "DHE-RSA-AES128-GCM-SHA256"
TLS1_TXT_DHE_RSA_WITH_AES_128_SHA = "DHE-RSA-AES128-SHA"
TLS1_TXT_DHE_RSA_WITH_AES_128_SHA256 = "DHE-RSA-AES128-SHA256"
TLS1_TXT_DHE_RSA_WITH_AES_256_GCM_SHA384 = "DHE-RSA-AES256-GCM-SHA384"
TLS1_TXT_DHE_RSA_WITH_AES_256_SHA = "DHE-RSA-AES256-SHA"
TLS1_TXT_DHE_RSA_WITH_AES_256_SHA256 = "DHE-RSA-AES256-SHA256"
TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = "DHE-RSA-CAMELLIA128-SHA"
TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = "DHE-RSA-CAMELLIA256-SHA"
TLS1_TXT_DHE_RSA_WITH_SEED_SHA = "DHE-RSA-SEED-SHA"
TLS1_TXT_ECDH_anon_WITH_AES_128_CBC_SHA = "AECDH-AES128-SHA"
TLS1_TXT_ECDH_anon_WITH_AES_256_CBC_SHA = "AECDH-AES256-SHA"
TLS1_TXT_ECDH_anon_WITH_DES_192_CBC3_SHA = "AECDH-DES-CBC3-SHA"
TLS1_TXT_ECDH_anon_WITH_NULL_SHA = "AECDH-NULL-SHA"
TLS1_TXT_ECDH_anon_WITH_RC4_128_SHA = "AECDH-RC4-SHA"
TLS1_TXT_ECDH_ECDSA_WITH_AES_128_CBC_SHA = "ECDH-ECDSA-AES128-SHA"
TLS1_TXT_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = "ECDH-ECDSA-AES128-GCM-SHA256"
TLS1_TXT_ECDH_ECDSA_WITH_AES_128_SHA256 = "ECDH-ECDSA-AES128-SHA256"
TLS1_TXT_ECDH_ECDSA_WITH_AES_256_CBC_SHA = "ECDH-ECDSA-AES256-SHA"
TLS1_TXT_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = "ECDH-ECDSA-AES256-GCM-SHA384"
TLS1_TXT_ECDH_ECDSA_WITH_AES_256_SHA384 = "ECDH-ECDSA-AES256-SHA384"
TLS1_TXT_ECDH_ECDSA_WITH_DES_192_CBC3_SHA = "ECDH-ECDSA-DES-CBC3-SHA"
TLS1_TXT_ECDH_ECDSA_WITH_NULL_SHA = "ECDH-ECDSA-NULL-SHA"
TLS1_TXT_ECDH_ECDSA_WITH_RC4_128_SHA = "ECDH-ECDSA-RC4-SHA"
TLS1_TXT_ECDH_RSA_WITH_AES_128_CBC_SHA = "ECDH-RSA-AES128-SHA"
TLS1_TXT_ECDH_RSA_WITH_AES_128_GCM_SHA256 = "ECDH-RSA-AES128-GCM-SHA256"
TLS1_TXT_ECDH_RSA_WITH_AES_128_SHA256 = "ECDH-RSA-AES128-SHA256"
TLS1_TXT_ECDH_RSA_WITH_AES_256_CBC_SHA = "ECDH-RSA-AES256-SHA"
TLS1_TXT_ECDH_RSA_WITH_AES_256_GCM_SHA384 = "ECDH-RSA-AES256-GCM-SHA384"
TLS1_TXT_ECDH_RSA_WITH_AES_256_SHA384 = "ECDH-RSA-AES256-SHA384"
TLS1_TXT_ECDH_RSA_WITH_DES_192_CBC3_SHA = "ECDH-RSA-DES-CBC3-SHA"
TLS1_TXT_ECDH_RSA_WITH_NULL_SHA = "ECDH-RSA-NULL-SHA"
TLS1_TXT_ECDH_RSA_WITH_RC4_128_SHA = "ECDH-RSA-RC4-SHA"
TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = "ECDHE-ECDSA-AES128-SHA"
TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = "ECDHE-ECDSA-AES128-GCM-SHA256"
TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_SHA256 = "ECDHE-ECDSA-AES128-SHA256"
TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = "ECDHE-ECDSA-AES256-SHA"
TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = "ECDHE-ECDSA-AES256-GCM-SHA384"
TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_SHA384 = "ECDHE-ECDSA-AES256-SHA384"
TLS1_TXT_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA = "ECDHE-ECDSA-DES-CBC3-SHA"
TLS1_TXT_ECDHE_ECDSA_WITH_NULL_SHA = "ECDHE-ECDSA-NULL-SHA"
TLS1_TXT_ECDHE_ECDSA_WITH_RC4_128_SHA = "ECDHE-ECDSA-RC4-SHA"
TLS1_TXT_ECDHE_RSA_WITH_AES_128_CBC_SHA = "ECDHE-RSA-AES128-SHA"
TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = "ECDHE-RSA-AES128-GCM-SHA256"
TLS1_TXT_ECDHE_RSA_WITH_AES_128_SHA256 = "ECDHE-RSA-AES128-SHA256"
TLS1_TXT_ECDHE_RSA_WITH_AES_256_CBC_SHA = "ECDHE-RSA-AES256-SHA"
TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = "ECDHE-RSA-AES256-GCM-SHA384"
TLS1_TXT_ECDHE_RSA_WITH_AES_256_SHA384 = "ECDHE-RSA-AES256-SHA384"
TLS1_TXT_ECDHE_RSA_WITH_DES_192_CBC3_SHA = "ECDHE-RSA-DES-CBC3-SHA"
TLS1_TXT_ECDHE_RSA_WITH_NULL_SHA = "ECDHE-RSA-NULL-SHA"
TLS1_TXT_ECDHE_RSA_WITH_RC4_128_SHA = "ECDHE-RSA-RC4-SHA"
TLS1_TXT_PSK_WITH_3DES_EDE_CBC_SHA = "PSK-3DES-EDE-CBC-SHA"
TLS1_TXT_PSK_WITH_AES_128_CBC_SHA = "PSK-AES128-CBC-SHA"
TLS1_TXT_PSK_WITH_AES_256_CBC_SHA = "PSK-AES256-CBC-SHA"
TLS1_TXT_PSK_WITH_RC4_128_SHA = "PSK-RC4-SHA"
TLS1_TXT_RSA_EXPORT1024_WITH_DES_CBC_SHA = "EXP1024-DES-CBC-SHA"
TLS1_TXT_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 = "EXP1024-RC2-CBC-MD5"
TLS1_TXT_RSA_EXPORT1024_WITH_RC4_56_MD5 = "EXP1024-RC4-MD5"
TLS1_TXT_RSA_EXPORT1024_WITH_RC4_56_SHA = "EXP1024-RC4-SHA"
TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256 = "AES128-GCM-SHA256"
TLS1_TXT_RSA_WITH_AES_128_SHA = "AES128-SHA"
TLS1_TXT_RSA_WITH_AES_128_SHA256 = "AES128-SHA256"
TLS1_TXT_RSA_WITH_AES_256_GCM_SHA384 = "AES256-GCM-SHA384"
TLS1_TXT_RSA_WITH_AES_256_SHA = "AES256-SHA"
TLS1_TXT_RSA_WITH_AES_256_SHA256 = "AES256-SHA256"
TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA = "CAMELLIA128-SHA"
TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA = "CAMELLIA256-SHA"
TLS1_TXT_RSA_WITH_NULL_SHA256 = "NULL-SHA256"
TLS1_TXT_RSA_WITH_SEED_SHA = "SEED-SHA"
TLS1_TXT_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = "SRP-DSS-3DES-EDE-CBC-SHA"
TLS1_TXT_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = "SRP-DSS-AES-128-CBC-SHA"
TLS1_TXT_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = "SRP-DSS-AES-256-CBC-SHA"
TLS1_TXT_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = "SRP-RSA-3DES-EDE-CBC-SHA"
TLS1_TXT_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = "SRP-RSA-AES-128-CBC-SHA"
TLS1_TXT_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = "SRP-RSA-AES-256-CBC-SHA"
TLS1_TXT_SRP_SHA_WITH_3DES_EDE_CBC_SHA = "SRP-3DES-EDE-CBC-SHA"
TLS1_TXT_SRP_SHA_WITH_AES_128_CBC_SHA = "SRP-AES-128-CBC-SHA"
TLS1_TXT_SRP_SHA_WITH_AES_256_CBC_SHA = "SRP-AES-256-CBC-SHA"
TLS1_VERSION = 0x0301
TLS1_VERSION_MAJOR = 0x03
TLS1_VERSION_MINOR = 0x01
TLS_CT_DSS_FIXED_DH = 4
TLS_CT_DSS_SIGN = 2
TLS_CT_ECDSA_FIXED_ECDH = 66
TLS_CT_ECDSA_SIGN = 64
TLS_CT_GOST01_SIGN = 22
TLS_CT_GOST94_SIGN = 21
TLS_CT_NUMBER = 9
TLS_CT_RSA_FIXED_DH = 3
TLS_CT_RSA_FIXED_ECDH = 65
TLS_CT_RSA_SIGN = 1
TLS_MD_CLIENT_FINISH_CONST = "client finished"
TLS_MD_CLIENT_FINISH_CONST_SIZE = 15
TLS_MD_CLIENT_WRITE_KEY_CONST = "client write key"
TLS_MD_CLIENT_WRITE_KEY_CONST_SIZE = 16
TLS_MD_IV_BLOCK_CONST = "IV block"
TLS_MD_IV_BLOCK_CONST_SIZE = 8
TLS_MD_KEY_EXPANSION_CONST = "key expansion"
TLS_MD_KEY_EXPANSION_CONST_SIZE = 13
TLS_MD_MASTER_SECRET_CONST = "master secret"
TLS_MD_MASTER_SECRET_CONST_SIZE = 13
TLS_MD_MAX_CONST_SIZE = 20
TLS_MD_SERVER_FINISH_CONST = "server finished"
TLS_MD_SERVER_FINISH_CONST_SIZE = 15
TLS_MD_SERVER_WRITE_KEY_CONST = "server write key"
TLS_MD_SERVER_WRITE_KEY_CONST_SIZE = 16
TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2 = 2
TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime = 1
TLSEXT_ECPOINTFORMAT_first = 0
TLSEXT_ECPOINTFORMAT_last = 2
TLSEXT_ECPOINTFORMAT_uncompressed = 0
TLSEXT_hash_md5 = 1
TLSEXT_hash_none = 0
TLSEXT_hash_sha1 = 2
TLSEXT_hash_sha224 = 3
TLSEXT_hash_sha256 = 4
TLSEXT_hash_sha384 = 5
TLSEXT_hash_sha512 = 6
TLSEXT_MAXLEN_host_name = 255
TLSEXT_NAMETYPE_host_name = 0
TLSEXT_signature_anonymous = 0
TLSEXT_signature_dsa = 2
TLSEXT_signature_ecdsa = 3
TLSEXT_signature_rsa = 1
TLSEXT_STATUSTYPE_ocsp = 1
TLSEXT_TYPE_cert_type = 9
TLSEXT_TYPE_client_authz = 7
TLSEXT_TYPE_client_certificate_url = 2
TLSEXT_TYPE_ec_point_formats = 11
TLSEXT_TYPE_elliptic_curves = 10
TLSEXT_TYPE_heartbeat = 15
TLSEXT_TYPE_max_fragment_length = 1
TLSEXT_TYPE_next_proto_neg = 13172
TLSEXT_TYPE_renegotiate = 0xff01
TLSEXT_TYPE_server_authz = 8
TLSEXT_TYPE_server_name = 0
TLSEXT_TYPE_session_ticket = 35
TLSEXT_TYPE_signature_algorithms = 13
TLSEXT_TYPE_srp = 12
TLSEXT_TYPE_status_request = 5
TLSEXT_TYPE_truncated_hmac = 4
TLSEXT_TYPE_trusted_ca_keys = 3
TLSEXT_TYPE_use_srtp = 14
TLSEXT_TYPE_user_mapping = 6
TMP_MAX = 238328
ub_common_name = 64
ub_email_address = 128
ub_locality_name = 128
ub_name = 32768
ub_organization_name = 64
ub_organization_unit_name = 64
ub_state_name = 128
ub_title = 64
V_ASN1_APP_CHOOSE = -2
V_ASN1_APPLICATION = 0x40
V_ASN1_BIT_STRING = 3
V_ASN1_BMPSTRING = 30
V_ASN1_BOOLEAN = 1
V_ASN1_CONSTRUCTED = 0x20
V_ASN1_CONTEXT_SPECIFIC = 0x80
V_ASN1_ENUMERATED = 10
V_ASN1_EOC = 0
V_ASN1_EXTERNAL = 8
V_ASN1_GENERALIZEDTIME = 24
V_ASN1_GENERALSTRING = 27
V_ASN1_GRAPHICSTRING = 25
V_ASN1_IA5STRING = 22
V_ASN1_INTEGER = 2
V_ASN1_ISO64STRING = 26
V_ASN1_NEG = 0x100
V_ASN1_NULL = 5
V_ASN1_NUMERICSTRING = 18
V_ASN1_OBJECT = 6
V_ASN1_OBJECT_DESCRIPTOR = 7
V_ASN1_OCTET_STRING = 4
V_ASN1_OTHER = -3
V_ASN1_PRIMATIVE_TAG = 0x1f
V_ASN1_PRIMITIVE_TAG = 0x1f
V_ASN1_PRINTABLESTRING = 19
V_ASN1_PRIVATE = 0xc0
V_ASN1_REAL = 9
V_ASN1_SEQUENCE = 16
V_ASN1_SET = 17
V_ASN1_T61STRING = 20
V_ASN1_TELETEXSTRING = 20
V_ASN1_UNDEF = -1
V_ASN1_UNIVERSAL = 0x00
V_ASN1_UNIVERSALSTRING = 28
V_ASN1_UTCTIME = 23
V_ASN1_UTF8STRING = 12
V_ASN1_VIDEOTEXSTRING = 21
V_ASN1_VISIBLESTRING = 26
V_CRYPTO_MDEBUG_THREAD = 0x2
V_CRYPTO_MDEBUG_TIME = 0x1
WCONTINUED = 8
WEXITED = 4
WNOHANG = 1
WNOWAIT = 0x01000000
WSTOPPED = 2
WUNTRACED = 2
XN_FLAG_COMPAT = 0
XN_FLAG_DN_REV = (bit.lshift(1,20))
XN_FLAG_DUMP_UNKNOWN_FIELDS = (bit.lshift(1,24))
XN_FLAG_FN_ALIGN = (bit.lshift(1,25))
XN_FLAG_FN_LN = (bit.lshift(1,21))
XN_FLAG_FN_MASK = (bit.lshift(0x3,21))
XN_FLAG_FN_NONE = (bit.lshift(3,21))
XN_FLAG_FN_OID = (bit.lshift(2,21))
XN_FLAG_FN_SN = 0
XN_FLAG_SEP_COMMA_PLUS = (bit.lshift(1,16))
XN_FLAG_SEP_CPLUS_SPC = (bit.lshift(2,16))
XN_FLAG_SEP_MASK = bit.lshift(0xf , 16)
XN_FLAG_SEP_MULTILINE = (bit.lshift(4,16))
XN_FLAG_SEP_SPLUS_SPC = (bit.lshift(3,16))
XN_FLAG_SPC_EQ = (bit.lshift(1,23))


SSL_FILETYPE_ASN1 = X509_FILETYPE_ASN1
SSL_FILETYPE_PEM = X509_FILETYPE_PEM
SSL_get0_session = SSL_get_session
SSL3_RT_MAX_ENCRYPTED_OVERHEAD = (256 + SSL3_RT_MAX_MD_SIZE)
SSL3_RT_MAX_COMPRESSED_LENGTH = (SSL3_RT_MAX_PLAIN_LENGTH+SSL3_RT_MAX_COMPRESSED_OVERHEAD)
SSL3_RT_MAX_ENCRYPTED_LENGTH = (SSL3_RT_MAX_ENCRYPTED_OVERHEAD+SSL3_RT_MAX_COMPRESSED_LENGTH)
SSL3_RT_MAX_PACKET_SIZE = (SSL3_RT_MAX_ENCRYPTED_LENGTH+SSL3_RT_HEADER_LENGTH)
SSL3_RT_SEND_MAX_ENCRYPTED_OVERHEAD = (SSL_RT_MAX_CIPHER_BLOCK_SIZE + SSL3_RT_MAX_MD_SIZE)
