include "sys/types"
include "sys/socket"

require"ffi".cdef [[
struct tcphdr
  {
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
    u_int16_t res1:4;
    u_int16_t doff:4;
    u_int16_t fin:1;
    u_int16_t syn:1;
    u_int16_t rst:1;
    u_int16_t psh:1;
    u_int16_t ack:1;
    u_int16_t urg:1;
    u_int16_t res2:2;
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};
enum
{
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING
};
enum tcp_ca_state
{
  TCP_CA_Open = 0,
  TCP_CA_Disorder = 1,
  TCP_CA_CWR = 2,
  TCP_CA_Recovery = 3,
  TCP_CA_Loss = 4
};
struct tcp_info
{
  u_int8_t tcpi_state;
  u_int8_t tcpi_ca_state;
  u_int8_t tcpi_retransmits;
  u_int8_t tcpi_probes;
  u_int8_t tcpi_backoff;
  u_int8_t tcpi_options;
  u_int8_t tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
  u_int32_t tcpi_rto;
  u_int32_t tcpi_ato;
  u_int32_t tcpi_snd_mss;
  u_int32_t tcpi_rcv_mss;
  u_int32_t tcpi_unacked;
  u_int32_t tcpi_sacked;
  u_int32_t tcpi_lost;
  u_int32_t tcpi_retrans;
  u_int32_t tcpi_fackets;
  u_int32_t tcpi_last_data_sent;
  u_int32_t tcpi_last_ack_sent;
  u_int32_t tcpi_last_data_recv;
  u_int32_t tcpi_last_ack_recv;
  u_int32_t tcpi_pmtu;
  u_int32_t tcpi_rcv_ssthresh;
  u_int32_t tcpi_rtt;
  u_int32_t tcpi_rttvar;
  u_int32_t tcpi_snd_ssthresh;
  u_int32_t tcpi_snd_cwnd;
  u_int32_t tcpi_advmss;
  u_int32_t tcpi_reordering;
  u_int32_t tcpi_rcv_rtt;
  u_int32_t tcpi_rcv_space;
  u_int32_t tcpi_total_retrans;
};
struct tcp_md5sig
{
  struct sockaddr_storage tcpm_addr;
  u_int16_t __tcpm_pad1;
  u_int16_t tcpm_keylen;
  u_int32_t __tcpm_pad2;
  u_int8_t tcpm_key[80];
};
]]

module ( ... )

TCP_NODELAY      = 1      -- Don't delay send to coalesce packets
TCP_MAXSEG       = 2      -- Set maximum segment size
TCP_CORK         = 3      -- Control sending of partial frames
TCP_KEEPIDLE     = 4      -- Start keeplives after this period
TCP_KEEPINTVL    = 5      -- Interval between keepalives
TCP_KEEPCNT      = 6      -- Number of keepalives before death
TCP_SYNCNT       = 7      -- Number of SYN retransmits
TCP_LINGER2      = 8      -- Life time of orphaned FIN-WAIT-2 state
TCP_DEFER_ACCEPT = 9      -- Wake up listener only when data arrive
TCP_WINDOW_CLAMP = 10     -- Bound advertised window
TCP_INFO         = 11     -- Information about this connection.
TCP_QUICKACK     = 12     -- Bock/reenable quick ACKs.
TCP_CONGESTION   = 13     -- Congestion control algorithm.
TCP_MD5SIG       = 14     -- TCP MD5 Signature (RFC2385)


TH_FIN = 0x01
TH_SYN = 0x02
TH_RST = 0x04
TH_PUSH = 0x08
TH_ACK = 0x10
TH_URG = 0x20

TCPOPT_EOL             = 0
TCPOPT_NOP             = 1
TCPOPT_MAXSEG          = 2
TCPOLEN_MAXSEG         = 4
TCPOPT_WINDOW          = 3
TCPOLEN_WINDOW         = 3
TCPOPT_SACK_PERMITTED  = 4               -- Experimental
TCPOLEN_SACK_PERMITTED = 2
TCPOPT_SACK            = 5               -- Experimental
TCPOPT_TIMESTAMP       = 8
TCPOLEN_TIMESTAMP      = 10
TCPOLEN_TSTAMP_APPA    = (TCPOLEN_TIMESTAMP+2) -- appendix A

TCP_MSS          = 512
TCP_MAXWIN       = 65535   -- largest value for (unscaled) window
TCP_MAX_WINSHIFT = 14      -- maximum window shift

SOL_TCP = 6       -- TCP level

TCPI_OPT_TIMESTAMPS = 1
TCPI_OPT_SACK       = 2
TCPI_OPT_WSCALE     = 4
TCPI_OPT_ECN        = 8

TCP_MD5SIG_MAXKEYLEN = 80

return _M
