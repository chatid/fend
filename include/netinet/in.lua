include "sys/socket"

ffi.cdef [[
enum
  {
    IPPROTO_IP = 0,
    IPPROTO_HOPOPTS = 0,
    IPPROTO_ICMP = 1,
    IPPROTO_IGMP = 2,
    IPPROTO_IPIP = 4,
    IPPROTO_TCP = 6,
    IPPROTO_EGP = 8,
    IPPROTO_PUP = 12,
    IPPROTO_UDP = 17,
    IPPROTO_IDP = 22,
    IPPROTO_TP = 29,
    IPPROTO_DCCP = 33,
    IPPROTO_IPV6 = 41,
    IPPROTO_ROUTING = 43,
    IPPROTO_FRAGMENT = 44,
    IPPROTO_RSVP = 46,
    IPPROTO_GRE = 47,
    IPPROTO_ESP = 50,
    IPPROTO_AH = 51,
    IPPROTO_ICMPV6 = 58,
    IPPROTO_NONE = 59,
    IPPROTO_DSTOPTS = 60,
    IPPROTO_MTP = 92,
    IPPROTO_ENCAP = 98,
    IPPROTO_PIM = 103,
    IPPROTO_COMP = 108,
    IPPROTO_SCTP = 132,
    IPPROTO_UDPLITE = 136,
    IPPROTO_RAW = 255,
    IPPROTO_MAX
  };
typedef uint16_t in_port_t;
enum
  {
    IPPORT_ECHO = 7,
    IPPORT_DISCARD = 9,
    IPPORT_SYSTAT = 11,
    IPPORT_DAYTIME = 13,
    IPPORT_NETSTAT = 15,
    IPPORT_FTP = 21,
    IPPORT_TELNET = 23,
    IPPORT_SMTP = 25,
    IPPORT_TIMESERVER = 37,
    IPPORT_NAMESERVER = 42,
    IPPORT_WHOIS = 43,
    IPPORT_MTP = 57,
    IPPORT_TFTP = 69,
    IPPORT_RJE = 77,
    IPPORT_FINGER = 79,
    IPPORT_TTYLINK = 87,
    IPPORT_SUPDUP = 95,
    IPPORT_EXECSERVER = 512,
    IPPORT_LOGINSERVER = 513,
    IPPORT_CMDSERVER = 514,
    IPPORT_EFSSERVER = 520,
    IPPORT_BIFFUDP = 512,
    IPPORT_WHOSERVER = 513,
    IPPORT_ROUTESERVER = 520,
    IPPORT_RESERVED = 1024,
    IPPORT_USERRESERVED = 5000
  };
typedef uint32_t in_addr_t;
struct in_addr
  {
    in_addr_t s_addr;
  };
struct in6_addr
  {
    union
      {
 uint8_t __u6_addr8[16];
 uint16_t __u6_addr16[8];
 uint32_t __u6_addr32[4];
      } __in6_u;
  };
extern const struct in6_addr in6addr_any;
extern const struct in6_addr in6addr_loopback;
struct sockaddr_in
  {
    sa_family_t sin_family;
    in_port_t sin_port;
    struct in_addr sin_addr;
    unsigned char sin_zero[sizeof (struct sockaddr) -
      (sizeof (unsigned short int)) -
      sizeof (in_port_t) -
      sizeof (struct in_addr)];
  };
struct sockaddr_in6
  {
    sa_family_t sin6_family;
    in_port_t sin6_port;
    uint32_t sin6_flowinfo;
    struct in6_addr sin6_addr;
    uint32_t sin6_scope_id;
  };
struct ip_mreq
  {
    struct in_addr imr_multiaddr;
    struct in_addr imr_interface;
  };
struct ip_mreq_source
  {
    struct in_addr imr_multiaddr;
    struct in_addr imr_interface;
    struct in_addr imr_sourceaddr;
  };
struct ipv6_mreq
  {
    struct in6_addr ipv6mr_multiaddr;
    unsigned int ipv6mr_interface;
  };
struct group_req
  {
    uint32_t gr_interface;
    struct sockaddr_storage gr_group;
  };
struct group_source_req
  {
    uint32_t gsr_interface;
    struct sockaddr_storage gsr_group;
    struct sockaddr_storage gsr_source;
  };
struct ip_msfilter
  {
    struct in_addr imsf_multiaddr;
    struct in_addr imsf_interface;
    uint32_t imsf_fmode;
    uint32_t imsf_numsrc;
    struct in_addr imsf_slist[1];
  };
struct group_filter
  {
    uint32_t gf_interface;
    struct sockaddr_storage gf_group;
    uint32_t gf_fmode;
    uint32_t gf_numsrc;
    struct sockaddr_storage gf_slist[1];
};
struct ip_opts
  {
    struct in_addr ip_dst;
    char ip_opts[40];
  };
struct ip_mreqn
  {
    struct in_addr imr_multiaddr;
    struct in_addr imr_address;
    int imr_ifindex;
  };
struct in_pktinfo
  {
    int ipi_ifindex;
    struct in_addr ipi_spec_dst;
    struct in_addr ipi_addr;
  };
extern uint32_t ntohl (uint32_t __netlong) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));
extern uint16_t ntohs (uint16_t __netshort)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));
extern uint32_t htonl (uint32_t __hostlong)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));
extern uint16_t htons (uint16_t __hostshort)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));
extern int bindresvport (int __sockfd, struct sockaddr_in *__sock_in) __attribute__ ((__nothrow__ , __leaf__));
extern int bindresvport6 (int __sockfd, struct sockaddr_in6 *__sock_in)
     __attribute__ ((__nothrow__ , __leaf__));
]]

PF_UNSPEC = 0
PF_INET = 2
PF_IPX = 4
PF_INET6 = 10
PF_X25 = 9
PF_WANPIPE = 25
PF_TIPC = 30
PF_SNA = 22
PF_SECURITY = 14
PF_RXRPC = 33
PF_ROSE = 11
PF_RDS = 21
PF_PPPOX = 24
PF_PHONET = 35
PF_PACKET = 17
PF_NFC = 39
PF_NETROM = 6
PF_NETLINK = 16
PF_NETBEUI = 13
PF_MAX = 40
PF_LOCAL = 1
PF_LLC = 26
PF_KEY = 15
PF_IUCV = 32
PF_ISDN = 34
PF_IRDA = 23
PF_IEEE802154 = 36
PF_ECONET = 19
PF_DECnet = 12
PF_CAN = 29
PF_CAIF = 37
PF_BRIDGE = 7
PF_BLUETOOTH = 31
PF_AX25 = 3
PF_ATMSVC = 20
PF_ATMPVC = 8
PF_ASH = 18
PF_APPLETALK = 5
PF_ALG = 38
PF_UNIX = PF_LOCAL
PF_ROUTE = PF_NETLINK
PF_FILE = PF_LOCAL

AF_X25 = PF_X25
AF_WANPIPE = PF_WANPIPE
AF_UNSPEC = PF_UNSPEC
AF_UNIX = PF_UNIX
AF_TIPC = PF_TIPC
AF_SNA = PF_SNA
AF_SECURITY = PF_SECURITY
AF_RXRPC = PF_RXRPC
AF_ROUTE = PF_ROUTE
AF_ROSE = PF_ROSE
AF_RDS = PF_RDS
AF_PPPOX = PF_PPPOX
AF_PHONET = PF_PHONET
AF_PACKET = PF_PACKET
AF_NFC = PF_NFC
AF_NETROM = PF_NETROM
AF_NETLINK = PF_NETLINK
AF_NETBEUI = PF_NETBEUI
AF_MAX = PF_MAX
AF_LOCAL = PF_LOCAL
AF_LLC = PF_LLC
AF_KEY = PF_KEY
AF_IUCV = PF_IUCV
AF_ISDN = PF_ISDN
AF_IRDA = PF_IRDA
AF_IPX = PF_IPX
AF_INET6 = PF_INET6
AF_INET = PF_INET
AF_IEEE802154 = PF_IEEE802154
AF_FILE = PF_FILE
AF_ECONET = PF_ECONET
AF_DECnet = PF_DECnet
AF_CAN = PF_CAN
AF_CAIF = PF_CAIF
AF_BRIDGE = PF_BRIDGE
AF_BLUETOOTH = PF_BLUETOOTH
AF_AX25 = PF_AX25
AF_ATMSVC = PF_ATMSVC
AF_ATMPVC = PF_ATMPVC
AF_ASH = PF_ASH
AF_APPLETALK = PF_APPLETALK
AF_ALG = PF_ALG

INET6_ADDRSTRLEN = 46
INET_ADDRSTRLEN = 16

--[[ Options for use with `getsockopt' and `setsockopt' at the IP level.
   The first word in the comment at the right is the data type used;
   "bool" means a boolean value stored in an `int'.]]
IP_OPTIONS                = 4 -- ip_opts; IP per-packet options.
IP_HDRINCL                = 3 -- int; Header is included with data.
IP_TOS                    = 1 -- int; IP type of service and precedence.
IP_TTL                    = 2 -- int; IP time to live.
IP_RECVOPTS               = 6 -- bool; Receive all IP options w/datagram.
-- For BSD compatibility.
IP_RETOPTS                = 7 -- ip_opts; Set/get IP per-packet options.
IP_RECVRETOPTS            = IP_RETOPTS -- bool; Receive IP options for response.
IP_MULTICAST_IF           = 32 -- in_addr; set/get IP multicast i/f
IP_MULTICAST_TTL          = 33 -- u_char; set/get IP multicast ttl
IP_MULTICAST_LOOP         = 34 -- i_char; set/get IP multicast loopback
IP_ADD_MEMBERSHIP         = 35 -- ip_mreq; add an IP group membership
IP_DROP_MEMBERSHIP        = 36 -- ip_mreq; drop an IP group membership
IP_UNBLOCK_SOURCE         = 37 -- ip_mreq_source: unblock data from source
IP_BLOCK_SOURCE           = 38 -- ip_mreq_source: block data from source
IP_ADD_SOURCE_MEMBERSHIP  = 39 -- ip_mreq_source: join source group
IP_DROP_SOURCE_MEMBERSHIP = 40 -- ip_mreq_source: leave source group
IP_MSFILTER               = 41


MCAST_JOIN_GROUP          = 42  -- group_req: join any-source group
MCAST_BLOCK_SOURCE        = 43  -- group_source_req: block from given group
MCAST_UNBLOCK_SOURCE      = 44 -- group_source_req: unblock from given group
MCAST_LEAVE_GROUP         = 45 -- group_req: leave any-source group
MCAST_JOIN_SOURCE_GROUP   = 46 -- group_source_req: join source-spec gr
MCAST_LEAVE_SOURCE_GROUP  = 47 -- group_source_req: leave source-spec gr
MCAST_MSFILTER            = 48
IP_MULTICAST_ALL          = 49
IP_UNICAST_IF             = 50

MCAST_EXCLUDE             = 0
MCAST_INCLUDE       = 1

IP_ROUTER_ALERT     = 5 -- bool
IP_PKTINFO          = 8 -- bool
IP_PKTOPTIONS       = 9
IP_PMTUDISC         = 10 -- obsolete name?
IP_MTU_DISCOVER     = 10 -- int; see below
IP_RECVERR          = 11 -- bool
IP_RECVTTL          = 12 -- bool
IP_RECVTOS          = 13 -- bool
IP_MTU              = 14 -- int
IP_FREEBIND         = 15
IP_IPSEC_POLICY     = 16
IP_XFRM_POLICY      = 17
IP_PASSSEC          = 18
IP_TRANSPARENT      = 19
IP_MULTICAST_ALL    = 49 -- bool

-- TProxy original addresses
IP_ORIGDSTADDR      = 20
IP_IRECVORIGDSTADDR = IP_ORIGDSTADD

IP_MINTTL           = 2

-- IP_MTU_DISCOVER arguments.
IP_PMTUDISC_DONT  = 0 -- Never send DF frames.
IP_PMTUDISC_WANT  = 1 -- Use per route hints.
IP_PMTUDISC_DO    = 2 -- Always DF.
IP_PMTUDISC_PROBE = 3 -- Ignore dst pmtu.

-- To select the IP level.
SOL_IP = 0

IP_DEFAULT_MULTICAST_TTL  = 1
IP_DEFAULT_MULTICAST_LOOP = 1
IP_MAX_MEMBERSHIPS        = 20


--[[ Options for use with `getsockopt' and `setsockopt' at the IPv6 level.
   The first word in the comment at the right is the data type used;
   "bool" means a boolean value stored in an `int'.]]
IPV6_ADDRFORM        = 1
IPV6_2292PKTINFO     = 2
IPV6_2292HOPOPTS     = 3
IPV6_2292DSTOPTS     = 4
IPV6_2292RTHDR       = 5
IPV6_2292PKTOPTIONS  = 6
IPV6_CHECKSUM        = 7
IPV6_2292HOPLIMIT    = 8

SCM_SRCRT            = IPV6_RXSRCRT -- Undefined???

IPV6_NEXTHOP         = 9
IPV6_AUTHHDR         = 10
IPV6_UNICAST_HOPS    = 16
IPV6_MULTICAST_IF    = 17
IPV6_MULTICAST_HOPS  = 18
IPV6_MULTICAST_LOOP  = 19
IPV6_JOIN_GROUP      = 20
IPV6_LEAVE_GROUP     = 21
IPV6_ROUTER_ALERT    = 22
IPV6_MTU_DISCOVER    = 23
IPV6_MTU             = 24
IPV6_RECVERR         = 25
IPV6_V6ONLY          = 26
IPV6_JOIN_ANYCAST    = 27
IPV6_LEAVE_ANYCAST   = 28
IPV6_IPSEC_POLICY    = 34
IPV6_XFRM_POLICY     = 35

IPV6_RECVPKTINFO     = 49
IPV6_PKTINFO         = 50
IPV6_RECVHOPLIMIT    = 51
IPV6_HOPLIMIT        = 52
IPV6_RECVHOPOPTS     = 53
IPV6_HOPOPTS         = 54
IPV6_RTHDRDSTOPTS    = 55
IPV6_RECVRTHDR       = 56
IPV6_RTHDR           = 57
IPV6_RECVDSTOPTS     = 58
IPV6_DSTOPTS         = 59

IPV6_RECVTCLASS      = 66
IPV6_TCLASS          = 67

-- Obsolete synonyms for the above.
IPV6_ADD_MEMBERSHIP  = IPV6_JOIN_GROUP
IPV6_DROP_MEMBERSHIP = IPV6_LEAVE_GROUP
IPV6_RXHOPOPTS       = IPV6_HOPOPTS
IPV6_RXDSTOPTS       = IPV6_DSTOPTS

-- IPV6_MTU_DISCOVER values.
IPV6_PMTUDISC_DONT   = 0 -- Never send DF frames.
IPV6_PMTUDISC_WANT   = 1 -- Use per route hints.
IPV6_PMTUDISC_DO     = 2 -- Always DF.
IPV6_PMTUDISC_PROBE  = 3 -- Ignore dst pmtu.

-- Socket level values for IPv6.
SOL_IPV6             = 41
SOL_ICMPV6           = 58

-- Routing header options for IPv6.
IPV6_RTHDR_LOOSE     = 0 -- Hop doesn't need to be neighbour.
IPV6_RTHDR_STRICT    = 1 -- Hop must be a neighbour.

IPV6_RTHDR_TYPE_0    = 0 -- IPv6 Routing header type 0.
