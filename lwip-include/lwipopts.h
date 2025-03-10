// SPDX-License-Identifier: GPL-3.0-or-later

#define TCP_MSS                         1500
#define TCP_WND                         65535
#define NO_SYS                          1
#define SYS_LIGHTWEIGHT_PROT            0

#define MEM_LIBC_MALLOC                 1
#define MEMP_MEM_MALLOC                 1
#define MEM_USE_POOLS                   0
#define LWIP_ALLOW_MEM_FREE_FROM_OTHER_CONTEXT 1

#define LWIP_ETHERNET                   1
// Enable LWIP_IPV4 or LWIP_IPV6, but
// not both.
#define LWIP_IPV4                       0
#define LWIP_IPV6                       1
#define LWIP_TCP                        1
#define LWIP_UDP                        1
#define LWIP_ARP                        1
#define LWIP_ICMP                       1
#define IP_FRAG                         0
#define LWIP_IPV6_REASS                 0

#define ICMP_DEBUG                      LWIP_DBG_ON
#define LWIP_DEBUG                      LWIP_DBG_ON
#define ECHO_DEBUG                      0
//#define PBUF_DEBUG                      LWIP_DBG_ON
//#define IP4_DEBUG                       LWIP_DBG_ON
//#define IP6_DEBUG                       LWIP_DBG_ON
//#define IP_DEBUG                        LWIP_DBG_ON
//#define NETIF_DEBUG                     LWIP_DBG_ON
//#define INET_DEBUG                      LWIP_DBG_ON
//#define TCP_DEBUG                       LWIP_DBG_ON
//#define UDP_DEBUG                       LWIP_DBG_ON
//#define ETHARP_DEBUG                    LWIP_DBG_ON

#define PPP_SUPPORT                     0
#define LWIP_SOCKET                     0
#define LWIP_NETCONN                    0
#define LWIP_RAW                        0
#define LWIP_COMPAT_SOCKETS             0
#define LWIP_STATS                      0

#define LWIP_CHECKSUM_CTRL_PER_NETIF    1

