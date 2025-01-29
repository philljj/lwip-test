// SPDX-License-Identifier: GPL-3.0-or-later

/* gnu c and posix includes */
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>

/* pcap includes */
#include <pcap/pcap.h>

/* lwip includes */
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/ethip6.h"
#include "netif/etharp.h"
#include "lwip/udp.h"
#include "lwip/mld6.h"
#include "lwip/timeouts.h"
#include "lwip/esp_common.h"
#include "lwip/ip6_esp.h"

/* this example's includes */
#include "echo.h"

/* defines */
#define NCAT_DEFAULT_LISTEN_PORT 31337

int
dbg_printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int r = vprintf(fmt, args);
    va_end(args);
    return r;
}

static err_t
pcap_output(struct netif * netif,
            struct pbuf *  p)
{
    pcap_t * pcap = netif->state;
    int      rc =  0;

    if (pcap == NULL) {
        printf("error: pcap_output: netif->state == NULL\n");
        return ERR_IF;
    }

    rc = pcap_sendpacket(pcap, (uint8_t *)p->payload, p->tot_len);

    if (rc != 0) {
        printf("error: pcap_sendpacket returned: %d: %s\n", rc,
               pcap_geterr(pcap));
        return ERR_IF;
    }

    #if ECHO_TEST_INFO_MSG
    printf("info: pcap_sendpacket sent %d bytes\n", p->tot_len);
    #endif

    return ERR_OK;
}

static err_t
init_callback(struct netif * netif)
{
    netif->name[0] = 't';
    netif->name[1] = 'p';
    netif->linkoutput = pcap_output;
#if LWIP_IPV4
    netif->output = etharp_output;
#endif
#if LWIP_IPV6
    netif->output_ip6 = ethip6_output;
#endif

    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP |
                   NETIF_FLAG_ETHERNET;

    netif_set_link_up(netif);

    netif_ipsec_enable(netif);

    return ERR_OK;
}

int
main(size_t argc,
     char * argv[])
{
    pcap_t *       pcap = NULL;
    struct netif   netif;
    struct netif * netif_p;
    char           errbuf[PCAP_ERRBUF_SIZE];
    int            rc = 0;

    memset(errbuf, 0, sizeof(errbuf));

    pcap = pcap_open_live("eth0", 65536, 1, 100, errbuf);

    if (pcap == NULL) {
        printf("error: pcap_open_live returned: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    lwip_init();

    memset(&netif, 0, sizeof netif);
    netif.hwaddr_len = 6;
    memcpy(netif.hwaddr, "\xaa\x00\x00\x00\x00\x01", 6);

    /* This is the hard-coded listen IP iaddress */
    #if LWIP_IPV6
    ip6_addr_t ip;
    int        addr_ok = 0;

    addr_ok = ip6addr_aton("2001:db8::5", &ip);
    if (addr_ok != 1) {
        printf("error: ip6addr_aton failed\n");
        return -1;
    }
    #else
    ip_addr_t ip;
    ip_addr_t mask;
    ip_addr_t gw;
    IP4_ADDR(&ip, 172, 17, 0, 5);
    IP4_ADDR(&mask, 255, 255, 0, 0);
    IP4_ADDR(&gw, 172, 17, 0, 1);
    #endif

    #if LWIP_IPV6
    netif_p = netif_add(&netif, pcap, init_callback, ethernet_input);
    netif_ip6_addr_set(&netif, 0, &ip);
    netif_ip6_addr_set_state(&netif, 0, IP6_ADDR_TENTATIVE);
    netif_ip6_addr_set_state(&netif, 0, IP6_ADDR_PREFERRED);
    #else
    netif_p = netif_add(&netif, &ip, &mask, &gw, pcap, init_callback,
                        ethernet_input);
    #endif

    if (netif_p == NULL) {
        printf("error: netif_add returned: NULL\n");
        return EXIT_FAILURE;
    }

    netif_set_up(&netif);

    NETIF_SET_CHECKSUM_CTRL(&netif, 0x00FF);

    rc = echo_init();

    if (rc < 0) {
        printf("error: echo_init returned %d\n", rc);
        return EXIT_FAILURE;
    }

    sys_restart_timeouts();

    #define IPSEC_PROVISION

    #ifdef IPSEC_PROVISION
    #include "ipsec_provision.c"
    #endif

    struct pcap_pkthdr *  hdr = NULL;
    const unsigned char * data = NULL;

    for (;;) {
        sys_check_timeouts();
        int r = pcap_next_ex(pcap, &hdr, &data);

        switch (r)
        {
            case 0:
                // timeout
                continue;

            case -1:
                printf("Error: %s\n", pcap_geterr(pcap));
                continue;

            case 1:
                break;

            default:
                printf("Unknown result: %d\n", r);
                continue;
        }

    #if 1
        /* Process all in one contiguous pbuf. */
        struct pbuf * pbuf = pbuf_alloc(PBUF_RAW, hdr->len, PBUF_RAM);
        memcpy(pbuf->payload, data, hdr->len);
        netif.input(pbuf, &netif);
    #else
        /* Process in pbuf chain to test chaining. */
        size_t chain_len = 120;
        size_t hdr_len = 0;
        size_t pbuf_len = 0;
        size_t offset = 0;
        struct pbuf * pbuf_head = NULL;
        struct pbuf * pbuf_tail = NULL;

        hdr_len = hdr->len;
        pbuf_len = (chain_len <= hdr_len) ? chain_len : hdr_len;
        pbuf_head = pbuf_alloc(PBUF_RAW, pbuf_len, PBUF_RAM);

        #if 0
        printf("chain_len: %d\n", chain_len);
        printf("pbuf_len: %d\n", pbuf_len);
        printf("hdr_len: %d\n", hdr_len);
        printf("offset: %d\n", offset);
        #endif

        memcpy(pbuf_head->payload, data, pbuf_len);
        hdr_len -= pbuf_len;
        offset += pbuf_len;

        while (hdr_len) {
            pbuf_len = (chain_len <= hdr_len) ? chain_len : hdr_len;
            pbuf_tail = pbuf_alloc(PBUF_RAW, pbuf_len, PBUF_RAM);

            #if 0
            printf("chain_len: %d\n", chain_len);
            printf("pbuf_len: %d\n", pbuf_len);
            printf("hdr_len: %d\n", hdr_len);
            printf("offset: %d\n", offset);
            #endif

            memcpy(pbuf_tail->payload, data + offset, pbuf_len);
            hdr_len -= pbuf_len;
            offset += pbuf_len;

            pbuf_chain(pbuf_head, pbuf_tail);
        }

        netif.input(pbuf_head, &netif);
    #endif
    }

    return EXIT_SUCCESS;
}
