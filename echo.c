// SPDX-License-Identifier: GPL-3.0-or-later

/* gnu c and posix includes */
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
/* lwip includes */
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
/* this example's includes */
#include "echo.h"

/* defines */
#define NCAT_DEFAULT_LISTEN_PORT 31337
/* if doing UDP encap of ESP */
#define LWIP_DEFAULT_LISTEN_PORT 11111
#define LWIP_LISTEN_PORT         LWIP_DEFAULT_LISTEN_PORT

/* globals */
/* Toggle tcp/udp at build time. */
static int use_tcp = 1;
/* Toggle server/client mode. */
static int am_server = 1;

/* tcp functions */

static void
echo_tcp_close(struct tcp_pcb *tpcb)
{
    tcp_arg(tpcb, NULL);
    tcp_sent(tpcb, NULL);
    tcp_recv(tpcb, NULL);
    tcp_arg(tpcb, NULL);
    tcp_close(tpcb);
}

static err_t
echo_tcp_recv(void *           arg,
              struct tcp_pcb * tpcb,
              struct pbuf *    p,
              err_t            err)
{
    (void) arg;

    if (err == ERR_OK && p != NULL) {
        struct pbuf * q = NULL;

        for (q = p; q != NULL; q = q->next) {
            printf("recv: %.*s\n", q->len < 64 ? q->len : 64, q->payload);
            err_t wr_err = ERR_OK;

            /* Echo it back to sender.
             * First enqueue the data to be sent. */
            wr_err = tcp_write(tpcb, q->payload, q->len, 1);

            if (wr_err != ERR_OK) {
                printf("error: tcp_write(%d) returned: %d\n", q->len, wr_err);
                continue;
            }

            printf("send: %.*s\n", q->len < 64 ? q->len : 64, q->payload);

            /* Now trigger it to be sent. */
            wr_err = tcp_output(tpcb);

            if (wr_err != ERR_OK) {
                printf("error: tcp_output(%p) returned: %d\n", (void *)tpcb,
                       wr_err);
            }
            else {
               #if ECHO_TEST_INFO_MSG
                printf("info: tcp_output(%p) returned: %d\n", (void *)tpcb,
                       wr_err);
               #endif
            }
        }
    }
    else if (err == ERR_OK && p == NULL) {
        echo_tcp_close(tpcb);
    }
    else {
        printf("error: echo_tcp_recv: %d\n", err);
    }

    return ERR_OK;
}

static err_t
echo_tcp_sent(void *           arg,
              struct tcp_pcb * tpcb,
              u16_t            len)
{
    (void) arg;
    (void) tpcb;
    return ERR_OK;
}

static void
echo_tcp_err(void * arg,
             err_t  err)
{
    (void) arg;
    printf("error: echo_tcp_err: %s\n", lwip_strerr(err));
    return;
}

static err_t
echo_tcp_poll(void *           arg,
              struct tcp_pcb * tpcb)
{
    (void) arg;
    (void) tpcb;
    return ERR_OK;
}

static err_t
echo_tcp_accept(void *           arg,
                struct tcp_pcb * tpcb,
                err_t            err)
{
    (void) arg;
    (void) arg;

    /* Accepted new connection */
    LWIP_PLATFORM_DIAG(("info: echo_tcp_accept called\n"));

    printf("info: connect from: %s port: %d\n",
           ipaddr_ntoa(&(tpcb->remote_ip)), tpcb->remote_port);

    /* Set TCP callbacks. */
    tcp_recv(tpcb, echo_tcp_recv);
    tcp_sent(tpcb, echo_tcp_sent);
    tcp_err(tpcb, echo_tcp_err);
    tcp_poll(tpcb, echo_tcp_poll, 1);

    return ERR_OK;
}

/* udp functions */

static void
echo_udp_close(struct udp_pcb *pcb)
{
    udp_recv(pcb, NULL, NULL);
}

static void
echo_udp_recv(void *            arg,
              struct udp_pcb *  upcb,
              struct pbuf *     p,
              const ip_addr_t * addr,
              u16_t             port)
{
    (void) arg;

    if (p != NULL) {
        struct pbuf * q = NULL;

        for (q = p; q != NULL; q = q->next) {
            err_t wr_err = ERR_OK;
            printf("recv: %.*s\n", q->len < 64 ? q->len : 64, q->payload);
            printf("send: %.*s\n", q->len < 64 ? q->len : 64, q->payload);
            /* Echo received packet back to sender. */
            wr_err = udp_sendto(upcb, q, addr, port);

            if (wr_err != ERR_OK) {
                printf("error: udp_sendto returned: %d\n", wr_err);
                continue;
            }

            /* don't need to iterate because the underlying
             * code will process the whole chain. */
            break;
        }
    }
    else {
        echo_udp_close(upcb);
    }

    return;
}

static err_t
echo_tcp_connect(void *           arg,
                 struct tcp_pcb * tpcb,
                 err_t            err)
{
    (void) arg;
    (void) err;

    /* Made new connection */
    printf("info: tcp connected to: %s port: %d\n",
           ipaddr_ntoa(&(tpcb->remote_ip)), tpcb->remote_port);

    /* Set TCP callbacks. */
    tcp_recv(tpcb, echo_tcp_recv);
    tcp_sent(tpcb, echo_tcp_sent);
    tcp_err(tpcb, echo_tcp_err);
    tcp_poll(tpcb, echo_tcp_poll, 1);

    return ERR_OK;
}

/* init functions */

static int
echo_tcp_server_init(void)
{
    struct tcp_pcb * pcb = NULL;
    err_t            err = 0;

    pcb = tcp_new();

    if (pcb == NULL) {
        printf("error: tcp_new returned: NULL\n");
        return -1;
    }

    LWIP_DEBUGF(ECHO_DEBUG, ("echo_init: pcb: %x\n", pcb));

    /* Bind port 11111 */
    err = tcp_bind(pcb, IP_ADDR_ANY, LWIP_LISTEN_PORT);

    if (err != ERR_OK) {
        printf("error: tcp_bind returned: %d\n", err);
        return -1;
    }

    LWIP_DEBUGF(ECHO_DEBUG, ("echo_init: tcp_bind: %d\n", err));

    /* Enable listening */
    pcb = tcp_listen(pcb);

    if (pcb == NULL) {
        printf("error: tcp_listen returned: NULL\n");
        return -1;
    }

    LWIP_DEBUGF(ECHO_DEBUG, ("echo_init: listen-pcb: %x\n", pcb));

    /* Set accept message callback */
    tcp_accept(pcb, echo_tcp_accept);

    return 0;
}

static int
echo_udp_server_init(void)
{
    struct udp_pcb * pcb = NULL;
    err_t            err = 0;

    pcb = udp_new();

    if (pcb == NULL) {
        printf("error: udp_new returned: NULL\n");
        return -1;
    }

    LWIP_DEBUGF(ECHO_DEBUG, ("echo_init: pcb: %x\n", pcb));

    /* Bind port LWIP_LISTEN_PORT */
    err = udp_bind(pcb, IP_ADDR_ANY, LWIP_LISTEN_PORT);

    if (err != ERR_OK) {
        printf("error: udp_bind returned: %d\n", err);
        return -1;
    }

    udp_recv(pcb, echo_udp_recv, NULL);

    LWIP_DEBUGF(ECHO_DEBUG, ("echo_init: udp_bind: %d\n", err));

    return 0;
}

static int
echo_tcp_client_init(void)
{
    struct tcp_pcb * tpcb = NULL;
    ip_addr_t        dst_ip;
    err_t            err = 0;
    struct pbuf *    p = NULL;
    struct pbuf *    q = NULL;
    const char *     hello_msg = "Hi from lwip TCP client (-:\n";
    const char *     src = NULL;
    u16_t            data_len;
    int              addr_ok = 0;

    tpcb = tcp_new();

    if (tpcb == NULL) {
        printf("error: tcp_new returned: NULL\n");
        return -1;
    }

    LWIP_DEBUGF(ECHO_DEBUG, ("echo_init: tpcb: %x\n", tpcb));

    #if defined(ECHO_BIND_CLIENT)
    /* Optionally bind the client side to port LWIP_LISTEN_PORT. */
    err = tcp_bind(tpcb, IP_ADDR_ANY, LWIP_LISTEN_PORT);

    if (err != ERR_OK) {
        printf("error: tcp_bind returned: %d\n", err);
        return -1;
    }

    LWIP_DEBUGF(ECHO_DEBUG, ("echo_init: tcp_bind: %d\n", err));
    #endif

    #if LWIP_IPV6
    addr_ok = ip6addr_aton("2001:db8::1", ip_2_ip6(&dst_ip));
    if (addr_ok != 1) {
        printf("error: ip6addr_aton failed\n");
        return -1;
    }
    #else
    IP4_ADDR(&dst_ip, 172, 17, 0, 1);
    #endif

    err = tcp_connect(tpcb, &dst_ip, NCAT_DEFAULT_LISTEN_PORT,
                      echo_tcp_connect);

    if (err != ERR_OK) {
        printf("error: tcp_connect returned: %d\n", err);
        return -1;
    }

    /* Prepare a buffer with our tcp hello. */
    data_len = strlen(hello_msg);
    p = pbuf_alloc(PBUF_IP, (u16_t)data_len, PBUF_RAM);

    if (p == NULL) {
        printf("error: pbuf_alloc returned: NULL\n");
        return -1;
    }

    src = hello_msg;

    for (q = p; q != NULL; q = q->next) {
        if (data_len <= 0) {
            break;
        }

        printf("q->len: %d\n", q->len);
        memcpy(q->payload, src, q->len);
        data_len -= q->len;
        src += q->len;


        /* Enqueue the data to be sent. */
        err = tcp_write(tpcb, q->payload, q->len, 1);

        if (err != ERR_OK) {
            printf("error: tcp_write(%d) returned: %d\n", q->len, err);
            return -1;
        }

        /* Now trigger it to be sent. */
        err = tcp_output(tpcb);

        if (err != ERR_OK) {
            printf("error: tcp_output(%p) returned: %d\n", (void *)tpcb,
                   err);
        }
        else {
            #if ECHO_TEST_INFO_MSG
            printf("info: tcp_output(%p) returned: %d\n", (void *)tpcb,
                   err);
            #endif
        }
    }

    return 0;
}

static int
echo_udp_client_init(void)
{
    struct udp_pcb * upcb = NULL;
    ip_addr_t        dst_ip;
    err_t            err = 0;
    struct pbuf *    p = NULL;
    struct pbuf *    q = NULL;
    const char *     hello_msg = "Hi from lwip UDP client (-:\n";
    const char *     src = NULL;
    u16_t            data_len;
    int              addr_ok = 0;

    upcb = udp_new();

    if (upcb == NULL) {
        printf("error: udp_new returned: NULL\n");
        return -1;
    }

    LWIP_DEBUGF(ECHO_DEBUG, ("echo_init: upcb: %x\n", upcb));

    #if defined(ECHO_BIND_CLIENT)
    /* Optionally bind the client side to port LWIP_LISTEN_PORT. */
    /* Bind port LWIP_LISTEN_PORT */
    err = udp_bind(upcb, IP_ADDR_ANY, LWIP_LISTEN_PORT);

    if (err != ERR_OK) {
        printf("error: udp_bind returned: %d\n", err);
        return -1;
    }
    #endif

    udp_recv(upcb, echo_udp_recv, NULL);

    #if LWIP_IPV6
    addr_ok = ip6addr_aton("2001:db8::1", ip_2_ip6(&dst_ip));
    if (addr_ok != 1) {
        printf("error: ip6addr_aton failed\n");
        return -1;
    }
    #else
    IP4_ADDR(&dst_ip, 172, 17, 0, 1);
    #endif

    err = udp_connect(upcb, &dst_ip, NCAT_DEFAULT_LISTEN_PORT);

    if (err != ERR_OK) {
        printf("error: udp_connect returned: %d\n", err);
        return -1;
    }
    printf("info: udp connected to: %s port: %d\n",
           ipaddr_ntoa(&(upcb->remote_ip)), upcb->remote_port);

    /* Prepare a buffer with our udp hello. */
    data_len = strlen(hello_msg);
    p = pbuf_alloc(PBUF_IP, (u16_t)data_len, PBUF_RAM);

    if (p == NULL) {
        printf("error: pbuf_alloc returned: NULL\n");
        return -1;
    }

    src = hello_msg;

    for (q = p; q != NULL; q = q->next) {
        if (data_len <= 0) {
            break;
        }

        printf("q->len: %d\n", q->len);
        memcpy(q->payload, src, q->len);
        data_len -= q->len;
        src += q->len;
    }

    err = udp_send(upcb, p);

    if (err != ERR_OK) {
        printf("error: udp_send returned: %d\n");
        return -1;
    }

    return 0;
}

int
echo_init(void)
{
    if (am_server) {
        if (use_tcp) {
            return echo_tcp_server_init();
        }
        else {
            return echo_udp_server_init();
        }
    }
    else {
        if (use_tcp) {
            return echo_tcp_client_init();
        }
        else {
            return echo_udp_client_init();
        }
    }
}
