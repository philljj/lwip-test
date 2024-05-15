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

/* globals */

/* Toggle tcp/udp at build time. */
static int use_tcp = 1;

/* tcp functions */

static void
echo_tcp_close(struct tcp_pcb *pcb)
{
    tcp_arg(pcb, NULL);
    tcp_sent(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_arg(pcb, NULL);
    tcp_close(pcb);
}

static err_t
echo_tcp_recv(void *           arg,
              struct tcp_pcb * pcb,
              struct pbuf *    p,
              err_t            err)
{
    (void) arg;

    if (err == ERR_OK && p != NULL) {
        struct pbuf * q = NULL;

        for (q = p; q != NULL; q = q->next) {
            printf("recv: %.*s\n", q->len, q->payload);
            err_t wr_err = ERR_OK;

            /* Echo it back to sender.
             * First enqueue the data to be sent. */
            wr_err = tcp_write(pcb, q->payload, q->len, 1);

            if (wr_err != ERR_OK) {
                printf("error: tcp_write(%d) returned: %d\n", q->len, wr_err);
                continue;
            }

            printf("send: %.*s\n", q->len, q->payload);

            /* Now trigger it to be sent. */
            wr_err = tcp_output(pcb);

            if (wr_err != ERR_OK) {
                printf("error: tcp_output(%p) returned: %d\n", (void *)pcb,
                       wr_err);
            }
            else {
                printf("info: tcp_output(%p) returned: %d\n", (void *)pcb,
                       wr_err);
            }
        }
    }
    else if (err == ERR_OK && p == NULL) {
        echo_tcp_close(pcb);
    }
    else {
        printf("error: echo_tcp_recv: %d\n", err);
    }

    return ERR_OK;
}

static err_t
echo_tcp_sent(void *           arg,
              struct tcp_pcb * pcb,
              u16_t            len)
{
    printf("Sent: %d\n", len);
    return ERR_OK;
}

static void
echo_tcp_err(void * arg,
             err_t  err)
{
    LWIP_DEBUGF(ECHO_DEBUG, ("echo_tcp_err: %s (%i)\n", lwip_strerr(err), err));
    printf("Err: %s\n", lwip_strerr(err));
}

static err_t
echo_tcp_poll(void *           arg,
              struct tcp_pcb * pcb)
{
    return ERR_OK;
}

static err_t
echo_tcp_accept(void *           arg,
                struct tcp_pcb * pcb,
                err_t            err)
{
    /* Accepted new connection */
    LWIP_PLATFORM_DIAG(("echo_tcp_accept called\n"));

    printf("Connect from: %s port: %d\n", ipaddr_ntoa(&(pcb->remote_ip)), pcb->remote_port);

    /* Set an arbitrary pointer for callbacks. */
    //tcp_arg(pcb, esm);

    /* Set TCP receive packet callback. */
    tcp_recv(pcb, echo_tcp_recv);

    /* Set a TCP packet sent callback. */
    tcp_sent(pcb, echo_tcp_sent);

    /* Set an error callback. */
    tcp_err(pcb, echo_tcp_err);

    /* Set a TCP poll callback */
    tcp_poll(pcb, echo_tcp_poll, 1);

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
            printf("recv: %.*s\n", q->len, q->payload);
            printf("send: %.*s\n", q->len, q->payload);
            /* Echo received packet back to sender. */
            wr_err = udp_sendto(upcb, q, addr, port);

            if (wr_err != ERR_OK) {
                printf("error: udp_sendto returned: %d\n", wr_err);
                continue;
            }
        }
    }
    else {
        echo_udp_close(upcb);
    }

    return;
}

/* init functions */

static int
echo_tcp_init(void)
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
    err = tcp_bind(pcb, IP_ADDR_ANY, 11111);

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
echo_udp_init(void)
{
    struct udp_pcb * pcb = NULL;
    err_t            err = 0;

    pcb = udp_new();

    if (pcb == NULL) {
        printf("error: udp_new returned: NULL\n");
        return -1;
    }

    LWIP_DEBUGF(ECHO_DEBUG, ("echo_init: pcb: %x\n", pcb));

    /* Bind port 11111 */
    err = udp_bind(pcb, IP_ADDR_ANY, 11111);

    if (err != ERR_OK) {
        printf("error: udp_bind returned: %d\n", err);
        return -1;
    }

    udp_recv(pcb, echo_udp_recv, NULL);

    LWIP_DEBUGF(ECHO_DEBUG, ("echo_init: udp_bind: %d\n", err));

    return 0;
}

int
echo_init(void)
{
    if (use_tcp) {
        return echo_tcp_init();
    }
    else {
        return echo_udp_init();
    }
}
