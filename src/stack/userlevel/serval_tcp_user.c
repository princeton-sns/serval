/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include "serval_tcp.h"
#include <serval/netdevice.h>

/* Dummy function for encapsulation in user mode */
int serval_udp_encap_xmit(struct sk_buff *skb)
{
        struct sock *sk = skb->sk;

        if (!sk) {
                kfree_skb(skb);
                return NET_RX_DROP;
        }

        return serval_sk(sk)->af_ops->encap_queue_xmit(skb);
}

/* tcp_input.c */

int sysctl_serval_tcp_sack = 1;
int sysctl_serval_tcp_fack = 1;
int sysctl_serval_tcp_ecn = 2;
int sysctl_serval_tcp_dsack = 1;

int sysctl_serval_tcp_stdurg = 0;
int sysctl_serval_tcp_rfc1337 = 0;
int sysctl_serval_tcp_frto = 2;
int sysctl_serval_tcp_frto_response = 0;
int sysctl_serval_tcp_nometrics_save = 0;

int sysctl_serval_tcp_thin_dupack = 0;

int sysctl_serval_tcp_abc = 0;

int sysctl_serval_tcp_cookie_size = 0; /* TCP_COOKIE_MAX */

/* tcp_ipv4.c */

int sysctl_serval_tcp_tw_reuse = 0;

unsigned int gso = 0;
