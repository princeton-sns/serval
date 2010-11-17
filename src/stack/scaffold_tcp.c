/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/platform.h>
#include <scaffold/debug.h>
#include <scaffold/skbuff.h>
#include <scaffold_tcp_sock.h>
#include <input.h>

#if defined(__KERNEL__)
#include <linux/ip.h>
#include <net/tcp.h>
#else
#include <netinet/ip.h>
#include <netinet/tcp.h>
#endif

int scaffold_tcp_rcv(struct sk_buff *skb)
{
	struct sock *sk;
        struct tcphdr *tcph = tcp_hdr(skb);
        struct sock_id *sockid = (struct sock_id *)&tcph->dest;

        LOG_DBG("tcp packet seq=%lu ack=%lu\n",  
                ntohl(tcph->seq),
                ntohl(tcph->ack_seq));

        sk = scaffold_table_lookup_sockid(sockid);
        
        if (!sk) {
                LOG_ERR("No matching scaffold sock\n");
                return INPUT_NO_SOCK;
        }

        return INPUT_OK;
}
