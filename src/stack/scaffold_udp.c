/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/platform.h>
#include <scaffold/debug.h>
#include <scaffold/skbuff.h>
#include <scaffold_udp_sock.h>
#include <input.h>

#if defined(__KERNEL__)
#include <linux/ip.h>
#include <net/udp.h>
#else
#include <netinet/ip.h>
#include <netinet/udp.h>
#endif

int scaffold_udp_rcv(struct sk_buff *skb)
{
	struct sock *sk;
        struct udphdr *udph = udp_hdr(skb);
        struct sock_id *sockid = (struct sock_id *)&udph->dest;

        LOG_DBG("udp packet len=%u\n", ntohs(udph->len));
        
        sk = scaffold_table_lookup_sockid(sockid);

        if (!sk) {
                LOG_ERR("No matching scaffold sock\n");
                return INPUT_NO_SOCK;
        }

        return INPUT_OK;
}
