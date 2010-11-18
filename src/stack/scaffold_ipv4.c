/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/platform.h>
#include <scaffold/skbuff.h>
#include <scaffold_sock.h>
#include <input.h>

extern int scaffold_tcp_rcv(struct sk_buff *);
extern int scaffold_udp_rcv(struct sk_buff *);

int scaffold_ipv4_rcv(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	unsigned int hdr_len = iph->ihl << 2;
	int ret = INPUT_OK;
#if !defined(__KERNEL__)
	char srcstr[18];
       
	LOG_DBG("received scaffold packet from %s hdr_len=%u prot=%u\n",
		inet_ntop(AF_INET, &iph->saddr, srcstr, 18), 
		hdr_len, iph->protocol);
#endif

	skb_set_transport_header(skb, hdr_len);

	switch (iph->protocol) {
	case IPPROTO_ICMP:
		LOG_DBG("icmp packet\n");
		break;
	case IPPROTO_UDP:
                ret = scaffold_udp_rcv(skb);
		break;
	case IPPROTO_TCP:
                ret = scaffold_tcp_rcv(skb);
		break;
	default:
		LOG_DBG("packet type=%u\n", iph->protocol);
	}

	return ret;
}
