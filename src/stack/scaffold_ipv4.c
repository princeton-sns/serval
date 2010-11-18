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
	char srcstr[18];
       
	LOG_DBG("received IPv4 packet from %s hdr_len=%u prot=%u\n",
		inet_ntop(AF_INET, &iph->saddr, srcstr, 18), 
		hdr_len, iph->protocol);

        /* Check if this is not a SCAFFOLD packet */
        if (1 /* !is_scaffold_packet */)
                return INPUT_DELIVER;

        if (!pskb_may_pull(skb, hdr_len))
                goto inhdr_error;
        
        skb_pull(skb, hdr_len);

	skb_reset_transport_header(skb);

	switch (iph->protocol) {
	case IPPROTO_ICMP:
		LOG_DBG("icmp packet\n");
                ret = INPUT_DELIVER;
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
inhdr_error:
        return INPUT_DROP;

}
