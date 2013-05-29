/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Generic segmentation offloading for Serval.
 *
 * NOTE: This code is experimental and is currently not in a working state.
 */
#include <linux/skbuff.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/ip.h>
#include <netinet/serval.h>
#include <serval_tcp.h>
#include <serval_sal.h>

struct sk_buff *serval_tcp4_tso_segment(struct sk_buff *skb,
				       netdev_features_t features)
{
        const struct iphdr *iph = ip_hdr(skb);
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	struct sal_hdr *sh;
	unsigned int sal_length;
        unsigned int n = 1;

	if (!pskb_may_pull(skb, SAL_HEADER_LEN))
		goto out;

        sh = (struct sal_hdr *)((char *)iph + (iph->ihl << 2));
        sal_length = sh->shl << 2;

        LOG_DBG("sal_length=%u protocol=%u\n", sal_length, sh->protocol);

	if (!pskb_may_pull(skb, sal_length))
                goto out;

	segs = ERR_PTR(-EPROTONOSUPPORT);

        /* Can only handle TCP at this point. */
        if (sh->protocol != IPPROTO_TCP)
                goto out;

        LOG_DBG("doing offloading\n");

	__skb_pull(skb, sal_length);
        skb_reset_transport_header(skb);

        /* Force complete checksum computation since the hardware does
           not know what to do with Serval packets */
        //skb->ip_summed = CHECKSUM_NONE;
        /* Should implement a lookup table for different Serval
           transport protocols. But at this time we only support
           TCP. */
        segs = tcp_tso_segment(skb, features);

	if (!segs || IS_ERR(segs))
		goto out;
        
        skb = segs;
        
        /* Ok, skb is segmented. Now we need to fix up the headers in
           each segment. */
        do {
                struct tcphdr *th;
                unsigned long len;

                /* skb->data is at mac header */
                iph = ip_hdr(skb);
                sh = (struct sal_hdr *)((char *)iph + (iph->ihl << 2));
                sal_length = sh->shl << 2;
                th = tcp_hdr(skb);
                /*
                LOG_DBG("tcphdr source=%u dest=%u doff=%u "
                        "iph->len=%u sal_len=%u "
                        "skb->data=%p mac=%p iph=%p sh=%p th=%p\n", 
                        th->source, th->dest, th->doff << 2, 
                        ntohs(iph->tot_len), sal_length,
                        skb->data, skb_mac_header(skb), iph, sh, th);
                */
                len = skb->len - ((unsigned char *)th - skb->data);
                
                skb->ip_summed = CHECKSUM_NONE;
                th->check = 0;
                th->check = serval_tcp_v4_check(len, iph->saddr, iph->daddr,
                                                csum_partial(th, len, 0));
                
                /* Do we need to fixup anything here? SAL base header
                   should probably be fine if it is just a
                   duplicate. An exception is control extensions that
                   shouldn't be duplicates. On the other hand, these
                   will simply be ignored due to invalid seqnos. In
                   most cases, we do not even piggy-back control
                   extensions on transport data packets, so this
                   problem won't occur often (if at all) in
                   practice. */

                LOG_DBG("segment %u skb->len=%lu len=%lu th->check=%u\n", 
                        n++, skb->len, len, th->check);
	} while ((skb = skb->next));
out:
	return segs;
}

static int serval_tcp4_gso_send_check(struct sk_buff *skb)
{
	const struct iphdr *iph;
        struct sal_hdr *sh;
	struct tcphdr *th;
        unsigned int sal_len;

	iph = ip_hdr(skb);

	if (!pskb_may_pull(skb, SAL_HEADER_LEN))
		return -EINVAL;

        sh = (struct sal_hdr *)((char *)iph + (iph->ihl << 2));
        sal_len = sh->shl << 2;

	if (!pskb_may_pull(skb, sal_len))
		return -EINVAL;

        if (sh->protocol != IPPROTO_TCP)
                return -EPROTONOSUPPORT;

        LOG_DBG("send check\n");

	__skb_pull(skb, sal_len);
        skb_reset_transport_header(skb);

        th = tcp_hdr(skb);
	th->check = 0;

	skb->ip_summed = CHECKSUM_PARTIAL;
	__serval_tcp_v4_send_check(skb, iph->saddr, iph->daddr);
	return 0;
}

struct sk_buff **serval_tcp4_gro_receive(struct sk_buff **head, 
                                         struct sk_buff *skb)
{
	const struct iphdr *iph = skb_gro_network_header(skb);    
	struct sk_buff **pp = NULL;
        struct sal_hdr *sh;
	unsigned int hlen, off, sal_len;
	__wsum wsum;
	__sum16 sum;

	off = skb_gro_offset(skb);
	hlen = off + SAL_HEADER_LEN;
	sh = skb_gro_header_fast(skb, off);
	if (skb_gro_header_hard(skb, hlen)) {
		sh = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!sh))
			goto out;
	}
        
        if (sh->protocol != IPPROTO_TCP) {
                LOG_DBG("Not TCP, cannot gro\n");
                goto out;
        }

        sal_len = sh->shl << 2;
	if (sal_len < SAL_HEADER_LEN)
		goto out;

	hlen = off + sal_len;
	if (skb_gro_header_hard(skb, hlen)) {
		sh = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!sh))
			goto out;
	}

	skb_gro_pull(skb, sal_len);
	skb_set_transport_header(skb, skb_gro_offset(skb));

	switch (skb->ip_summed) {
	case CHECKSUM_COMPLETE:
		if (!serval_tcp_v4_check(skb_gro_len(skb), iph->saddr, 
                                         iph->daddr,
                                         skb->csum)) {
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			break;
		}
flush:
		NAPI_GRO_CB(skb)->flush = 1;
		return NULL;

	case CHECKSUM_NONE:
		wsum = csum_tcpudp_nofold(iph->saddr, iph->daddr,
					  skb_gro_len(skb), IPPROTO_TCP, 0);
		sum = csum_fold(skb_checksum(skb,
					     skb_gro_offset(skb),
					     skb_gro_len(skb),
					     wsum));
		if (sum)
			goto flush;

		skb->ip_summed = CHECKSUM_UNNECESSARY;
		break;
	}

        pp = tcp_gro_receive(head, skb);
 out:
        return pp;
}

int serval_tcp4_gro_complete(struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
        struct sal_hdr *sh;        
        struct tcphdr *th;
	unsigned int sal_length;

	if (!pskb_may_pull(skb, SAL_HEADER_LEN))
		return -EINVAL;

	sh = sal_hdr(skb);
        sal_length = sh->shl << 2;

	if (!pskb_may_pull(skb, sal_length))
                return -EINVAL;

        __skb_pull(skb, sal_length);
        skb_reset_transport_header(skb);
        th = tcp_hdr(skb);
        //unsigned long len = skb_tail_pointer(skb) - skb_transport_header(skb);

        th->check = ~serval_tcp_v4_check(skb->len - skb_transport_offset(skb),
                                         iph->saddr, iph->daddr, 0);
	skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;

	return tcp_gro_complete(skb);
}

static const struct net_offload serval_tcp_offload = {
	.callbacks = {
		.gso_send_check	=	serval_tcp4_gso_send_check,
		.gso_segment	=	serval_tcp4_tso_segment,
		.gro_receive	=	serval_tcp4_gro_receive,
		.gro_complete	=	serval_tcp4_gro_complete,
	},
};

int __init serval_tcp_offload_init(void)
{
	/*
	 * Add offloads
	 */
        return inet_add_offload(&serval_tcp_offload, IPPROTO_SERVAL);  
}

void __exit serval_tcp_offload_fini(void)
{
        inet_del_offload(&serval_tcp_offload, IPPROTO_SERVAL);
}

