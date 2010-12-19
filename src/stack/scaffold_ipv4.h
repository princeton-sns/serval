#ifndef _SCAFFOLD_IPV4_H_
#define _SCAFFOLD_IPV4_H_

#include <scaffold/skbuff.h>

#if defined(OS_LINUX_KERNEL)
#include <net/ip.h>
#else
struct ipcm_cookie {
	uint32_t		addr;
	int			oif;
	/* 
	   struct ip_options	*opt;
	union skb_shared_tx	shtx;
	*/
};
struct ip_options {
	int dummy;
};
#endif

uint16_t in_cksum(const void *data, size_t len);
int scaffold_ipv4_fill_in_hdr(struct sock *sk, struct sk_buff *skb, 
			      struct ipcm_cookie *ipcm);
int scaffold_ipv4_build_and_send_pkt(struct sk_buff *skb, struct sock *sk,
				     uint32_t daddr, 
                                     struct ip_options *opt);
int scaffold_ipv4_xmit_skb(struct sock *sk, struct sk_buff *skb);

#endif /* _SCAFFOLD_IPV4_H_ */
