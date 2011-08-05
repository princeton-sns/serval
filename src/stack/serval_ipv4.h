#ifndef _SERVAL_IPV4_H_
#define _SERVAL_IPV4_H_

#include <serval/skbuff.h>

#if defined(OS_LINUX_KERNEL)
#include <net/ip.h>

struct dst_entry *serval_ipv4_req_route(struct sock *sk,
					struct request_sock *rsk,
					int protocol,
					u32 saddr,
					u32 daddr);
#endif

#define SERVAL_DEFTTL 64

int serval_ipv4_forward_out(struct sk_buff *skb);

int serval_ipv4_build_and_send_pkt(struct sk_buff *skb, struct sock *sk,
				   u32 saddr, u32 daddr, 
				   struct ip_options *opt);
int serval_ipv4_xmit_skb(struct sk_buff *skb);

const char *ipv4_hdr_dump(const void *hdr, char *buf, int buflen);

#endif /* _SERVAL_IPV4_H_ */
