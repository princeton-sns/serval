#ifndef _SERVAL_IPV4_H_
#define _SERVAL_IPV4_H_

#include <serval/skbuff.h>

#if defined(OS_LINUX_KERNEL)
#include <net/ip.h>

struct dst_entry *serval_ipv4_req_route(struct sock *sk,
					struct request_sock *rsk,
					int protocol,
					uint32_t saddr,
					uint32_t daddr);
#endif

#define SERVAL_DEFTTL 64

int serval_ipv4_build_and_send_pkt(struct sk_buff *skb, struct sock *sk,
				   uint32_t saddr, uint32_t daddr, 
				   struct ip_options *opt);
int serval_ipv4_xmit_skb(struct sk_buff *skb);

#endif /* _SERVAL_IPV4_H_ */
