#ifndef _SCAFFOLD_IPV4_H_
#define _SCAFFOLD_IPV4_H_

#include <scaffold/skbuff.h>

uint16_t in_cksum(const void *data, size_t len);
int scaffold_ipv4_xmit_skb(struct sock *sk, struct sk_buff *skb);

#endif /* _SCAFFOLD_IPV4_H_ */
