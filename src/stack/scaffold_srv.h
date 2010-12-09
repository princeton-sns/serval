#ifndef _SCAFFOLD_SRV_H_
#define _SCAFFOLD_SRV_H_

#include <scaffold/skbuff.h>
#include <scaffold/sock.h>

int scaffold_srv_xmit_skb(struct sock *sk, struct sk_buff *skb);

#endif /* _SCAFFOLD_SRV_H_ */
