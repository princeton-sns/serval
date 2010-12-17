#ifndef _SCAFFOLD_SRV_H_
#define _SCAFFOLD_SRV_H_

#include <scaffold/skbuff.h>
#include <scaffold/sock.h>
#include <netinet/scaffold.h>

int scaffold_srv_xmit_skb(struct sock *sk, struct sk_buff *skb);

struct service_entry;

/* 
   WARNING:
   
   We must be careful that this struct does not overflow the 48 bytes
   that the skb struct gives us in the cb field.

*/
struct scaffold_skb_cb {
        enum scaffold_packet_type pkttype;
        struct service_id srvid;
        struct service_entry *se;
        unsigned char hard_addr[];
};

static inline struct scaffold_skb_cb *__scaffold_skb_cb(struct sk_buff *skb)
{
	struct scaffold_skb_cb * sscb = 
		(struct scaffold_skb_cb *)&(skb)->cb[0];
	return sscb;
}

#define SCAFFOLD_SKB_CB(__skb) __scaffold_skb_cb(__skb)

#endif /* _SCAFFOLD_SRV_H_ */
