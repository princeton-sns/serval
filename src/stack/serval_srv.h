#ifndef _SERVAL_SRV_H_
#define _SERVAL_SRV_H_

#include <serval/skbuff.h>
#include <serval/sock.h>
#include <netinet/serval.h>

int serval_srv_xmit_skb(struct sk_buff *skb);

struct service_entry;

/* 
   WARNING:
   
   We must be careful that this struct does not overflow the 48 bytes
   that the skb struct gives us in the cb field.

   NOTE: Currently adds up to 48 bytes (non packed) on 64-bit platform.
   Should probably find another solution for storing a reference to
   the service id instead of a copy.
*/
struct serval_skb_cb {
        enum serval_packet_type pkttype;
	struct net_addr dst_addr;
        struct service_entry *se;
        struct service_id srvid;
};

static inline struct serval_skb_cb *__serval_skb_cb(struct sk_buff *skb)
{
	struct serval_skb_cb * sscb = 
		(struct serval_skb_cb *)&(skb)->cb[0];
	return sscb;
}

#define SERVAL_SKB_CB(__skb) __serval_skb_cb(__skb)

int serval_srv_do_rcv(struct sock *sk, struct sk_buff *skb);
void serval_srv_rexmit_timeout(unsigned long data);

#endif /* _SERVAL_SRV_H_ */
