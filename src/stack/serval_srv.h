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

*/
struct serval_skb_cb {
        enum serval_packet_type pkttype;
        struct service_id srvid;
        struct service_entry *se;
	struct flow_id dst_flowid;
        unsigned char hard_addr[];
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
