/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/platform.h>
#include <scaffold/platform_tcpip.h>
#include <scaffold/skbuff.h>
#include <scaffold/debug.h>
#include <scaffold_sock.h>
#include <scaffold/netdevice.h>
#include <scaffold_srv.h>
#include <scaffold_ipv4.h>
#include <netinet/scaffold.h>
#if defined(OS_LINUX_KERNEL)
#include <linux/if_ether.h>
#elif !defined(OS_ANDROID)
#include <netinet/if_ether.h>
#endif
#include "service.h"

extern int scaffold_tcp_rcv(struct sk_buff *);
extern int scaffold_udp_rcv(struct sk_buff *);

static int scaffold_srv_syn_rcv(struct sk_buff *skb)
{
        struct sock *sk;
        struct scaffold_request_sock *rsk;
        struct scaffold_hdr *sfh = 
                (struct scaffold_hdr *)skb_transport_header(skb);        
        struct scaffold_service_ext *srv_ext = 
                (struct scaffold_service_ext *)(sfh + 1);
        unsigned int hdr_len = ntohs(sfh->length);
        int err = 0;
        
        if (hdr_len <= sizeof(struct scaffold_hdr))
                goto drop;
        
        if (srv_ext->type != SCAFFOLD_SERVICE_EXT)
                goto drop;
        
        /* Cache this service FIXME: should not assume ETH_ALEN here. */
        err = service_add(&srv_ext->src_srvid, sizeof(srv_ext->src_srvid), 
                          skb->dev, 
                          SCAFFOLD_SKB_CB(skb)->hard_addr, 
                          ETH_ALEN, GFP_ATOMIC);
        
        if (err < 0) {
                LOG_ERR("could not cache service for incoming packet\n");
        }
        
        sk = scaffold_sock_lookup_serviceid(&srv_ext->dst_srvid);
        
        if (!sk) {
                LOG_ERR("No matching scaffold sock\n");
                err = -1;
                goto drop;
        }

        bh_lock_sock(sk);
        
        if (sk->sk_ack_backlog >= sk->sk_max_ack_backlog) 
                goto drop_unlock;
        
        err = scaffold_sk(sk)->af_ops->conn_request(sk, skb);
        
        if (err < 0)
                goto drop_unlock;

        rsk = scaffold_rsk_alloc(GFP_ATOMIC);

        if (!rsk) {
                bh_unlock_sock(sk);
                return -ENOMEM;
        }
        
        list_add(&rsk->lh, &scaffold_sk(sk)->syn_queue);
        
        SCAFFOLD_SKB_CB(skb)->pkttype = SCAFFOLD_PKT_SYNACK;

        /* Push back the Scaffold header again to make IP happy */
        skb_push(skb, hdr_len);
        skb_reset_transport_header(skb);

        memcpy(&sfh->dst_sid, &sfh->src_sid, sizeof(sfh->src_sid));
        memcpy(&scaffold_sk(sk)->peer_sockid, &sfh->src_sid, sizeof(sfh->src_sid));
        memcpy(&sfh->src_sid, &scaffold_sk(sk)->local_sockid, 
               sizeof(scaffold_sk(sk)->local_sockid));

        memcpy(&scaffold_sk(sk)->peer_srvid, &srv_ext->src_srvid, 
               sizeof(srv_ext->src_srvid));
        err = scaffold_ipv4_build_and_send_pkt(skb, sk, 
                                               ip_hdr(skb)->saddr, NULL);
        
drop_unlock:
        bh_unlock_sock(sk);
drop:
        return err;
}

int scaffold_srv_rcv(struct sk_buff *skb)
{
        //struct sock *sk = NULL;
        struct scaffold_hdr *sfh = 
                (struct scaffold_hdr *)skb_transport_header(skb);
        unsigned int hdr_len = ntohs(sfh->length);
        int err = 0;

        if (!pskb_may_pull(skb, hdr_len))
                goto out_error;
        
        pskb_pull(skb, hdr_len);
        skb_reset_transport_header(skb);

        if (hdr_len < sizeof(struct scaffold_hdr))
                goto out_error;
        
        if (sfh->flags & SFH_SYN && sfh->flags & SFH_ACK) {
                /* Connection completed */
                LOG_DBG("SYNACK received\n");
                /* sk = scaffold_sock_lookup_sockid();

                if (!sk) {
                        LOG_ERR("No matching scaffold sock\n");
                        err = -1;
                        goto out_error;
                }
                err = scaffold_sk(sk)->af_ops->conn_request(sk, skb);
                */
                
        } else if (sfh->flags & SFH_SYN) {
                LOG_DBG("SYN received\n");
                err = scaffold_srv_syn_rcv(skb);
        } else if (sfh->flags & SFH_FIN) {

        } else {
                /* Data packet */
                switch (sfh->protocol) {
                case IPPROTO_UDP:
                        err = scaffold_udp_rcv(skb);
                        break;
                case IPPROTO_TCP:
                        err = scaffold_tcp_rcv(skb);
                        break;
                default:
                        LOG_ERR("unsupported protocol=%u\n", sfh->protocol);
                        err = -1;
                        goto out_error;
                }
        }

	return err;
out_error:
        FREE_SKB(skb);
        return err;
}

#define EXTRA_HDR (20)
#define SCAFFOLD_MAX_HDR (MAX_HEADER + 20 +                             \
                          sizeof(struct scaffold_hdr) +                 \
                          sizeof(struct scaffold_service_ext) +         \
                          EXTRA_HDR)
/*
int scaffold_srv_connect(struct sock *sk, struct sk_buff *skb)
{
        struct scaffold_sock *ssk = scaffold_sk(sk);
        struct scaffold_hdr *sfh;
        struct scaffold_service_ext *srvext;
        struct sk_buff *skb;
        
        skb = ALLOC_SKB(SCAFFOLD_MAX_HDR, sk->sk_allocation);
        
        if (!skb)
                return -ENOBUFS;
        
	skb_set_owner_w(skb, sk);
        skb_reserve(skb, SCAFFOLD_MAX_HDR);

        srvext = (struct scaffold_service_ext *)skb_push(skb, sizeof(struct scaffold_service_ext));
        
        sfh = (struct scaffold_hdr *)skb_push(skb, sizeof(struct scaffold_hdr));
        
        memcpy(&sfh->dst_sid, &ssk->sockid, sizeof(ssk->sockid));
        SCAFFOLD_SKB_CB(skb)->pkttype = SCAFFOLD_PKT_DATA;
        
        FREE_SKB(skb);

        return 0;
}
*/

int scaffold_srv_xmit_skb(struct sock *sk, struct sk_buff *skb)
{
        struct scaffold_sock *ssk = scaffold_sk(sk);
	struct service_entry *se;
	struct net_device *dev;
        struct scaffold_hdr *sfh;
        struct scaffold_service_ext *srvext;
	int err = 0;

        srvext = (struct scaffold_service_ext *)skb_push(skb, sizeof(struct scaffold_service_ext));

        /* Add Scaffold service extension */
        srvext->type = SCAFFOLD_SERVICE_EXT;
        srvext->length = htons(sizeof(struct scaffold_service_ext));
        srvext->flags = 0;

        memcpy(&srvext->src_srvid, &ssk->local_srvid, sizeof(ssk->local_srvid));
        memcpy(&srvext->dst_srvid, &SCAFFOLD_SKB_CB(skb)->srvid, 
               sizeof(SCAFFOLD_SKB_CB(skb)->srvid));

        /* Add Scaffold header */
        sfh = (struct scaffold_hdr *)skb_push(skb, sizeof(struct scaffold_hdr));
        sfh->flags = 0;
        sfh->protocol = skb->protocol;
        sfh->length = htons(sizeof(struct scaffold_service_ext) + 
                            sizeof(struct scaffold_hdr));
        memcpy(&sfh->src_sid, &ssk->local_sockid, sizeof(ssk->local_sockid));
        memcpy(&sfh->src_sid, &ssk->peer_sockid, sizeof(ssk->peer_sockid));

	if (sk->sk_state == SCAFFOLD_CONNECTED) {
		err = scaffold_ipv4_xmit_skb(sk, skb);
                
		if (err < 0) {
			LOG_ERR("xmit failed\n");
			FREE_SKB(skb);
		}
		return err;
	}

	/* Unresolved packet, use service id */
	se = service_find(&SCAFFOLD_SKB_CB(skb)->srvid);
	
	if (!se) {
		LOG_ERR("service lookup failed\n");
		FREE_SKB(skb);
		return -EADDRNOTAVAIL;
	}
        
        skb->protocol = IPPROTO_SCAFFOLD;
        /* 
           Send on all interfaces listed for this service.
        */
	service_entry_dev_iterate_begin(se);
	
	dev = service_entry_dev_next(se);
	
	while (dev) {
		struct sk_buff *cskb;
		struct net_device *next_dev;
		
                LOG_DBG("tx dev=%s\n", dev->name);

		/* Remember the hardware destination */
		service_entry_dev_dst(se, SCAFFOLD_SKB_CB(skb)->hard_addr, 6);

		next_dev = service_entry_dev_next(se);
		
                if (next_dev == NULL) {
			cskb = skb;
		} else {
			cskb = skb_clone(skb, current ? 
					 GFP_KERNEL : GFP_ATOMIC);
			
			if (!cskb) {
				LOG_ERR("Allocation failed\n");
				FREE_SKB(skb);
				break;
			}
		}
                
		/* Set the output device */
		skb_set_dev(cskb, dev);

		err = scaffold_ipv4_xmit_skb(sk, cskb);
                
		if (err < 0) {
			LOG_ERR("xmit failed\n");
			FREE_SKB(cskb);
			break;
		}
		dev = next_dev;
	}
	
	service_entry_dev_iterate_end(se);
	service_entry_put(se);

	return err;
}

