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

int scaffold_srv_rcv(struct sk_buff *skb)
{
        struct sock *sk;
	struct service_id *srvid_src = NULL;
        struct service_id *srvid_dst = NULL;
        unsigned char pkt_type = ip_hdr(skb)->tos;
	unsigned char protocol = ip_hdr(skb)->protocol;
	int err = 0;

        switch (protocol) {
        case IPPROTO_UDP:
        {
                struct udphdr *udph = udp_hdr(skb);
                srvid_src = (struct service_id *)&udph->source;
                srvid_dst = (struct service_id *)&udph->dest;
                break;
        }
        case IPPROTO_TCP:
        {
                struct tcphdr *tcph = tcp_hdr(skb);
                srvid_src = (struct service_id *)&tcph->source;
                srvid_dst = (struct service_id *)&tcph->dest;
                break;
        }
        default:
                LOG_ERR("unsupported protocol=%u\n", protocol);
                err = -1;
                goto out_error;
        }

	/* Cache this service FIXME: should not assume ETH_ALEN here. */
	err = service_add(srvid_src, sizeof(*srvid_src), skb->dev, 
			  SCAFFOLD_SKB_CB(skb)->hard_addr, 
                          ETH_ALEN, GFP_ATOMIC);

	if (err < 0) {
		LOG_ERR("could not cache service for incoming packet\n");
	}

        switch (pkt_type) {
        case SCAFFOLD_PKT_SYN:
                LOG_DBG("SYN received\n");
                sk = scaffold_sock_lookup_serviceid(srvid_dst);

                if (!sk) {
                        LOG_ERR("No matching scaffold sock\n");
                        err = -1;
                        goto out_error;
                }
                err = scaffold_sk(sk)->af_ops->conn_request(sk, skb);
                break;
        case SCAFFOLD_PKT_SYNACK:
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
                break;
        case SCAFFOLD_PKT_DATA:
                switch (protocol) {
                case IPPROTO_UDP:
                        err = scaffold_udp_rcv(skb);
                        break;
                case IPPROTO_TCP:
                        err = scaffold_tcp_rcv(skb);
                        break;
                default:
                        LOG_ERR("unsupported protocol=%u\n", protocol);
                        err = -1;
                        goto out_error;
                }
                break;
        default:
                LOG_ERR("unknown packet type %u\n", pkt_type);
                FREE_SKB(skb);
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

int scaffold_srv_connect(struct sock *sk)
{
        //struct scaffold_sock *ssk = scaffold_sk(sk);
        struct scaffold_service_ext *srvext;
        struct sk_buff *skb;
        
        skb = ALLOC_SKB(SCAFFOLD_MAX_HDR, sk->sk_allocation);
        
        if (!skb)
                return -ENOBUFS;
        
	skb_set_owner_w(skb, sk);
        skb_reserve(skb, SCAFFOLD_MAX_HDR);

        srvext = (struct scaffold_service_ext *)skb_push(skb, sizeof(struct scaffold_service_ext));

        SCAFFOLD_SKB_CB(skb)->pkttype = SCAFFOLD_PKT_DATA;
        
        FREE_SKB(skb);

        return 0;
}

int scaffold_srv_xmit_skb(struct sock *sk, struct sk_buff *skb)
{
	struct service_entry *se;
	struct net_device *dev;
	int err = 0;

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

