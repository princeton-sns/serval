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
#if defined(OS_USER)
#include <signal.h>
#endif
#include <scaffold_request_sock.h>
#include <service.h>
#include <neighbor.h>

extern int scaffold_tcp_rcv(struct sk_buff *);
extern int scaffold_udp_rcv(struct sk_buff *);
extern atomic_t scaffold_nr_socks;

static int scaffold_srv_state_process(struct sock *sk, 
                                      struct scaffold_hdr *sfh, 
                                      struct sk_buff *skb);
        
static int scaffold_srv_syn_rcv(struct sock *sk, 
                                struct scaffold_hdr *sfh,
                                struct sk_buff *skb)
{
        struct scaffold_sock *ssk = scaffold_sk(sk);
        struct scaffold_request_sock *rsk;
        struct scaffold_service_ext *srv_ext = 
                (struct scaffold_service_ext *)(sfh + 1);
        unsigned int hdr_len = ntohs(sfh->length);
        int err = 0;
        
        /* Cache this service. FIXME, need to garbage this entry at
         * some point so that we aren't always redirected to same
         * instance. */
       
        err = service_add(&srv_ext->src_srvid, sizeof(srv_ext->src_srvid) * 8, 
                          skb->dev, &ip_hdr(skb)->saddr, 4, GFP_ATOMIC);
        
        if (err < 0) {
                LOG_ERR("could not cache service for incoming packet\n");
        }
        
        /* Cache neighbor */
        neighbor_add((struct flow_id *)&ip_hdr(skb)->saddr, 32, 
                     skb->dev, eth_hdr(skb)->h_source, 
                     ETH_ALEN, GFP_ATOMIC);
        
        if (sk->sk_ack_backlog >= sk->sk_max_ack_backlog) 
                goto drop;

        /* Call upper protocol handler */
        err = ssk->af_ops->conn_request(sk, skb);
        
        if (err < 0)
                goto drop;

        rsk = scaffold_rsk_alloc(GFP_ATOMIC);

        if (!rsk) {
                err = -ENOMEM;
                goto drop;
        }
        
        /* Copy fields in request packet into request sock */
        memcpy(&rsk->peer_sockid, &sfh->src_sid, 
               sizeof(sfh->src_sid));
        memcpy(&rsk->peer_srvid, &srv_ext->src_srvid,            
               sizeof(srv_ext->src_srvid));
        memcpy(&rsk->dst_flowid, &ip_hdr(skb)->saddr,
               sizeof(rsk->dst_flowid));
        
        list_add(&rsk->lh, &ssk->syn_queue);
        
        SCAFFOLD_SKB_CB(skb)->pkttype = SCAFFOLD_PKT_SYNACK;

        /* Push back the Scaffold header again to make IP happy */
        skb_push(skb, hdr_len);
        skb_reset_transport_header(skb);
        
        /* Update info in packet */
        memcpy(&sfh->dst_sid, &sfh->src_sid, 
               sizeof(sfh->src_sid));
        memcpy(&sfh->src_sid, &rsk->local_sockid, 
               sizeof(rsk->local_sockid));
        memcpy(&srv_ext->dst_srvid, &rsk->peer_srvid,            
               sizeof(rsk->peer_srvid));
        
        sfh->flags |= SFH_ACK;
        skb->protocol = IPPROTO_SCAFFOLD;

        err = scaffold_ipv4_build_and_send_pkt(skb, sk, 
                                               ip_hdr(skb)->saddr, NULL);
done:        
        return err;
drop:
        FREE_SKB(skb);
        goto done;
}

static struct sock *
scaffold_srv_request_sock_handle(struct sock *sk,
                                 struct scaffold_hdr *sfh,
                                 struct sk_buff *skb)
{

        struct scaffold_sock *ssk = scaffold_sk(sk);
        struct scaffold_request_sock *rsk;

        list_for_each_entry(rsk, &ssk->syn_queue, lh) {
                if (memcmp(&rsk->local_sockid, &sfh->dst_sid, 
                           sizeof(rsk->local_sockid)) == 0) {
                        struct sock *nsk;
                        struct scaffold_sock *nssk;

                        /* Move request sock to accept queue */
                        list_del(&rsk->lh);
                        list_add_tail(&rsk->lh, &ssk->accept_queue);
                        
                        nsk = ssk->af_ops->conn_child_sock(sk, skb, 
                                                           rsk, NULL);
                        
                        if (!nsk)
                                return NULL;
                        
                        atomic_inc(&scaffold_nr_socks);
                        nsk->sk_state = SCAFFOLD_RESPOND;
                        nssk = scaffold_sk(nsk);
                        memcpy(&nssk->local_sockid, &rsk->local_sockid, 
                               sizeof(rsk->local_sockid));
                        memcpy(&nssk->peer_sockid, &rsk->peer_sockid, 
                               sizeof(rsk->peer_sockid));
                        memcpy(&nssk->peer_srvid, &rsk->peer_srvid,
                               sizeof(rsk->peer_srvid));
                        memcpy(&nssk->dst_flowid, &rsk->dst_flowid,
                               sizeof(rsk->dst_flowid));
                         
                        rsk->sk = nsk;

                        /* Hash the sock to make it available */
                        nsk->sk_prot->hash(nsk);

                        return nsk;
                }
        }
        
        return sk;
}

static void scaffold_srv_fin(struct sock *sk, struct scaffold_hdr *sfh,
                             struct sk_buff *skb)
{
        sk->sk_shutdown |= SEND_SHUTDOWN;
        sock_set_flag(sk, SOCK_DONE);

        LOG_DBG("received FIN\n");

        switch (sk->sk_state) {
        case SCAFFOLD_REQUEST:
        case SCAFFOLD_RESPOND:
        case SCAFFOLD_CONNECTED:
                scaffold_sock_set_state(sk, SCAFFOLD_CLOSEWAIT);
                break;
        case SCAFFOLD_CLOSING:
                break;
        case SCAFFOLD_CLOSEWAIT:
                break;
        default:
                break;
        }
}

static int scaffold_srv_connected_state_process(struct sock *sk, 
                                                struct scaffold_hdr *sfh,
                                                struct sk_buff *skb)
{
        struct scaffold_sock *ssk = scaffold_sk(sk);
        int err = 0;
        
        if (sfh->flags & SFH_FIN) {
                SCAFFOLD_SKB_CB(skb)->pkttype = SCAFFOLD_PKT_CLOSE;
                scaffold_srv_fin(sk, sfh, skb);
        } else {
                SCAFFOLD_SKB_CB(skb)->pkttype = SCAFFOLD_PKT_DATA;
        }

        err = ssk->af_ops->receive(sk, skb);
        
        return err;
}

static int scaffold_srv_child_process(struct sock *parent, struct sock *child,
                                      struct scaffold_hdr *sfh,
                                      struct sk_buff *skb)
{
        int ret = 0;
        int state = child->sk_state;

        scaffold_sk(child)->dev = NULL;
        
        if (!sock_owned_by_user(child)) {
                ret = scaffold_srv_state_process(child, sfh, skb);
                /* Wakeup parent, send SIGIO */
                if (state == SCAFFOLD_RESPOND && child->sk_state != state) {
                        LOG_DBG("waking up parent (listening) sock\n");
                        parent->sk_data_ready(parent, 0);
                }
        } else {
                /* Alas, it is possible again, because we do lookup
                 * in main socket hash table and lock on listening
                 * socket does not protect us more.
                 */
                __sk_add_backlog(child, skb);
        }

        bh_unlock_sock(child);
        sock_put(child);
        LOG_DBG("child refcnt=%d\n", atomic_read(&child->sk_refcnt));
        return ret;
}

static int scaffold_srv_listen_state_process(struct sock *sk,
                                             struct scaffold_hdr *sfh,
                                             struct sk_buff *skb)
{
        int err = 0;                         

        if (sfh->flags & SFH_ACK) {
                /* Processing for socket that has received SYN already */
                struct sock *nsk;
                LOG_DBG("ACK recv\n");

                nsk = scaffold_srv_request_sock_handle(sk, sfh, skb);
                
                if (nsk && nsk != sk) {
                        return scaffold_srv_child_process(sk, nsk, sfh, skb);
                }
                FREE_SKB(skb);
        } else if (sfh->flags & SFH_SYN) {
                LOG_DBG("SYN recv\n");

                err = scaffold_srv_syn_rcv(sk, sfh, skb);
        }

        return err;
}

static int scaffold_srv_request_state_process(struct sock *sk, 
                                              struct scaffold_hdr *sfh,
                                              struct sk_buff *skb)
{
        struct scaffold_sock *ssk = scaffold_sk(sk);
        struct scaffold_service_ext *srv_ext = 
                (struct scaffold_service_ext *)(sfh + 1);        
        unsigned int hdr_len = ntohs(sfh->length);
        int err = 0;
                
        /* Cache neighbor */
        neighbor_add((struct flow_id *)&ip_hdr(skb)->saddr, 32, 
                     skb->dev, eth_hdr(skb)->h_source, 
                     ETH_ALEN, GFP_ATOMIC);
        
        scaffold_sock_set_state(sk, SCAFFOLD_CONNECTED);
        
        /* Let app know we are connected. */
        sk->sk_state_change(sk);
        sk_wake_async(sk, SOCK_WAKE_IO, POLL_OUT);

        /* Save device and peer flow id */
        ssk->dev = skb->dev;
        dev_hold(ssk->dev);
        memcpy(&ssk->dst_flowid, &ip_hdr(skb)->saddr, 
               sizeof(ssk->dst_flowid));

        /* Push back the Scaffold header again to make IP happy */
        skb_push(skb, hdr_len);      
        skb_reset_transport_header(skb);

        /* Trim away the service extension at the end */
        //pskb_trim(skb, sizeof(*srv_ext));
        
        /* Update headers */
        sfh->length = htons(sizeof(*sfh) + sizeof(*srv_ext));
        sfh->flags = 0;
        sfh->flags |= SFH_ACK;
        skb->protocol = IPPROTO_SCAFFOLD;

        /* Fill in socket ids */
        memcpy(&ssk->peer_sockid, &sfh->src_sid, sizeof(sfh->src_sid));
        memcpy(&sfh->src_sid, &ssk->local_sockid, sizeof(sfh->src_sid));
        memcpy(&sfh->dst_sid, &ssk->peer_sockid, sizeof(sfh->dst_sid));

        /* Update service extension header */
        memcpy(&srv_ext->dst_srvid, &ssk->peer_srvid, 
               sizeof(ssk->peer_srvid));
        memcpy(&srv_ext->src_srvid, &ssk->local_srvid, 
               sizeof(ssk->local_srvid));

        err = scaffold_ipv4_build_and_send_pkt(skb, sk, 
                                               ip_hdr(skb)->saddr, NULL);

        if (err < 0)
                goto drop;
                
        return err;
drop:
        FREE_SKB(skb);
        return err;
}

static int scaffold_srv_respond_state_process(struct sock *sk, 
                                              struct scaffold_hdr *sfh,
                                              struct sk_buff *skb)
{
        struct scaffold_sock *ssk = scaffold_sk(sk);
        int err = 0;

        /* TODO: check packet, allow data. */
        scaffold_sock_set_state(sk, SCAFFOLD_CONNECTED);

        LOG_DBG("\n");

        /* Save device and peer flow id */
        ssk->dev = skb->dev;
        dev_hold(ssk->dev);
        memcpy(&ssk->dst_flowid, &ip_hdr(skb)->saddr, 
               sizeof(ssk->dst_flowid));

        FREE_SKB(skb);

        return err;
}

int scaffold_srv_state_process(struct sock *sk, 
                               struct scaffold_hdr *sfh, 
                               struct sk_buff *skb)
{
        int err = 0;

        switch (sk->sk_state) {
        case SCAFFOLD_CONNECTED:
                err = scaffold_srv_connected_state_process(sk, sfh, skb);
                break;
        case SCAFFOLD_REQUEST:
                err = scaffold_srv_request_state_process(sk, sfh, skb);
                break;
        case SCAFFOLD_RESPOND:
                err = scaffold_srv_respond_state_process(sk, sfh, skb);
                break;
        case SCAFFOLD_LISTEN:
                err = scaffold_srv_listen_state_process(sk, sfh, skb);
                break;
        default:
                LOG_ERR("bad socket state %u\n", sk->sk_state);
                goto drop;
        }

        return err;
drop:
        FREE_SKB(skb);

        return err;

}

int scaffold_srv_do_rcv(struct sock *sk, 
                        struct sk_buff *skb)
{
        struct scaffold_hdr *sfh = 
                (struct scaffold_hdr *)skb_transport_header(skb);
        unsigned int hdr_len = ntohs(sfh->length);
                 
        pskb_pull(skb, hdr_len);
        skb_reset_transport_header(skb);
                
        return scaffold_srv_state_process(sk, sfh, skb);
}

int scaffold_srv_rcv(struct sk_buff *skb)
{
        struct sock *sk = NULL;
        struct scaffold_hdr *sfh = 
                (struct scaffold_hdr *)skb_transport_header(skb);
        unsigned int hdr_len = ntohs(sfh->length);
        int err = 0;

        if (!pskb_may_pull(skb, hdr_len)) {
                LOG_ERR("cannot pull header (hdr_len=%u)\n",
                        hdr_len);
                goto drop;
        }

        if (hdr_len < sizeof(*sfh)) {
                LOG_ERR("header length too short\n");
                goto drop;
        }
        
        LOG_DBG("sockid (src,dst)=(%u,%u)\n", 
                ntohs(sfh->src_sid.s_id), ntohs(sfh->dst_sid.s_id));
       
        /* If SYN and not ACK is set, we know for sure that we must
         * demux on service id instead of socket id */
        if (!(sfh->flags & SFH_SYN && !(sfh->flags & SFH_ACK))) {
                /* Ok, check if we can demux on socket id */
                sk = scaffold_sock_lookup_sockid(&sfh->dst_sid);
        }
        
        if (!sk) {
                /* Try to demux on service id */
                struct scaffold_service_ext *srv_ext = 
                        (struct scaffold_service_ext *)(sfh + 1);

                /* Check for service extension. We require that this
                 * extension always directly follows the main Scaffold
                 * header */
                if (hdr_len <= sizeof(*sfh)) {
                        LOG_ERR("No service extension, too short length\n");
                        goto drop;
                }
                
                if (srv_ext->type != SCAFFOLD_SERVICE_EXT) {
                        LOG_ERR("No service extension, bad extension type\n");
                        goto drop;
                }
                
                sk = scaffold_sock_lookup_serviceid(&srv_ext->dst_srvid);
                
                if (!sk) {
                        LOG_ERR("No matching scaffold sock\n");
                        goto drop;
                }
        }
 
        bh_lock_sock_nested(sk);

        if (!sock_owned_by_user(sk)) {
                err = scaffold_srv_do_rcv(sk, skb);
        } 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
        else {
                sk_add_backlog(sk, skb);
        }
#else
        else if (unlikely(sk_add_backlog(sk, skb))) {
                bh_unlock_sock(sk);
                sock_put(sk);
                goto drop;
        }
#endif
        bh_unlock_sock(sk);
        sock_put(sk);

	return err;
drop:
        FREE_SKB(skb);
        return err;
}

#define EXTRA_HDR (20)
#define SCAFFOLD_MAX_HDR (MAX_HEADER + 20 +                             \
                          sizeof(struct scaffold_hdr) +                 \
                          sizeof(struct scaffold_service_ext) +         \
                          EXTRA_HDR)

static int scaffold_srv_rexmit_skb(struct sk_buff *skb)
{        
        LOG_WARN("not implemented\n");

        return 0;
}

void scaffold_srv_rexmit_timeout(unsigned long data)
{
        struct sock *sk = (struct sock *)data;
        int err;

        err = scaffold_srv_rexmit_skb(skb_peek(&sk->sk_write_queue));

        sock_put(sk);
}

int scaffold_srv_xmit_skb(struct sk_buff *skb)
{
        struct sock *sk = skb->sk;
        struct scaffold_sock *ssk = scaffold_sk(sk);
	struct service_entry *se;
	struct net_device *dev;
        struct scaffold_hdr *sfh;
        struct scaffold_service_ext *srv_ext;
        uint8_t flags = 0;
        int hdr_len = sizeof(*sfh);
	int err = 0;

        /* Add appropriate flags and headers */
        switch (SCAFFOLD_SKB_CB(skb)->pkttype) {
        case SCAFFOLD_PKT_SYNACK:
                flags |= SFH_ACK;
        case SCAFFOLD_PKT_SYN:
                flags |= SFH_SYN;
                srv_ext = (struct scaffold_service_ext *)skb_push(skb, sizeof(*srv_ext));
                srv_ext->type = SCAFFOLD_SERVICE_EXT;
                srv_ext->length = htons(sizeof(*srv_ext));
                srv_ext->flags = 0;                
                memcpy(&srv_ext->src_srvid, &ssk->local_srvid, 
                       sizeof(ssk->local_srvid));
                memcpy(&srv_ext->dst_srvid, &SCAFFOLD_SKB_CB(skb)->srvid, 
                       sizeof(SCAFFOLD_SKB_CB(skb)->srvid));
                hdr_len += sizeof(*srv_ext);
                break;
        case SCAFFOLD_PKT_ACK:
                flags |= SFH_ACK;
                break;
        case SCAFFOLD_PKT_CLOSE:
                flags |= SFH_FIN;
        default:
                break;
        }

        /* Add Scaffold header */
        sfh = (struct scaffold_hdr *)skb_push(skb, sizeof(*sfh));
        sfh->flags = flags;
        sfh->protocol = skb->protocol;
        sfh->length = htons(hdr_len);
        memcpy(&sfh->src_sid, &ssk->local_sockid, sizeof(ssk->local_sockid));
        memcpy(&sfh->dst_sid, &ssk->peer_sockid, sizeof(ssk->peer_sockid));

        skb->protocol = IPPROTO_SCAFFOLD;
                
	if (sk->sk_state == SCAFFOLD_CONNECTED) {
                if (ssk->dev) {
                        skb_set_dev(skb, ssk->dev);
                        memcpy(&SCAFFOLD_SKB_CB(skb)->dst_flowid,
                               &ssk->dst_flowid, sizeof(ssk->dst_flowid));
                        err = ssk->af_ops->queue_xmit(skb);
                } else {
                        err = -ENODEV;
			FREE_SKB(skb);
                }
		if (err < 0) {
			LOG_ERR("xmit failed\n");
		}
		return err;
	}

        if (SCAFFOLD_SKB_CB(skb)->pkttype == SCAFFOLD_PKT_SYN) {
                sk_reset_timer(sk, &ssk->retransmit_timer, 
                               msecs_to_jiffies(2000));
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
		
                /* Remember the flow destination */
		service_entry_dev_dst(se, &SCAFFOLD_SKB_CB(skb)->dst_flowid,
                                      sizeof(struct flow_id));

		next_dev = service_entry_dev_next(se);
		
                if (next_dev == NULL) {
			cskb = skb;
		} else {
                        /* Always be atomic here since we are holding
                         * socket lock */
                        cskb = skb_clone(skb, GFP_ATOMIC);
			
			if (!cskb) {
				LOG_ERR("Allocation failed\n");
				FREE_SKB(skb);
				break;
			}
		}
                
		/* Set the output device */
		skb_set_dev(cskb, dev);
                
		err = ssk->af_ops->queue_xmit(cskb);
                
		if (err < 0) {
			LOG_ERR("xmit failed\n");
		}
		dev = next_dev;
	}
	
	service_entry_dev_iterate_end(se);
	service_entry_put(se);

	return err;
}

