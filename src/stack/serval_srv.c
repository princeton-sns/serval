/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/platform.h>
#include <serval/platform_tcpip.h>
#include <serval/skbuff.h>
#include <serval/debug.h>
#include <serval_sock.h>
#include <serval/netdevice.h>
#include <serval_srv.h>
#include <serval_ipv4.h>
#include <netinet/serval.h>
#if defined(OS_LINUX_KERNEL)
#include <linux/if_ether.h>
#elif !defined(OS_ANDROID)
#include <netinet/if_ether.h>
#endif
#if defined(OS_USER)
#include <signal.h>
#endif
#include <serval_request_sock.h>
#include <service.h>
#include <neighbor.h>

extern int serval_tcp_rcv(struct sk_buff *);
extern int serval_udp_rcv(struct sk_buff *);
extern atomic_t serval_nr_socks;

static int serval_srv_state_process(struct sock *sk, 
                                    struct serval_hdr *sfh, 
                                    struct sk_buff *skb);
        

static int has_connection_extension(struct serval_hdr *sfh)
{
        struct serval_connection_ext *conn_ext = 
                (struct serval_connection_ext *)(sfh + 1);
        unsigned int hdr_len = ntohs(sfh->length);

        /* Check for connection extension. We require that this
         * extension always directly follows the main Serval
         * header */
        if (hdr_len < sizeof(*sfh) + sizeof(*conn_ext)) {
                LOG_ERR("No connection extension, hdr_len=%u\n", 
                        hdr_len);
                return 0;
        }
        
        if (conn_ext->type != SERVAL_CONNECTION_EXT) {
                LOG_ERR("No connection extension, bad extension type\n");
                return 0;
        }

        return 1;
}

static int has_control_extension(struct sock *sk, struct serval_hdr *sfh)
{
        struct serval_control_ext *ctrl_ext = 
                (struct serval_control_ext *)(sfh + 1);
        unsigned int hdr_len = ntohs(sfh->length);

        /* Check for control extension. We require that this
         * extension always directly follows the main Serval
         * header */
        if (hdr_len < sizeof(*sfh) + sizeof(*ctrl_ext)) {
                LOG_ERR("No control extension, hdr_len=%u\n", 
                        hdr_len);
                return 0;
        }
        
        if (ctrl_ext->type != SERVAL_CONTROL_EXT) {
                LOG_ERR("No control extension, bad extension type\n");
                return 0;
        }

        if (memcmp(ctrl_ext->nonce, serval_sk(sk)->peer_nonce, 
                   SERVAL_NONCE_SIZE) != 0) {
                LOG_ERR("Control extension has bad nonce\n");
                return 0;
        }

        return 1;
}

static int serval_srv_syn_rcv(struct sock *sk, 
                              struct serval_hdr *sfh,
                              struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_request_sock *rsk;
        struct serval_connection_ext *conn_ext = 
                (struct serval_connection_ext *)(sfh + 1);
        unsigned int hdr_len = ntohs(sfh->length);
        int err = 0;
        
        /* Cache this service. FIXME, need to garbage this entry at
         * some point so that we aren't always redirected to same
         * instance. */
       
        /*
        err = service_add(&conn_ext->src_srvid, sizeof(conn_ext->src_srvid) * 8, 
                          skb->dev, &ip_hdr(skb)->saddr, 4, NULL, GFP_ATOMIC);
        
        if (err < 0) {
                LOG_ERR("could not cache service for incoming packet\n");
        }
        */

        /* Cache neighbor */
        neighbor_add((struct net_addr *)&ip_hdr(skb)->saddr, 32, 
                     skb->dev, eth_hdr(skb)->h_source, 
                     ETH_ALEN, GFP_ATOMIC);
        
        if (sk->sk_ack_backlog >= sk->sk_max_ack_backlog) 
                goto drop;

        /* Call upper protocol handler */
        err = ssk->af_ops->conn_request(sk, skb);
        
        if (err < 0)
                goto drop;

        rsk = serval_rsk_alloc(GFP_ATOMIC);

        if (!rsk) {
                err = -ENOMEM;
                goto drop;
        }
        
        /* Copy fields in request packet into request sock */
        memcpy(&rsk->peer_flowid, &sfh->src_flowid, 
               sizeof(sfh->src_flowid));
        memcpy(&rsk->dst_addr, &ip_hdr(skb)->saddr,
               sizeof(rsk->dst_addr));
        memcpy(rsk->nonce, conn_ext->nonce, SERVAL_NONCE_SIZE);
        {
                char buf[200];
                LOG_DBG("saving nonce %s\n", 
                        hexdump(conn_ext->nonce, 8, buf, 200));
        }
        
        list_add(&rsk->lh, &ssk->syn_queue);
        
        SERVAL_SKB_CB(skb)->pkttype = SERVAL_PKT_SYNACK;

        /* Push back the Serval header again to make IP happy */
        skb_push(skb, hdr_len);
        skb_reset_transport_header(skb);
        
        /* Update info in packet */
        memcpy(&sfh->dst_flowid, &sfh->src_flowid, 
               sizeof(sfh->src_flowid));
        memcpy(&sfh->src_flowid, &rsk->local_flowid, 
               sizeof(rsk->local_flowid));
        memcpy(&conn_ext->srvid, &rsk->peer_srvid,            
               sizeof(rsk->peer_srvid));
        
        /* Copy our nonce to connection extension */
        memcpy(conn_ext->nonce, ssk->local_nonce, SERVAL_NONCE_SIZE);
        {
                char buf[200];
                LOG_DBG("setting nonce %s\n", 
                        hexdump(conn_ext->nonce, 8, buf, 200));
        }
        sfh->flags |= SFH_ACK;
        skb->protocol = IPPROTO_SERVAL;

        err = serval_ipv4_build_and_send_pkt(skb, sk, 
                                             ip_hdr(skb)->saddr, NULL);
done:        
        return err;
drop:
        FREE_SKB(skb);
        goto done;
}

static struct sock *
serval_srv_request_sock_handle(struct sock *sk,
                               struct serval_hdr *sfh,
                               struct sk_buff *skb)
{

        struct serval_sock *ssk = serval_sk(sk);
        struct serval_request_sock *rsk;

        list_for_each_entry(rsk, &ssk->syn_queue, lh) {
                if (memcmp(&rsk->local_flowid, &sfh->dst_flowid, 
                           sizeof(rsk->local_flowid)) == 0) {
                        struct sock *nsk;
                        struct serval_sock *nssk;

                        /* Move request sock to accept queue */
                        list_del(&rsk->lh);
                        list_add_tail(&rsk->lh, &ssk->accept_queue);
                        
                        nsk = ssk->af_ops->conn_child_sock(sk, skb, 
                                                           rsk, NULL);
                        
                        if (!nsk)
                                return NULL;
                        
                        atomic_inc(&serval_nr_socks);
                        nsk->sk_state = SERVAL_RESPOND;
                        nssk = serval_sk(nsk);
                        memcpy(&nssk->local_flowid, &rsk->local_flowid, 
                               sizeof(rsk->local_flowid));
                        memcpy(&nssk->peer_flowid, &rsk->peer_flowid, 
                               sizeof(rsk->peer_flowid));
                        memcpy(&nssk->peer_srvid, &rsk->peer_srvid,
                               sizeof(rsk->peer_srvid));
                        memcpy(&nssk->dst_addr, &rsk->dst_addr,
                               sizeof(rsk->dst_addr));
                        memcpy(nssk->peer_nonce, rsk->nonce, SERVAL_NONCE_SIZE);
                        {
                                char buf[200];
                                LOG_DBG("peer nonce is %s\n", 
                                        hexdump(nssk->peer_nonce, 8, buf, 200));
                        }
                        rsk->sk = nsk;

                        /* Hash the sock to make it available */
                        nsk->sk_prot->hash(nsk);

                        return nsk;
                }
        }
        
        return sk;
}

static void serval_srv_fin(struct sock *sk, struct serval_hdr *sfh,
                           struct sk_buff *skb)
{
        LOG_DBG("received FIN\n");
        
        if (!has_control_extension(sk, sfh)) {
                LOG_DBG("Bad control extension\n");
                FREE_SKB(skb);
                return;
        }
            
        sk->sk_shutdown |= SEND_SHUTDOWN;
        sock_set_flag(sk, SOCK_DONE);

        switch (sk->sk_state) {
        case SERVAL_REQUEST:
        case SERVAL_RESPOND:
        case SERVAL_CONNECTED:
                serval_sock_set_state(sk, SERVAL_CLOSEWAIT);
                break;
        case SERVAL_CLOSING:
                break;
        case SERVAL_CLOSEWAIT:
                break;
        default:
                break;
        }
}

static int serval_srv_connected_state_process(struct sock *sk, 
                                              struct serval_hdr *sfh,
                                              struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;
        
        if (sfh->flags & SFH_FIN) {
                SERVAL_SKB_CB(skb)->pkttype = SERVAL_PKT_CLOSE;
                serval_srv_fin(sk, sfh, skb);
        } else {
                SERVAL_SKB_CB(skb)->pkttype = SERVAL_PKT_DATA;
        }

        err = ssk->af_ops->receive(sk, skb);
        
        return err;
}

static int serval_srv_child_process(struct sock *parent, struct sock *child,
                                    struct serval_hdr *sfh,
                                    struct sk_buff *skb)
{
        int ret = 0;
        int state = child->sk_state;

        serval_sk(child)->dev = NULL;
        
        if (!sock_owned_by_user(child)) {
                ret = serval_srv_state_process(child, sfh, skb);
                /* Wakeup parent, send SIGIO */
                if (state == SERVAL_RESPOND && child->sk_state != state) {
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

static int serval_srv_listen_state_process(struct sock *sk,
                                           struct serval_hdr *sfh,
                                           struct sk_buff *skb)
{
        int err = 0;                         

        if (sfh->flags & SFH_ACK) {
                /* Processing for socket that has received SYN already */
                struct sock *nsk;
                LOG_DBG("ACK recv\n");

                nsk = serval_srv_request_sock_handle(sk, sfh, skb);
                
                if (nsk && nsk != sk) {
                        return serval_srv_child_process(sk, nsk, sfh, skb);
                }
                FREE_SKB(skb);
        } else if (sfh->flags & SFH_SYN) {
                LOG_DBG("SYN recv\n");

                err = serval_srv_syn_rcv(sk, sfh, skb);
        }

        return err;
}

static int serval_srv_request_state_process(struct sock *sk, 
                                            struct serval_hdr *sfh,
                                            struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_connection_ext *conn_ext = 
                (struct serval_connection_ext *)(sfh + 1);        
        unsigned int hdr_len = ntohs(sfh->length);
        int err = 0;
                
        if (!has_connection_extension(sfh)) {
                LOG_ERR("No connection extension\n");
                goto drop;
        }
        
        /* Cache neighbor */
        neighbor_add((struct net_addr *)&ip_hdr(skb)->saddr, 32, 
                     skb->dev, eth_hdr(skb)->h_source, 
                     ETH_ALEN, GFP_ATOMIC);
        
        serval_sock_set_state(sk, SERVAL_CONNECTED);
        
        /* Let app know we are connected. */
        sk->sk_state_change(sk);
        sk_wake_async(sk, SOCK_WAKE_IO, POLL_OUT);

        /* Save device and peer flow id */
        ssk->dev = skb->dev;
        dev_hold(ssk->dev);
        memcpy(&ssk->dst_addr, &ip_hdr(skb)->saddr, 
               sizeof(ssk->dst_addr));

        /* Save nonce */
        memcpy(ssk->peer_nonce, conn_ext->nonce, SERVAL_NONCE_SIZE);

        /* Push back the Serval header again to make IP happy */
        skb_push(skb, hdr_len);      
        skb_reset_transport_header(skb);

        /* Trim away the connection extension at the end */
        //pskb_trim(skb, sizeof(*conn_ext));
        
        /* Update headers */
        sfh->length = htons(sizeof(*sfh) + sizeof(*conn_ext));
        sfh->flags = 0;
        sfh->flags |= SFH_ACK;
        skb->protocol = IPPROTO_SERVAL;

        /* Fill in socket ids */
        memcpy(&ssk->peer_flowid, &sfh->src_flowid, sizeof(sfh->src_flowid));
        memcpy(&sfh->src_flowid, &ssk->local_flowid, sizeof(sfh->src_flowid));
        memcpy(&sfh->dst_flowid, &ssk->peer_flowid, sizeof(sfh->dst_flowid));
      
        /* Update connection extension header */
        memcpy(&conn_ext->srvid, &ssk->peer_srvid, 
               sizeof(ssk->peer_srvid));
        memcpy(conn_ext->nonce, ssk->local_nonce, SERVAL_NONCE_SIZE);

        err = serval_ipv4_build_and_send_pkt(skb, sk, 
                                             ip_hdr(skb)->saddr, NULL);

        if (err < 0)
                goto drop;
                
        return err;
drop:
        FREE_SKB(skb);
        return err;
}

static int serval_srv_respond_state_process(struct sock *sk, 
                                            struct serval_hdr *sfh,
                                            struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_connection_ext *conn_ext = 
                (struct serval_connection_ext *)(sfh + 1);
        int err = 0;

        if (!has_connection_extension(sfh)) {
                LOG_ERR("No connection extension\n");
                goto drop;
        }
        {
                char buf[200];
                LOG_DBG("nonce is %s\n", 
                        hexdump(conn_ext->nonce, 8, buf, 200));
        }
        if (memcmp(conn_ext->nonce, ssk->peer_nonce, 
                   SERVAL_NONCE_SIZE) != 0) {
                LOG_ERR("bad nonce in connection extension\n");
                goto drop;
        }
        /* TODO: check packet, allow data. */
        serval_sock_set_state(sk, SERVAL_CONNECTED);

        LOG_DBG("\n");

        /* Save device and peer flow id */
        ssk->dev = skb->dev;
        dev_hold(ssk->dev);
        memcpy(&ssk->dst_addr, &ip_hdr(skb)->saddr, 
               sizeof(ssk->dst_addr));
drop:
        FREE_SKB(skb);

        return err;
}

int serval_srv_state_process(struct sock *sk, 
                             struct serval_hdr *sfh, 
                             struct sk_buff *skb)
{
        int err = 0;

        switch (sk->sk_state) {
        case SERVAL_CONNECTED:
                err = serval_srv_connected_state_process(sk, sfh, skb);
                break;
        case SERVAL_REQUEST:
                err = serval_srv_request_state_process(sk, sfh, skb);
                break;
        case SERVAL_RESPOND:
                err = serval_srv_respond_state_process(sk, sfh, skb);
                break;
        case SERVAL_LISTEN:
                err = serval_srv_listen_state_process(sk, sfh, skb);
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

int serval_srv_do_rcv(struct sock *sk, 
                      struct sk_buff *skb)
{
        struct serval_hdr *sfh = 
                (struct serval_hdr *)skb_transport_header(skb);
        unsigned int hdr_len = ntohs(sfh->length);
                 
        pskb_pull(skb, hdr_len);
        skb_reset_transport_header(skb);
                
        return serval_srv_state_process(sk, sfh, skb);
}

int serval_srv_rcv(struct sk_buff *skb)
{
        struct sock *sk = NULL;
        struct serval_hdr *sfh = 
                (struct serval_hdr *)skb_transport_header(skb);
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
        
        LOG_DBG("flowid (src,dst)=(%u,%u)\n", 
                ntohs(sfh->src_flowid.s_id), 
                ntohs(sfh->dst_flowid.s_id));
       
        /* If SYN and not ACK is set, we know for sure that we must
         * demux on service id instead of socket id */
        if (!(sfh->flags & SFH_SYN && !(sfh->flags & SFH_ACK))) {
                /* Ok, check if we can demux on socket id */
                sk = serval_sock_lookup_flowid(&sfh->dst_flowid);
        }
        
        if (!sk) {
                /* Try to demux on service id */
                struct serval_connection_ext *conn_ext = 
                        (struct serval_connection_ext *)(sfh + 1);

                /* Check for connection extension. We require that this
                 * extension always directly follows the main Serval
                 * header */
                if (!has_connection_extension(sfh))
                        goto drop;

                LOG_DBG("SYN with srvid=%s\n", 
                        service_id_to_str(&conn_ext->srvid));

                sk = serval_sock_lookup_serviceid(&conn_ext->srvid);
                
                if (!sk) {
                        LOG_ERR("No matching serval sock\n");
                        goto drop;
                }
        }
 
        bh_lock_sock_nested(sk);

        if (!sock_owned_by_user(sk)) {
                err = serval_srv_do_rcv(sk, skb);
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
#define SERVAL_MAX_HDR (MAX_HEADER + 20 +                       \
                        sizeof(struct serval_hdr) +             \
                        sizeof(struct serval_connection_ext) +     \
                        EXTRA_HDR)

static int serval_srv_rexmit_skb(struct sk_buff *skb)
{        
        LOG_WARN("not implemented\n");

        return 0;
}

void serval_srv_rexmit_timeout(unsigned long data)
{
        struct sock *sk = (struct sock *)data;
        int err;

        err = serval_srv_rexmit_skb(skb_peek(&sk->sk_write_queue));

        sock_put(sk);
}

int serval_srv_xmit_skb(struct sk_buff *skb)
{
        struct sock *sk = skb->sk;
        struct serval_sock *ssk = serval_sk(sk);
	struct service_entry *se;
	struct net_device *dev;
        struct serval_hdr *sfh;
        struct serval_connection_ext *conn_ext;
        struct serval_control_ext *ctrl_ext;
        uint8_t flags = 0;
        int hdr_len = sizeof(*sfh);
	int err = 0;

        /* Add appropriate flags and headers */
        switch (SERVAL_SKB_CB(skb)->pkttype) {
        case SERVAL_PKT_SYNACK:
                flags |= SFH_ACK;
        case SERVAL_PKT_SYN:
                flags |= SFH_SYN;
                conn_ext = (struct serval_connection_ext *)skb_push(skb, sizeof(*conn_ext));
                conn_ext->type = SERVAL_CONNECTION_EXT;
                conn_ext->length = htons(sizeof(*conn_ext));
                conn_ext->flags = 0;
                memcpy(&conn_ext->srvid, &SERVAL_SKB_CB(skb)->srvid, 
                       sizeof(SERVAL_SKB_CB(skb)->srvid));
                memcpy(conn_ext->nonce, ssk->local_nonce, SERVAL_NONCE_SIZE);
                hdr_len += sizeof(*conn_ext);
                break;
        case SERVAL_PKT_ACK:
                flags |= SFH_ACK;
                break;
        case SERVAL_PKT_CLOSE:
                flags |= SFH_FIN;
                ctrl_ext = (struct serval_control_ext *)skb_push(skb, sizeof(*ctrl_ext));
                ctrl_ext->type = SERVAL_CONTROL_EXT;
                ctrl_ext->length = htons(sizeof(*ctrl_ext));
                ctrl_ext->flags = 0;
                memcpy(ctrl_ext->nonce, ssk->local_nonce, SERVAL_NONCE_SIZE);
                hdr_len += sizeof(*ctrl_ext);
        default:
                break;
        }

        /* Add Serval header */
        sfh = (struct serval_hdr *)skb_push(skb, sizeof(*sfh));
        sfh->flags = flags;
        sfh->protocol = skb->protocol;
        sfh->length = htons(hdr_len);
        memcpy(&sfh->src_flowid, &ssk->local_flowid, sizeof(ssk->local_flowid));
        memcpy(&sfh->dst_flowid, &ssk->peer_flowid, sizeof(ssk->peer_flowid));

        skb->protocol = IPPROTO_SERVAL;

	if (sk->sk_state == SERVAL_CONNECTED) {
                if (ssk->dev) {
                        skb_set_dev(skb, ssk->dev);
                        memcpy(&SERVAL_SKB_CB(skb)->dst_addr,
                               &ssk->dst_addr, sizeof(ssk->dst_addr));
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

        if (SERVAL_SKB_CB(skb)->pkttype == SERVAL_PKT_SYN) {
                sk_reset_timer(sk, &ssk->retransmit_timer, 
                               msecs_to_jiffies(2000));
                LOG_DBG("SYN hdr_len=%u\n", htons(sfh->length));
        }
	/* Unresolved packet, use service id */
	se = service_find(&SERVAL_SKB_CB(skb)->srvid);
	
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
		service_entry_dev_dst(se, &SERVAL_SKB_CB(skb)->dst_addr,
                                      sizeof(struct net_addr));

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

                        LOG_DBG("cskb->len=%u\n", cskb->len);
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

