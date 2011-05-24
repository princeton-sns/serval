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
#include <linux/if_ether.h>
#include <linux/inetdevice.h>
#include <linux/netfilter_ipv4.h>
#include <net/route.h>
#include <net/ip.h>
#elif !defined(OS_ANDROID)
#include <netinet/if_ether.h>
#endif
#if defined(OS_USER)
#include <signal.h>
#include <arpa/inet.h>
#endif
#include <serval_request_sock.h>
#include <service.h>

extern int serval_tcp_rcv(struct sk_buff *);
extern int serval_udp_rcv(struct sk_buff *);
extern atomic_t serval_nr_socks;

static struct net_addr null_addr = { 
        .net_raw = { 0x00, 0x00, 0x00, 0x00 } 
};

static struct net_addr local_addr = {
        .net_raw = { 0x7F, 0x00, 0x00, 0x01 }
};

/* Backoff multipliers for retransmission, fail when reaching 0. */
static uint8_t backoff[] = { 1, 2, 4, 8, 16, 32, 64, 0 };

atomic_t serval_transit = ATOMIC_INIT(0);

static int serval_srv_state_process(struct sock *sk, 
                                    struct serval_hdr *sfh, 
                                    struct sk_buff *skb);

static int serval_srv_transmit_skb(struct sock *sk, struct sk_buff *skb, 
                                   int clone_it, gfp_t gfp_mask);

/* FIXME: should find a better way to distinguish between control
 * packets and data */
static inline int is_control_packet(struct sk_buff *skb)
{
        struct serval_hdr *sfh = 
                (struct serval_hdr *)skb_transport_header(skb);

        if (sfh->flags & SVH_SYN || sfh->flags & SVH_ACK)
                return 1;
        return 0;
}

static inline int is_data_packet(struct sk_buff *skb)
{
        return !is_control_packet(skb);
}

static inline int has_connection_extension(struct serval_hdr *sfh)
{
        struct serval_connection_ext *conn_ext = 
                (struct serval_connection_ext *)(sfh + 1);
        unsigned int hdr_len = ntohs(sfh->length);

        /* Check for connection extension. We require that this
         * extension always directly follows the main Serval
         * header */
        if (hdr_len < sizeof(*sfh) + sizeof(*conn_ext)) {
                LOG_PKT("No connection extension, hdr_len=%u\n", 
                        hdr_len);
                return 0;
        }
        
        if (conn_ext->type != SERVAL_CONNECTION_EXT || 
            ntohs(conn_ext->length) != sizeof(*conn_ext)) {
                LOG_DBG("No connection extension, bad extension type\n");
                return 0;
        }

        return 1;
}

static inline int has_service_extension(struct serval_hdr *sfh)
{
        struct serval_service_ext *srv_ext = 
                (struct serval_service_ext *)(sfh + 1);
        unsigned int hdr_len = ntohs(sfh->length);

        if (hdr_len < sizeof(*sfh) + sizeof(*srv_ext)) {
                LOG_PKT("No service extension, hdr_len=%u\n", 
                        hdr_len);
                return 0;
        }
        
        if (srv_ext->type != SERVAL_SERVICE_EXT || 
            ntohs(srv_ext->length) != sizeof(*srv_ext)) {
                LOG_DBG("No service extension, bad extension type\n");
                return 0;
        }

        return 1;
}

static inline int has_valid_seqno(uint32_t seg_seq, struct serval_sock *ssk)
{        
        int ret = 0;

        /* Basically modelled after TCP, should check whether it makes
         * sense... */
        if (seg_seq == 0) {
                if (seg_seq == ssk->rcv_seq.nxt)
                        ret = 1;
        } else if (seg_seq >= ssk->rcv_seq.nxt &&
                   seg_seq < (ssk->rcv_seq.nxt + 
                              ssk->rcv_seq.wnd)) {
                ret = 1;
        }
        if (ret == 0) {
                LOG_PKT("Seqno not in sequence received=%u next=%u."
                        " Could be ACK though...\n",
                        seg_seq, ssk->rcv_seq.nxt);
        }
        return ret;
}

static inline int has_valid_connection_extension(struct sock *sk, 
                                                 struct serval_hdr *sfh)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_connection_ext *conn_ext = 
                (struct serval_connection_ext *)(sfh + 1);

        if (!has_connection_extension(sfh))
                return 0;

        if (memcmp(conn_ext->nonce, ssk->peer_nonce, 
                   SERVAL_NONCE_SIZE) != 0) {
                LOG_PKT("Connection extension has bad nonce\n");
                return 0;
        }

        return 1;
}

static inline int has_valid_control_extension(struct sock *sk, 
                                              struct serval_hdr *sfh)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_control_ext *ctrl_ext = 
                (struct serval_control_ext *)(sfh + 1);
        unsigned int hdr_len = ntohs(sfh->length);

        /* Check for control extension. We require that this
         * extension always directly follows the main Serval
         * header */
        if (hdr_len < sizeof(*sfh) + sizeof(*ctrl_ext)) {
                LOG_PKT("No control extension, hdr_len=%u\n", 
                        hdr_len);
                return 0;
        }
        
        if (ctrl_ext->type != SERVAL_CONTROL_EXT ||
            ntohs(ctrl_ext->length) != sizeof(*ctrl_ext)) {
                LOG_PKT("No control extension, bad extension type\n");
                return 0;
        }

        if (memcmp(ctrl_ext->nonce, ssk->peer_nonce, 
                   SERVAL_NONCE_SIZE) != 0) {
                LOG_PKT("Control extension has bad nonce\n");
                return 0;
        }

        return 1;
}

static void serval_srv_queue_ctrl_skb(struct sock *sk, struct sk_buff *skb)
{
	skb_header_release(skb);
	serval_srv_add_ctrl_queue_tail(sk, skb);
        LOG_PKT("queue packet seqno=%u\n", SERVAL_SKB_CB(skb)->seqno);
        /* Check if the skb became first in queue, in that case update
         * unacknowledged seqno. */
        if (skb == serval_srv_ctrl_queue_head(sk)) {
                serval_sk(sk)->snd_seq.una = SERVAL_SKB_CB(skb)->seqno;
                LOG_PKT("setting snd_una=%u\n",
                        serval_sk(sk)->snd_seq.una);
        }
}

/* 
   This function writes packets in the control queue to the
   network. It will write up to the current send window or the limit
   given as argument.  
*/
static int serval_srv_write_xmit(struct sock *sk, 
                                 unsigned int limit, gfp_t gfp)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *skb;
        unsigned int num = 0;
        int err = 0;
        
        LOG_PKT("writing from queue snd_una=%u snd_nxt=%u snd_wnd=%u\n",
                ssk->snd_seq.una, ssk->snd_seq.nxt, ssk->snd_seq.wnd);
        
	while ((skb = serval_srv_send_head(sk)) && 
               (ssk->snd_seq.nxt - ssk->snd_seq.una) <= ssk->snd_seq.wnd) {
                
                if (limit && num == limit)
                        break;

                err = serval_srv_transmit_skb(sk, skb, 1, gfp);
                
                if (err < 0) {
                        LOG_ERR("xmit failed\n");
                        break;
                }
                serval_srv_advance_send_head(sk, skb);
                num++;
        }

        LOG_PKT("sent %u packets\n", num);

        return err;
}

/*
  Queue packet on control queue and push pending packets.
*/
static int serval_srv_queue_and_push(struct sock *sk, struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err;
        
        serval_srv_queue_ctrl_skb(sk, skb);

        /* 
           Set retransmission timer if this was inserted first in the
           queue */
        if (skb == serval_srv_ctrl_queue_head(sk)) {
                sk_reset_timer(sk, &serval_sk(sk)->retransmit_timer,
                               jiffies + msecs_to_jiffies(ssk->rto)); 
        }
        
        /* 
           Write packets in queue to network.
           NOTE: only one packet for now. Should implement TX window.
        */
        err = serval_srv_write_xmit(sk, 1, GFP_ATOMIC);

        if (err != 0) {
                LOG_ERR("xmit failed\n");
        }

        return err;
}

/*
  Given an ACK, clean all packets from the control queue that this ACK
  acknowledges.

  Reschedule retransmission timer as neccessary, i.e., if there are
  still unacked packets in the queue and we removed the first packet
  in the queue.
*/
static int serval_srv_clean_rtx_queue(struct sock *sk, uint32_t ackno)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *skb, *fskb = serval_srv_ctrl_queue_head(sk);
        unsigned int num = 0;
        int err = 0;
       
        while ((skb = serval_srv_ctrl_queue_head(sk)) && 
               skb != serval_srv_send_head(sk)) {
                if (ackno == SERVAL_SKB_CB(skb)->seqno + 1) {
                        serval_srv_unlink_ctrl_queue(skb, sk);
                        LOG_PKT("cleaned rtx queue seqno=%u\n", 
                                SERVAL_SKB_CB(skb)->seqno);
                        FREE_SKB(skb);
                        skb = serval_srv_ctrl_queue_head(sk);
                        if (skb)
                                ssk->snd_seq.una = SERVAL_SKB_CB(skb)->seqno;
                        num++;
                } else {
                        break;
                }
        }

        LOG_PKT("cleaned up %u packets from rtx queue\n", num);
        
        /* Did we remove the first packet in the queue? */
        if (serval_srv_ctrl_queue_head(sk) != fskb) {
                sk_stop_timer(sk, &serval_sk(sk)->retransmit_timer);
                ssk->retransmits = 0;
        }

        if (serval_srv_ctrl_queue_head(sk)) {
                LOG_PKT("Setting retrans timer\n");
                sk_reset_timer(sk, &serval_sk(sk)->retransmit_timer,
                               jiffies + msecs_to_jiffies(ssk->rto));
        }
        return err;
}

int serval_srv_connect(struct sock *sk, struct sockaddr *uaddr, 
                       int addr_len)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *skb;
        struct service_id *srvid = &((struct sockaddr_sv *)uaddr)->sv_srvid;
        int err;
        
        LOG_DBG("srvid=%s addr_len=%d\n", 
                service_id_to_str(srvid), addr_len);

	if ((size_t)addr_len < sizeof(struct sockaddr_sv))
		return -EINVAL;
        
        skb = ALLOC_SKB(sk->sk_prot->max_header, GFP_ATOMIC);

        if (!skb)
                return -ENOMEM;
        
        skb_reserve(skb, sk->sk_prot->max_header);
        skb_serval_set_owner_w(skb, sk);
        skb->protocol = 0;

        /* Ask transport to fill in */
        if (ssk->af_ops->conn_build_syn) {
                err = ssk->af_ops->conn_build_syn(sk, skb);

                if (err) {
                        LOG_ERR("Transport protocol returned error\n");
                        FREE_SKB(skb);
                        return err;
                }
        }

        memcpy(&SERVAL_SKB_CB(skb)->srvid, srvid, sizeof(*srvid));
        SERVAL_SKB_CB(skb)->pkttype = SERVAL_PKT_CONN_SYN;
        SERVAL_SKB_CB(skb)->seqno = ssk->snd_seq.iss;
        ssk->snd_seq.nxt = ssk->snd_seq.iss + 1;
        memcpy(&SERVAL_SKB_CB(skb)->addr, &inet_sk(sk)->inet_daddr, 
               sizeof(inet_sk(sk)->inet_daddr));

        LOG_DBG("Sending REQUEST seqno=%u\n",
                SERVAL_SKB_CB(skb)->seqno);

        err = serval_srv_queue_and_push(sk, skb);
        
        if (err < 0) {
                LOG_ERR("queuing failed\n");
        }
        
        return err;
}

static void serval_srv_timewait(struct sock *sk, int state)
{
        serval_sock_set_state(sk, state);
        /* FIXME: Dynamically set timeout */
        sk_reset_timer(sk, &serval_sk(sk)->tw_timer,
                       jiffies + msecs_to_jiffies(8000)); 
}

/* Called as a result of user app close() */
void serval_srv_close(struct sock *sk, long timeout)
{
        struct sk_buff *skb = NULL;
        int err = 0;

        LOG_DBG("\n");
        
        if (sk->sk_state == SERVAL_CONNECTED ||
            sk->sk_state == SERVAL_RESPOND ||
            sk->sk_state == SERVAL_CLOSEWAIT) {
                struct serval_sock *ssk = serval_sk(sk);
                
                if (ssk->af_ops->conn_close) {
                        err = ssk->af_ops->conn_close(sk);

                        if (err != 0) {
                                LOG_ERR("Transport error %d\n", err);
                        }
                }
                if (sk->sk_state == SERVAL_CLOSEWAIT) {
                        serval_sock_set_state(sk, SERVAL_LASTACK);
                } else {
                        serval_sock_set_state(sk, SERVAL_FINWAIT1);
                }
                /* We are under lock, so allocation must be atomic */
                /* Socket is locked, keep trying until memory is available. */
                for (;;) {
                        skb = ALLOC_SKB(sk->sk_prot->max_header, GFP_ATOMIC);
                        
                        if (skb)
                                break;
                        yield();
                }
                
                skb_reserve(skb, sk->sk_prot->max_header);
                skb_serval_set_owner_w(skb, sk);
                SERVAL_SKB_CB(skb)->pkttype = SERVAL_PKT_CLOSE;
                SERVAL_SKB_CB(skb)->seqno = serval_sk(sk)->snd_seq.nxt++;
                memcpy(&SERVAL_SKB_CB(skb)->addr, &inet_sk(sk)->inet_daddr, 
                       sizeof(inet_sk(sk)->inet_daddr));

                err = serval_srv_queue_and_push(sk, skb);
                
                if (err < 0) {
                        LOG_ERR("queuing failed\n");
                }
        } else {
                serval_sock_done(sk);
        }
}

/* We got a close request (FIN) from our peer */
static int serval_srv_send_close_ack(struct sock *sk, struct serval_hdr *sfh, 
                                     struct sk_buff *rskb)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *skb;
        int err = 0;

        LOG_DBG("Sending Close ACK\n");

        skb = ALLOC_SKB(sk->sk_prot->max_header, GFP_ATOMIC);
                        
        if (!skb)
                return -ENOMEM;
        
        skb_reserve(skb, sk->sk_prot->max_header);
        skb_serval_set_owner_w(skb, sk);
        SERVAL_SKB_CB(skb)->pkttype = SERVAL_PKT_CLOSEACK;
        memcpy(&SERVAL_SKB_CB(skb)->addr, &inet_sk(sk)->inet_daddr, 
               sizeof(inet_sk(sk)->inet_daddr));
        /* Do not increment sequence numbers for pure ACKs */
        SERVAL_SKB_CB(skb)->seqno = ssk->snd_seq.nxt;

        if (err == 0) {
                /* Do not queue pure ACKs */
                err = serval_srv_transmit_skb(sk, skb, 0, GFP_ATOMIC);
        }
               
        if (err < 0) {
                LOG_ERR("xmit failed\n");
        }
   
        return err;
}

static int serval_srv_syn_rcv(struct sock *sk, 
                              struct serval_hdr *sfh,
                              struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct request_sock *rsk;
        struct serval_request_sock *srsk;
        struct serval_connection_ext *conn_ext = 
                (struct serval_connection_ext *)(sfh + 1);
        struct net_addr saddr;
        struct dst_entry *dst = NULL;
        struct sk_buff *rskb;
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

        LOG_DBG("REQUEST seqno=%u\n", ntohl(conn_ext->seqno));

        if (sk->sk_ack_backlog >= sk->sk_max_ack_backlog) 
                goto drop;


        /* Try to figure out the source address for the incoming
         * interface so that we can use it in our reply.  
         *
         * FIXME:
         * should probably route the reply here somehow in case we
         * want to reply on another interface than the incoming one.
         */
        if (!dev_get_ipv4_addr(skb->dev, &saddr)) {
                LOG_ERR("No source address for interface %s\n",
                        skb->dev);
                goto drop;
        }

        rsk = serval_reqsk_alloc(sk->sk_prot->rsk_prot);

        if (!rsk) {
                err = -ENOMEM;
                goto drop;
        }

        srsk = serval_rsk(rsk);

        /* Copy fields in request packet into request sock */
        memcpy(&srsk->peer_flowid, &sfh->src_flowid, 
               sizeof(sfh->src_flowid));
        memcpy(&inet_rsk(rsk)->rmt_addr, &ip_hdr(skb)->saddr,
               sizeof(inet_rsk(rsk)->rmt_addr));
        memcpy(&inet_rsk(rsk)->loc_addr, &ip_hdr(skb)->daddr,
               sizeof(inet_rsk(rsk)->loc_addr));
        memcpy(srsk->peer_nonce, conn_ext->nonce, SERVAL_NONCE_SIZE);
        srsk->rcv_seq = ntohl(conn_ext->seqno);

        list_add(&srsk->lh, &ssk->syn_queue);
        
        /* Call upper transport protocol handler */
        if (ssk->af_ops->conn_request) {
                err = ssk->af_ops->conn_request(sk, rsk, skb);
                
                if (err) {
                        reqsk_free(rsk);
                        goto drop;
                }
        }
        
        /* Allocate RESPONSE reply */
        rskb = ALLOC_SKB(sk->sk_prot->max_header, GFP_ATOMIC);

        if (!rskb) {
                err = -ENOMEM;
                goto drop;
        }
        
        skb_reserve(rskb, sk->sk_prot->max_header);
        skb_serval_set_owner_w(rskb, sk);
        rskb->protocol = 0;

#if defined(OS_LINUX_KERNEL)
        {
                /*
                  For kernel, we need to route this packet and
                  associate a dst_entry with the skb for it to be
                  accepted by the kernel IP stack.
                 */
                dst = serval_ipv4_req_route(sk, rsk, rskb->protocol,
                                            saddr.net_ip.s_addr,
                                            ip_hdr(skb)->saddr);

                if (!dst) {
                        LOG_ERR("RESPONSE not routable\n");
                        goto drop;
                }
        }
#endif /* OS_LINUX_KERNEL */

        /* Let transport chip in */
        if (ssk->af_ops->conn_build_synack) {
                err = ssk->af_ops->conn_build_synack(sk, dst, rsk, rskb);
                
                if (err) {
                        reqsk_free(rsk);
                        goto drop_and_release;
                }
        } else {
                LOG_DBG("Transport has no SYNACK callback\n");
        }

        rskb->protocol = IPPROTO_SERVAL;
        conn_ext = (struct serval_connection_ext *)
                skb_push(rskb, sizeof(*conn_ext));
        conn_ext->type = SERVAL_CONNECTION_EXT;
        conn_ext->length = htons(sizeof(*conn_ext));
        conn_ext->flags = 0;
        conn_ext->seqno = htonl(srsk->iss_seq);
        conn_ext->ackno = htonl(srsk->rcv_seq + 1);
        memcpy(&conn_ext->srvid, &SERVAL_SKB_CB(skb)->srvid, 
               sizeof(SERVAL_SKB_CB(skb)->srvid));
        /* Copy our nonce to connection extension */
        memcpy(conn_ext->nonce, srsk->local_nonce, SERVAL_NONCE_SIZE);
        
        /* Add Serval header */
        sfh = (struct serval_hdr *)skb_push(rskb, sizeof(*sfh));
        sfh->flags = SVH_SYN | SVH_ACK;
        sfh->protocol = rskb->protocol;
        sfh->length = htons(sizeof(*sfh) + sizeof(*conn_ext));

        /* Update info in packet */
        memcpy(&sfh->dst_flowid, &srsk->peer_flowid, 
               sizeof(sfh->dst_flowid));
        memcpy(&sfh->src_flowid, &srsk->local_flowid, 
               sizeof(srsk->local_flowid));
        memcpy(&conn_ext->srvid, &srsk->peer_srvid,            
               sizeof(srsk->peer_srvid));
        SERVAL_SKB_CB(rskb)->pkttype = SERVAL_PKT_CONN_SYNACK;
     
        {
                char buf[900];                
                LOG_DBG("Hex: %s\n", hexdump(rskb->data, rskb->len, buf, 900));
        }
        skb_reset_transport_header(rskb);      
        skb_dst_set(rskb, dst);

        rskb->dev = skb->dev;

        LOG_DBG("Sending RESPONSE seqno=%u ackno=%u rskb->len=%u\n",
                ntohl(conn_ext->seqno),
                ntohl(conn_ext->ackno),
                rskb->len);
                
        {
                char buf[900];                
                LOG_DBG("Hex: %s\n", hexdump(rskb->data, rskb->len, buf, 900));
        }
        /* Cannot use serval_srv_transmit_skb here since we do not yet
         * have a full accepted socket (sk is the listening sock). */
        err = serval_ipv4_build_and_send_pkt(rskb, sk, 
                                             saddr.net_ip.s_addr,
                                             ip_hdr(skb)->saddr, NULL);
        
done:        
        /* Free the REQUEST */
        FREE_SKB(skb);

        return err;
drop_and_release:
        dst_release(dst);
drop:
        goto done;
}

/*
  Create new child socket in RESPOND state. This happens as a result
  of a LISTEN:ing socket receiving an ACK in response to a SYNACK
  response.  */
static struct sock *
serval_srv_create_respond_sock(struct sock *sk, 
                               struct sk_buff *skb,
                               struct request_sock *req,
                               struct dst_entry *dst)
{
        struct sock *nsk;

        nsk = sk_clone(sk, GFP_ATOMIC);

        if (nsk) {
                atomic_inc(&serval_nr_socks);
                serval_sock_init(nsk);

                /* Transport protocol specific init. */                
                serval_sk(sk)->af_ops->conn_child_sock(sk, skb, req, nsk, NULL);
        }        
        
        return nsk;
}


/*
  This function is called as a result of receiving a ACK in response
  to a SYNACK that was sent by a "parent" sock in LISTEN state (the sk
  argument). 
   
  The objective is to find a serval_request_sock that corresponds to
  the ACK just received and initiate processing on that request
  sock. Such processing includes transforming the request sock into a
  regular sock and putting it on the parent sock's accept queue.

*/
static struct sock * serval_srv_request_sock_handle(struct sock *sk,
                                                    struct serval_hdr *sfh,
                                                    struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_request_sock *srsk;
        struct serval_connection_ext *conn_ext = 
                (struct serval_connection_ext *)(sfh + 1);

        list_for_each_entry(srsk, &ssk->syn_queue, lh) {
                if (memcmp(&srsk->local_flowid, &sfh->dst_flowid, 
                           sizeof(srsk->local_flowid)) == 0) {
                        struct sock *nsk;
                        struct serval_sock *nssk;
                        struct request_sock *rsk = &srsk->rsk.req;
                        struct inet_request_sock *irsk = &srsk->rsk;
                        struct inet_sock *newinet;

                        if (memcmp(srsk->peer_nonce, conn_ext->nonce, 
                                   SERVAL_NONCE_SIZE) != 0) {
                                LOG_ERR("Bad nonce\n");
                                return NULL;
                        }

                        if (ntohl(conn_ext->seqno) != srsk->rcv_seq + 1) {
                                LOG_ERR("Bad seqno received=%u expected=%u\n",
                                        ntohl(conn_ext->seqno), 
                                        srsk->rcv_seq + 1);
                                return NULL;
                        }
                        if (ntohl(conn_ext->ackno) != srsk->iss_seq + 1) {
                                LOG_ERR("Bad ackno received=%u expected=%u\n",
                                        ntohl(conn_ext->ackno), 
                                        srsk->iss_seq + 1);
                                return NULL;
                        }
                        /* Move request sock to accept queue */
                        list_del(&srsk->lh);
                        list_add_tail(&srsk->lh, &ssk->accept_queue);
                        
                        nsk = serval_srv_create_respond_sock(sk, skb, 
                                                             rsk, NULL);
                        
                        if (!nsk)
                                return NULL;

                        newinet = inet_sk(nsk);
                        nssk = serval_sk(nsk);

                        nsk->sk_state = SERVAL_RESPOND;

                        memcpy(&nssk->local_flowid, &srsk->local_flowid, 
                               sizeof(srsk->local_flowid));
                        memcpy(&nssk->peer_flowid, &srsk->peer_flowid, 
                               sizeof(srsk->peer_flowid));
                        memcpy(&nssk->peer_srvid, &srsk->peer_srvid,
                               sizeof(srsk->peer_srvid));
                        memcpy(&newinet->inet_daddr, &irsk->rmt_addr,
                               sizeof(newinet->inet_daddr));              
                        //newinet->mc_index = inet_iif(skb);
                        //newinet->mc_ttl	= ip_hdr(skb)->ttl;

                        memcpy(nssk->local_nonce, srsk->local_nonce, 
                               SERVAL_NONCE_SIZE);
                        memcpy(nssk->peer_nonce, srsk->peer_nonce, 
                               SERVAL_NONCE_SIZE);
                        nssk->snd_seq.iss = srsk->iss_seq;
                        nssk->snd_seq.una = srsk->iss_seq;
                        nssk->snd_seq.nxt = srsk->iss_seq + 1;
                        nssk->rcv_seq.iss = srsk->rcv_seq;
                        nssk->rcv_seq.nxt = srsk->rcv_seq + 1;
                        rsk->sk = nsk;

                        /* Hash the sock to make it available */
                        nsk->sk_prot->hash(nsk);

                        return nsk;
                }
        }
        
        return sk;
}

static int serval_srv_ack_process(struct sock *sk,
                                  struct serval_hdr *sfh, 
                                  struct sk_buff *skb)
{
        struct serval_ext *ext = (struct serval_ext *)(sfh + 1);
        uint32_t ackno = 0;
        int err = -1;

        if (!(sfh->flags & SVH_ACK))
                return -1;

        switch (ext->type) {
        case SERVAL_CONNECTION_EXT:
        {
                struct serval_connection_ext *conn_ext = 
                        (struct serval_connection_ext *)ext;
                ackno = ntohl(conn_ext->ackno);
        }
        break;
        case SERVAL_CONTROL_EXT:
        {
                struct serval_control_ext *ctrl_ext = 
                        (struct serval_control_ext *)ext;
                ackno = ntohl(ctrl_ext->ackno);
        }
        break;
        default:
                goto done;
        }
        
        if (ackno == serval_sk(sk)->snd_seq.una + 1) {
                serval_srv_clean_rtx_queue(sk, ackno);
                serval_sk(sk)->snd_seq.una++;
                LOG_PKT("received valid ACK ackno=%u\n", 
                        ackno);
                err = 0;
        } else {
                LOG_PKT("ackno %u out of sequence, expected %u\n",
                        ackno, serval_sk(sk)->snd_seq.una + 1);
        }
done:
        return err;
}

static int serval_srv_rcv_close_req(struct sock *sk, 
                                    struct serval_hdr *sfh,
                                    struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_control_ext *ctrl_ext = 
                (struct serval_control_ext *)(sfh + 1);
        int err = 0;

        LOG_DBG("received CLOSE REQUEST\n");
        
        if (!has_valid_control_extension(sk, sfh)) {
                LOG_DBG("Bad control extension\n");
                return -1;
        }
        
        if (has_valid_seqno(ntohl(ctrl_ext->seqno), ssk)) {
                ssk->rcv_seq.nxt = ntohl(ctrl_ext->seqno) + 1;                
                ssk->close_received = 1;

                /* Give transport a chance to chip in */ 
                if (ssk->af_ops->close_request) {
                        err = ssk->af_ops->close_request(sk, skb);
                } else {
                        /* If transport has no close_request function,
                           assume 1 */
                        err = 1;
                }
                
                /* FIXME: This is a HACK! If close_request
                 * returns 1, the transport is ready to tell
                 * the user that the other end closed. */
                if (err == 1) {
                        sk->sk_shutdown |= SEND_SHUTDOWN;
                        sock_set_flag(sk, SOCK_DONE);

                        switch (sk->sk_state) {
                        case SERVAL_REQUEST:
                                /* FIXME: check correct processing here in
                                 * REQUEST state. */
                        case SERVAL_RESPOND:
                        case SERVAL_CONNECTED:
                                serval_sock_set_state(sk, SERVAL_CLOSEWAIT);
                                sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_HUP);
                                break;
                        case SERVAL_CLOSING:
                                break;
                        case SERVAL_CLOSEWAIT:
                                /* Must be retransmitted FIN */
                                
                                /* FIXME: is this the right place for async
                                 * wake? */
                                sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_HUP);
                                break;
                        case SERVAL_FINWAIT1:
                                /* Simultaneous close */
                                serval_sock_set_state(sk, SERVAL_CLOSING);
                        default:
                                break;
                        }
                } else {
                        LOG_DBG("Transport not ready to close\n");
                }
                err = serval_srv_send_close_ack(sk, sfh, skb);
        }
        
        return err;
}

int serval_srv_rcv_transport_fin(struct sock *sk,
                                 struct sk_buff *skb)
{
        int err = 0;
        struct serval_sock *ssk = serval_sk(sk);

        if (!ssk->close_received)
                return 0;
        
        if (sock_flag(sk, SOCK_DONE))
                return 0;

        sk->sk_shutdown |= SEND_SHUTDOWN;
        sock_set_flag(sk, SOCK_DONE);
        
        switch (sk->sk_state) {
        case SERVAL_REQUEST:
                /* FIXME: check correct processing here in
                 * REQUEST state. */
        case SERVAL_RESPOND:
        case SERVAL_CONNECTED:
                serval_sock_set_state(sk, SERVAL_CLOSEWAIT);
                sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_HUP);
                break;
        case SERVAL_CLOSING:
                break;
        case SERVAL_CLOSEWAIT:
                /* Must be retransmitted FIN */
                                
                /* FIXME: is this the right place for async
                 * wake? */
                sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_HUP);
                break;
        case SERVAL_FINWAIT1:
                /* Simultaneous close */
                serval_sock_set_state(sk, SERVAL_CLOSING);
        default:
                break;
        }
        
        return err;
}

static int serval_srv_connected_state_process(struct sock *sk, 
                                              struct serval_hdr *sfh,
                                              struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;
        
        if (sfh->flags & SVH_FIN) {
                SERVAL_SKB_CB(skb)->pkttype = SERVAL_PKT_CLOSE;
                err = serval_srv_rcv_close_req(sk, sfh, skb);

                if (err == 0) {
                        /* Valid FIN means valid header that may
                           contain ACK */
                        serval_srv_ack_process(sk, sfh, skb);
                        SERVAL_SKB_CB(skb)->pkttype = SERVAL_PKT_DATA;
                }
        }

        if (sfh->flags & SVH_ACK) {
                serval_srv_ack_process(sk, sfh, skb);
        } else if (sfh->flags == 0) {
                /* FIXME: Should find better way to detect that this
                 * might be a data packet */
                SERVAL_SKB_CB(skb)->pkttype = SERVAL_PKT_DATA;
        }

        /* Should also pass FIN to user, as it needs to pick it off
         * its receive queue to notice EOF. */
        if (SERVAL_SKB_CB(skb)->pkttype == SERVAL_PKT_DATA) {
                /* Set the received service id */
                memcpy(&SERVAL_SKB_CB(skb)->srvid, &ssk->peer_srvid,
                       sizeof(ssk->peer_srvid));
                /* Set receive IP */
                memcpy(&SERVAL_SKB_CB(skb)->addr, &ip_hdr(skb)->saddr,
                       sizeof(ip_hdr(skb)->saddr));

                err = ssk->af_ops->receive(sk, skb);
        } else {
                FREE_SKB(skb);
        }
        return err;
}

/*
  This function works as the initial receive function for a child
  socket that has just been created by a parent (as a result of
  successful connection handshake).

  The processing resembles that which happened for the parent socket
  when this packet was first received by the parent.

*/
static int serval_srv_child_process(struct sock *parent, struct sock *child,
                                    struct serval_hdr *sfh,
                                    struct sk_buff *skb)
{
        int ret = 0;
        int state = child->sk_state;

        serval_sk(child)->dev = NULL;
        
        /* Check lock on child socket, similarly to how we handled the
           parent sock for the incoming skb. */
        if (!sock_owned_by_user(child)) {
                ret = serval_srv_state_process(child, sfh, skb);
                if (state == SERVAL_RESPOND && child->sk_state != state) {
                        LOG_DBG("waking up parent (listening) sock\n");
                        parent->sk_data_ready(parent, 0);
                }
        } else {
                /* 
                   User got lock, add skb to backlog so that it will
                   be processed in user context when the lock is
                   released.
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

        if (sfh->flags & SVH_ACK) {
                /* Processing for socket that has received SYN already */
                struct sock *nsk;
                LOG_DBG("ACK recv\n");

                nsk = serval_srv_request_sock_handle(sk, sfh, skb);
                
                if (nsk && nsk != sk) {
                        return serval_srv_child_process(sk, nsk, sfh, skb);
                }
                FREE_SKB(skb);
        } else if (sfh->flags & SVH_SYN) {
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
        struct sk_buff *rskb;       
        int err = 0;
                
        if (!has_connection_extension(sfh)) {
                goto drop;
        }
        
        if (!(sfh->flags & SVH_SYN && sfh->flags & SVH_ACK)) {
                LOG_ERR("packet is not a RESPONSE\n");
                goto drop;
        }

        LOG_DBG("Got RESPONSE seqno=%u ackno=%u TCP off=%u hdrlen=%u\n",
                ntohl(conn_ext->seqno), 
                ntohl(conn_ext->ackno),
                skb_transport_header(skb) - (unsigned char *)sfh,
                sizeof(*sfh) + sizeof(*conn_ext));

        /* Let user know we are connected. */
	if (!sock_flag(sk, SOCK_DEAD)) {
                sk->sk_state_change(sk);
                sk_wake_async(sk, SOCK_WAKE_IO, POLL_OUT);
        }

        /* Save device and peer flow id */
        serval_sock_set_dev(sk, skb->dev);
        memcpy(&inet_sk(sk)->inet_daddr, &ip_hdr(skb)->saddr, 
               sizeof(inet_sk(sk)->inet_daddr));

        /* Save nonce */
        memcpy(ssk->peer_nonce, conn_ext->nonce, SERVAL_NONCE_SIZE);
        /* Update socket ids */
        memcpy(&ssk->peer_flowid, &sfh->src_flowid, 
               sizeof(sfh->src_flowid));
      
        /* Update expected rcv sequence number */
        ssk->rcv_seq.nxt = ntohl(conn_ext->seqno) + 1;

        /* Process potential ACK 

           TODO: should probably reject this packet if the ACK is
           invalid.
         */
        serval_srv_ack_process(sk, sfh, skb);
        {
                char buf[900];
                
                LOG_DBG("Hex: %s\n", 
                        hexdump(sfh, ntohs(sfh->length) + 20, buf, 900));
        } 
        
        /* Let transport know about the response */
        if (ssk->af_ops->request_state_process) {
                err = ssk->af_ops->request_state_process(sk, skb);

                if (err) {
                        LOG_ERR("Transport drops packet\n");
                        goto error;
                }
        }

        /* Move to connected state */
        serval_sock_set_state(sk, SERVAL_CONNECTED);
        
        /* Allocate ACK */
        rskb = ALLOC_SKB(sk->sk_prot->max_header, GFP_ATOMIC);

        if (!rskb) {
                err = -ENOMEM;
                goto drop;
        }
        
        skb_reserve(rskb, sk->sk_prot->max_header);
        skb_serval_set_owner_w(rskb, sk);
        rskb->protocol = 0;

        /* Ask transport to fill in*/
        if (ssk->af_ops->conn_build_ack) {
                err = ssk->af_ops->conn_build_ack(sk, rskb);

                if (err) {
                        LOG_ERR("Transport drops packet on building ACK\n");
                        goto drop;
                }
        }
        
        /* Update control block */
        SERVAL_SKB_CB(rskb)->pkttype = SERVAL_PKT_CONN_ACK;
        memcpy(&SERVAL_SKB_CB(rskb)->srvid, &ssk->peer_srvid, 
               sizeof(ssk->peer_srvid));
        memcpy(&SERVAL_SKB_CB(rskb)->addr, &inet_sk(sk)->inet_daddr, 
               sizeof(inet_sk(sk)->inet_daddr));

        /* Do not increase sequence number for pure ACK */
        SERVAL_SKB_CB(rskb)->seqno = ssk->snd_seq.nxt;
        rskb->protocol = IPPROTO_SERVAL;
        skb_serval_set_owner_w(rskb, sk);

        /* Xmit, do not queue ACK */
        err = serval_srv_transmit_skb(sk, rskb, 0, GFP_ATOMIC);

drop:                
        FREE_SKB(skb);
error:
        return err;
}

static int serval_srv_respond_state_process(struct sock *sk, 
                                            struct serval_hdr *sfh,
                                            struct sk_buff *skb)
{
        int err = 0;

        if (!has_valid_connection_extension(sk, sfh))
                goto drop;

        /* Process ACK */
        if (serval_srv_ack_process(sk, sfh, skb) == 0) {
                struct serval_sock *ssk = serval_sk(sk);
                LOG_DBG("\n");

                if (ssk->af_ops->respond_state_process) {
                        if (ssk->af_ops->respond_state_process(sk, skb)) {
                                LOG_WARN("Transport drops ACK\n");
                                goto error;
                        }
                }

                /* Valid ACK */
                serval_sock_set_state(sk, SERVAL_CONNECTED);
                
                /* Let user know */
                sk->sk_state_change(sk);
                sk_wake_async(sk, SOCK_WAKE_IO, POLL_OUT);

                /* Save device and peer flow id */
                serval_sock_set_dev(sk, skb->dev);
                memcpy(&inet_sk(sk)->inet_daddr, &ip_hdr(skb)->saddr, 
                       sizeof(inet_sk(sk)->inet_daddr));
        }
drop:
        FREE_SKB(skb);
error:
        return err;
}

static int serval_srv_finwait1_state_process(struct sock *sk, 
                                             struct serval_hdr *sfh, 
                                             struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err;
        
        if (sfh->flags & SVH_FIN) {
                SERVAL_SKB_CB(skb)->pkttype = SERVAL_PKT_CLOSE;
                err = serval_srv_rcv_close_req(sk, sfh, skb);

                if (err == 0) {
                        /* Both FIN and ACK */
                        err = serval_srv_ack_process(sk, sfh, skb);
                        
                        if (err == 0) {
                                serval_srv_timewait(sk, SERVAL_TIMEWAIT);
                        }
                }
        } else {
                /* Only ACK */
                err = serval_srv_ack_process(sk, sfh, skb);
                
                if (err == 0) {
                        /* ACK was valid */
                        serval_srv_timewait(sk, SERVAL_FINWAIT2);
                }
        }

        /* Set the received service id */
        memcpy(&SERVAL_SKB_CB(skb)->srvid, &ssk->peer_srvid,
               sizeof(ssk->peer_srvid));
        /* Set receive IP */
        memcpy(&SERVAL_SKB_CB(skb)->addr, &ip_hdr(skb)->saddr,
               sizeof(ip_hdr(skb)->saddr));
        
        err = ssk->af_ops->receive(sk, skb);

        //FREE_SKB(skb);
                
        return err;
}

static int serval_srv_finwait2_state_process(struct sock *sk, 
                                             struct serval_hdr *sfh, 
                                             struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;
        
        if (sfh->flags & SVH_FIN) {
                SERVAL_SKB_CB(skb)->pkttype = SERVAL_PKT_CLOSE;
                err = serval_srv_rcv_close_req(sk, sfh, skb);

                if (err == 0) {
                        serval_srv_timewait(sk, SERVAL_TIMEWAIT);
                }
        }

        /* Set the received service id */
        memcpy(&SERVAL_SKB_CB(skb)->srvid, &ssk->peer_srvid,
               sizeof(ssk->peer_srvid));
        /* Set receive IP */
        memcpy(&SERVAL_SKB_CB(skb)->addr, &ip_hdr(skb)->saddr,
               sizeof(ip_hdr(skb)->saddr));
        
        err = ssk->af_ops->receive(sk, skb);

        //FREE_SKB(skb);
        
        return err;
}

static int serval_srv_closing_state_process(struct sock *sk, 
                                            struct serval_hdr *sfh, 
                                            struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;

        err = serval_srv_ack_process(sk, sfh, skb);
                
        if (err == 0) {
                /* ACK was valid */
                serval_srv_timewait(sk, SERVAL_TIMEWAIT);
        }

        /* Set the received service id */
        memcpy(&SERVAL_SKB_CB(skb)->srvid, &ssk->peer_srvid,
               sizeof(ssk->peer_srvid));
        /* Set receive IP */
        memcpy(&SERVAL_SKB_CB(skb)->addr, &ip_hdr(skb)->saddr,
               sizeof(ip_hdr(skb)->saddr));
        
        err = ssk->af_ops->receive(sk, skb);

        //FREE_SKB(skb);

        return err;
}

static int serval_srv_lastack_state_process(struct sock *sk, 
                                            struct serval_hdr *sfh, 
                                            struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;
        
        err = serval_srv_ack_process(sk, sfh, skb);
                
        if (err == 0) {
                /* ACK was valid */
                serval_sock_done(sk);
        }

        /* Set the received service id */
        memcpy(&SERVAL_SKB_CB(skb)->srvid, &ssk->peer_srvid,
               sizeof(ssk->peer_srvid));
        /* Set receive IP */
        memcpy(&SERVAL_SKB_CB(skb)->addr, &ip_hdr(skb)->saddr,
               sizeof(ip_hdr(skb)->saddr));
        
        err = ssk->af_ops->receive(sk, skb);

        //FREE_SKB(skb);

        return err;
}

/*
  Receive for datagram sockets that are not connected.
*/
static int serval_srv_init_state_process(struct sock *sk, 
                                         struct serval_hdr *sfh, 
                                         struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_service_ext *srv_ext = 
                (struct serval_service_ext *)(sfh + 1);
        int err = 0;

        if(ssk->hash_key && srv_ext && srv_ext){
                //LOG_DBG("Receiving unconnected datagram for service %s at %i from service %s at %s\n", service_id_to_str((struct service_id*) ssk->hash_key),
                //    ip_hdr(skb)->daddr, service_id_to_str(&srv_ext->src_srvid), ip_hdr(skb)->saddr);
                LOG_DBG("Receiving unconnected datagram for service %s\n", service_id_to_str((struct service_id*) ssk->hash_key));
        }

        /* Set receive IP */
        memcpy(&SERVAL_SKB_CB(skb)->addr, &ip_hdr(skb)->saddr,
               sizeof(ip_hdr(skb)->saddr));

        /* Set source serviceID */
        memcpy(&SERVAL_SKB_CB(skb)->srvid, &srv_ext->src_srvid,
               sizeof(srv_ext->src_srvid));
        
        err = ssk->af_ops->receive(sk, skb);

        return err;
}

int serval_srv_state_process(struct sock *sk, 
                             struct serval_hdr *sfh, 
                             struct sk_buff *skb)
{
        int err = 0;

        switch (sk->sk_state) {
        case SERVAL_INIT:
                if (sk->sk_type == SOCK_STREAM) 
                        goto drop;
                err = serval_srv_init_state_process(sk, sfh, skb);
                break;
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
        case SERVAL_FINWAIT1:
                err = serval_srv_finwait1_state_process(sk, sfh, skb);
                break;
        case SERVAL_FINWAIT2:
                err = serval_srv_finwait2_state_process(sk, sfh, skb);
                break;
        case SERVAL_CLOSING:
                err = serval_srv_closing_state_process(sk, sfh, skb);
                break;
        case SERVAL_LASTACK:
                err = serval_srv_lastack_state_process(sk, sfh, skb);
                break;
        case SERVAL_TIMEWAIT:
                LOG_DBG("Socket in TIMEWAIT, dropping packet\n");
                goto drop;
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
                 
        LOG_DBG("Auto-receiving\n");
        pskb_pull(skb, hdr_len);
        skb_reset_transport_header(skb);
                
        return serval_srv_state_process(sk, sfh, skb);
}

void serval_srv_error_rcv(struct sk_buff *skb, u32 info)
{
        LOG_PKT("received ICMP error!\n");
        
        /* TODO: deal with ICMP errors, e.g., wake user and report. */
}

static int serval_srv_add_source_ext(struct sk_buff *skb, 
                                     struct serval_hdr* sfh, 
                                     struct iphdr *iph, 
                                     unsigned int iph_len) 
{
        //int hdr_len = iph_len;


        /* Add in source header TODO
           skb_push(skb, ntohs(sfh->length));

           sfh = (struct serval_hdr *)skb_push(skb, sizeof(*sfh));
           sfh->flags = flags;
           sfh->protocol = skb->protocol;
           sfh->length = htons(hdr_len);
           memcpy(&sfh->src_flowid, &ssk->local_flowid, sizeof(ssk->local_flowid));
           memcpy(&sfh->dst_flowid, &ssk->peer_flowid, sizeof(ssk->peer_flowid));
        */
        return 0;
}

int serval_srv_rcv(struct sk_buff *skb)
{
        struct sock *sk = NULL;
        struct serval_hdr *sfh = 
                (struct serval_hdr *)skb_transport_header(skb);
        unsigned int hdr_len = 0;
        int err = 0;
        struct service_entry* se = NULL;
        struct service_resolution_iter iter;
        struct dest* dest = NULL;
        struct sk_buff *temp = NULL;
        struct iphdr *iph = NULL;
        unsigned int iph_len = 0;
        struct sk_buff *cskb = NULL;

        if (skb->len < sizeof(*sfh)) {
                LOG_ERR("skb length too short (%u bytes)\n", 
                        skb->len);
                goto drop;
        }

        if (!sfh) {
                LOG_ERR("No serval header\n");
                goto drop;
        }

        hdr_len = ntohs(sfh->length);

        if (hdr_len < sizeof(*sfh)) {
                LOG_ERR("Serval header length too short (%u bytes)\n",
                        hdr_len);
                goto drop;
        }

        if (!pskb_may_pull(skb, hdr_len)) {
                LOG_ERR("cannot pull header (hdr_len=%u)\n",
                        hdr_len);
                goto drop;
        }
        
        LOG_PKT("flowid (src,dst)=(%u,%u)\n",
                ntohl(sfh->src_flowid.s_id), 
                ntohl(sfh->dst_flowid.s_id));
       
        /* If SYN and not ACK is set, we know for sure that we must
         * demux on service id instead of socket id */
        if (!(sfh->flags & SVH_SYN && !(sfh->flags & SVH_ACK))) {
                /* Ok, check if we can demux on socket id */
                sk = serval_sock_lookup_flowid(&sfh->dst_flowid);

                if (!sk) {
                        LOG_INF("No matching sock for flowid %u\n",
                                ntohl(sfh->dst_flowid.s_id));
                }
        }
        
        if (!sk) {
                /* Try to demux on service id */
                struct service_id *srvid = NULL;

                /* Check for connection extension. We require that this
                 * extension always directly follows the main Serval
                 * header */
                if (sfh->flags & SVH_SYN || sfh->flags & SVH_ACK) {
                        struct serval_connection_ext *conn_ext =
                                (struct serval_connection_ext *)(sfh + 1);
                        /* Check for connection extension and do early
                         * drop if SYN or ACK flags are set. */
                        if (!has_connection_extension(sfh))
                                goto drop;

                        srvid = &conn_ext->srvid;
                } else {
                        struct serval_service_ext *srv_ext =
                                (struct serval_service_ext *)(sfh + 1);

                        if (!has_service_extension(sfh))
                                goto drop;

                        srvid = &srv_ext->dst_srvid;
                }

                if (atomic_read(&serval_transit)) {
                        LOG_DBG("Resolve or demux inbound "
                                "packet on serviceID %s\n", 
                                service_id_to_str(srvid));

                        /* Match on the highest priority srvid rule, even if it's
                         * not the sock TODO - use flags/prefix in resolution
                         * This should probably be in a separate function call
                         * serval_srv_transit_rcv or resolve something
                         */
                        se = service_find(srvid, sizeof(*srvid) * 8);

                        if (!se) {
                                LOG_INF("No matching service entry "
                                        "for serviceID %s\n",
                                        service_id_to_str(srvid));
                                goto drop;
                        }

                        service_resolution_iter_init(&iter, se, 0);

                        /*
                          Send to all destinations listed for this service.
                        */
                        dest = service_resolution_iter_next(&iter);

                        if (!dest) {
                                LOG_INF("No dest to transmit resolution on!\n");
                                service_resolution_iter_inc_stats(&iter, -1, -(skb->len - hdr_len));
                                service_resolution_iter_destroy(&iter);
                                service_entry_put(se);
                                err = -EHOSTUNREACH;
                                goto drop_no_stats;
                        }

                        while (dest) {
                                struct dest *next_dest;


                                if (cskb == NULL) {
                                        service_resolution_iter_inc_stats(&iter, 1, skb->len - hdr_len);
                                }

                                next_dest = service_resolution_iter_next(&iter);

                                if (next_dest == NULL) {
                                        cskb = skb;
                                } else {
                                        cskb = skb_clone(skb, GFP_ATOMIC);

                                        if (!cskb) {
                                                LOG_ERR("Skb allocation failed\n");
                                                FREE_SKB(skb);
                                                err = -ENOBUFS;
                                                break;
                                        }
                                        /* Cloned skb will have no socket set. */
                                        //skb_serval_set_owner_w(cskb, sk);
                                }

                                if (is_sock_dest(dest)) {
                                        /* local resolution */
                                        sk = dest->dest_out.sk;
                                        sock_hold(sk);
                                        temp = cskb;
                                } else {
                                        /* Need to drop dst since this packet is routed for
                                         * input. Otherwise, kernel IP stack will be confused when
                                         * transmitting this packet. */
                                        skb_dst_drop(cskb);


                                        iph = (struct iphdr *)skb_network_header(cskb);
                                        iph_len = iph->ihl << 2;
                                        skb_push(cskb, iph_len);

#if defined(OS_LINUX_KERNEL)
                                        err = ip_route_input(cskb, 
                                                             iph->daddr, 
                                                             iph->saddr, 
                                                             iph->tos, 
                                                             cskb->dev);

                                        if (err < 0) {
                                                //LOG_ERR("Could not route resolution packet from %s to %s\n", inet_ntoa(iph->saddr), inet_ntoa(iph->daddr));
                                                LOG_ERR("Could not route resolution packet\n");
                                                FREE_SKB(cskb);
                                                continue;
                                        }

#else
                                        /* Set the output device -
                                         * ip_forward uses the out
                                         * device specified in the
                                         * dst_entry route and assumes
                                         * that skb->dev is the input
                                         * interface*/
                                        if (dest->dest_out.dev)
                                                skb_set_dev(cskb, 
                                                            dest->dest_out.dev);

#endif /* OS_LINUX_KERNEL */

                                        /* TODO Set the true overlay
                                         * source address if the
                                         * packet may be
                                         * ingress-filtered user-level
                                         * raw socket forwarding may
                                         * drop the packet if the
                                         * source address is
                                         * invalid */
                                        serval_srv_add_source_ext(cskb, sfh, 
                                                                  iph, iph_len);

                                        //struct serval_sock *ssk = serval_sk(sk);
                                        //err = ssk->af_ops->queue_xmit(cskb);

                                        err = serval_ipv4_forward_out(cskb);

                                        if (err < 0) {
                                                LOG_ERR("Transit resolution forwarding failed\n");
                                        }

                                }
                                dest = next_dest;
                        }
                        if (!cskb) {
                                /* TODO this is not going to work
                                 * since it needs to be called PRIOR
                                 * to hitting the end*/
                                service_resolution_iter_inc_stats(&iter, -1, -(skb->len - hdr_len));
                        }

                        service_resolution_iter_destroy(&iter);
                        service_entry_put(se);

                        /* if no local socket destination encountered,
                         * return */
                        if (!sk) {
                                return 0;
                        }

                        skb = temp;
                } else {
                        /*LOG_DBG("Demux on serviceID %s\n", service_id_to_str(srvid));*/

                        /* only allow listening socket demux */
                        sk = serval_sock_lookup_serviceid(srvid);

                        if (!sk) {
                                LOG_INF("No matching sock for serviceID %s\n",
                                        service_id_to_str(srvid));
                                goto drop;
                        }
                }
        }

        /* We only reach this point if a valid local socket destination
         * has been found */
        /* Drop check if control queue is full here - this should
         * increment the per-service drop stats as well*/
        if (is_control_packet(skb) && 
            serval_srv_ctrl_queue_len(sk) >= MAX_CTRL_QUEUE_LEN) {

                /* Don't treat local flows as resolutions
                   if(!se) {
                   struct serval_sock *ssk = serval_sk(sk);
                   se = service_find(ssk->hash_key, ssk->hash_key_len);
                   }

                   if(se) {
                   service_entry_inc_dest_stats(se, NULL, 0, -1, -skb->len);
                   service_entry_put(se);
                   }
                */
                goto drop_no_stats;
        }

        bh_lock_sock_nested(sk);

        if (!sock_owned_by_user(sk)) {
                err = serval_srv_do_rcv(sk, skb);
        } else {
                /*
                  Add to backlog and process in user context when
                  the user process releases its lock ownership.
                  
                  Note, for kernels >= 2.6.33 the sk_add_backlog()
                  function adds the total allocated memory for the
                  backlog to that of the receive buffer and rejects
                  queuing in case the new total overreaches the
                  socket's configured receive buffer size.

                  This may not be the wanted behavior in case we are
                  processing control packets in the backlog (i.e.,
                  control packets can be dropped because the data
                  receive buffer is full. This might not be a big deal
                  though, as control packets are retransmitted.
                */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
                if (sk_add_backlog(sk, skb)) {
                        bh_unlock_sock(sk);
                        sock_put(sk);
                        goto drop;
                }
#else
                sk_add_backlog(sk, skb);
#endif
        }

        /* Don't treat established flow packets as resolutions
           if(!se) {
           struct serval_sock *ssk = serval_sk(sk);
           se = service_find(ssk->hash_key, ssk->hash_key_len);
           }

           if(se) {
           service_entry_inc_dest_stats(se, NULL, 0, -1, -skb->len);
           service_entry_put(se);
           }
        */

        bh_unlock_sock(sk);
        sock_put(sk);

        /*
          IP will resubmit packet if return value is less than
          zero. Therefore, make sure we always return 0, even if we drop the
          packet.
        */

	return 0;
drop:
        /*TODO - does this need a sock_put?*/
        service_inc_stats(-1, -(skb->len - hdr_len));
drop_no_stats:
        FREE_SKB(skb);
        return 0;
}

static int serval_srv_rexmit(struct sock *sk)
{        
        struct sk_buff *skb;
        int err;

        skb = serval_srv_ctrl_queue_head(sk);
        
        if (!skb) {
                LOG_ERR("No packet to retransmit!\n");
                return -1;
        }
        
        err = serval_srv_transmit_skb(sk, skb, 1, GFP_ATOMIC);
        
        if (err < 0) {
                LOG_ERR("retransmit failed\n");
        }

        return err;
}

void serval_srv_rexmit_timeout(unsigned long data)
{
        struct sock *sk = (struct sock *)data;
        struct serval_sock *ssk = serval_sk(sk);

        bh_lock_sock_nested(sk);

        LOG_DBG("Retransmit timeout sock=%p num=%u backoff=%u\n", 
                sk, ssk->retransmits, backoff[ssk->retransmits]);
        
        if (backoff[ssk->retransmits + 1] == 0) {
                /* TODO: check error values here */
                LOG_DBG("NOT rescheduling timer!\n");
                sk->sk_err = ETIMEDOUT;
                serval_sock_done(sk);
        } else {
                LOG_DBG("retransmitting and rescheduling timer\n");
                sk_reset_timer(sk, &serval_sk(sk)->retransmit_timer,
                               jiffies + (msecs_to_jiffies(ssk->rto) * 
                                          backoff[ssk->retransmits]));
                serval_srv_rexmit(sk);
                
                if (backoff[ssk->retransmits + 1] != 0)
                        ssk->retransmits++;
        }
        bh_unlock_sock(sk);
        sock_put(sk);
}

/* This timeout is used for TIMEWAIT and FINWAIT2 */
void serval_srv_timewait_timeout(unsigned long data)
{
        struct sock *sk = (struct sock *)data;
        bh_lock_sock_nested(sk);
        LOG_DBG("Timeout in state %s\n", serval_sock_state_str(sk));
        serval_sock_done(sk);
        bh_unlock_sock(sk);
        /* put for the timer. */
        sock_put(sk);
}

static inline int serval_srv_do_xmit(struct sk_buff *skb)
{
        struct sock *sk = skb->sk;
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;

        /*
          FIXME: we kind of hard code the outgoing device here based
          on what has been bound to the socket in the connection
          setup phase. Instead, the device should be resolved based
          on, e.g., dst IP (if it exists at this point).

          However, we currently do not implement an IP routing table
          for userlevel, which would otherwise be used for this
          resolution. Kernel space should work, because it routes
          packet according to the kernel's routing table, thus
          figuring out the device along the way.

          Packets that are sent using an advisory IP may fail in
          queue_xmit for userlevel unless the socket has had its
          interface set by a previous send event.
        */
        if (!skb->dev && ssk->dev)
                skb_set_dev(skb, ssk->dev);

        if (memcmp(&SERVAL_SKB_CB(skb)->addr, &null_addr,
                   sizeof(null_addr)) == 0) {
                /* Copy address from socket if no address is set */
                memcpy(&SERVAL_SKB_CB(skb)->addr,
                       &inet_sk(sk)->inet_daddr,
                       sizeof(inet_sk(sk)->inet_daddr));
        }

        err = ssk->af_ops->queue_xmit(skb);

        if (err < 0) {
                LOG_ERR("xmit failed\n");
        }

        return err;
}

static inline int serval_srv_add_conn_ext(struct sock *sk, 
                                          struct sk_buff *skb,
                                          int flags)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_connection_ext *conn_ext;
 
        conn_ext = (struct serval_connection_ext *)
                skb_push(skb, sizeof(*conn_ext));
        conn_ext->type = SERVAL_CONNECTION_EXT;
        conn_ext->length = htons(sizeof(*conn_ext));
        conn_ext->flags = flags;
        conn_ext->seqno = htonl(SERVAL_SKB_CB(skb)->seqno);
        conn_ext->ackno = htonl(ssk->rcv_seq.nxt);
        memcpy(&conn_ext->srvid, &SERVAL_SKB_CB(skb)->srvid, 
               sizeof(SERVAL_SKB_CB(skb)->srvid));
        memcpy(conn_ext->nonce, ssk->local_nonce, SERVAL_NONCE_SIZE);
        return sizeof(*conn_ext);
}

static inline int serval_srv_add_ctrl_ext(struct sock *sk, 
                                          struct sk_buff *skb,
                                          int flags)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_control_ext *ctrl_ext;

        ctrl_ext = (struct serval_control_ext *)
                skb_push(skb, sizeof(*ctrl_ext));
        ctrl_ext->type = SERVAL_CONTROL_EXT;
        ctrl_ext->length = htons(sizeof(*ctrl_ext));
        ctrl_ext->flags = flags;
        ctrl_ext->seqno = htonl(SERVAL_SKB_CB(skb)->seqno);
        ctrl_ext->ackno = htonl(ssk->rcv_seq.nxt);
        memcpy(ctrl_ext->nonce, ssk->local_nonce, SERVAL_NONCE_SIZE);
        return sizeof(*ctrl_ext);
}

static inline int serval_srv_add_service_ext(struct sock *sk, 
                                             struct sk_buff *skb,
                                             int flags)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_service_ext *srv_ext;

        srv_ext = (struct serval_service_ext *)
                skb_push(skb, sizeof(*srv_ext));
        srv_ext->type = SERVAL_SERVICE_EXT;
        srv_ext->length = htons(sizeof(*srv_ext));
        srv_ext->flags = flags;
        memcpy(&srv_ext->dst_srvid, &SERVAL_SKB_CB(skb)->srvid, 
               sizeof(SERVAL_SKB_CB(skb)->srvid));
        /* FIXME: check if socket is bound, if not, indicate somehow
         * that the source service id is not valid (e.g., with a
         * flag). */
        memcpy(&srv_ext->src_srvid, &ssk->local_srvid, 
               sizeof(ssk->local_srvid));

        return sizeof(*srv_ext);
}

int serval_srv_transmit_skb(struct sock *sk, struct sk_buff *skb, 
                            int clone_it, gfp_t gfp_mask)
{
        struct serval_sock *ssk = serval_sk(sk);
	struct service_entry *se;
	struct dest *dest;
        struct serval_hdr *sfh;
        uint8_t flags = 0;
        int hdr_len = sizeof(*sfh);
	int err = 0;
        struct service_resolution_iter iter;
        struct sk_buff *cskb = NULL;
        int dlen = skb->len - 8; /* KLUDGE?! TODO not sure where the
                                    extra 8 bytes are coming from at
                                    this point */
    
	if (likely(clone_it)) {
		if (unlikely(skb_cloned(skb)))
			skb = pskb_copy(skb, gfp_mask);
		else
			skb = skb_clone(skb, gfp_mask);
		if (unlikely(!skb)) {
                        /* Shouldn't free the passed skb here, since
                         * we were asked to clone it. That probably
                         * means the original skb sits in a queue
                         * somewhere, and freeing it would be bad. */
                        return -ENOBUFS;
                }
                if (!skb->sk)
                        skb_serval_set_owner_w(skb, sk);
	}

        /* NOTE:
         *
         * Do not use skb_set_owner_w(skb, sk) here as that will
         * reserve write space for the socket on the transport
         * queue. We might not want to reserve such space for control
         * packets as they might then fill up the write queue/buffer
         * for the socket. However, skb_set_owner_w(skb, sk) also
         * guarantees that the socket is not released until skb is
         * free'd, which is good. I guess we could implement our own
         * version of skb_set_owner_w() and grab a socket refcount
         * instead, which is released in the skb's destructor.
         */

        /* Add appropriate flags and headers */
        switch (SERVAL_SKB_CB(skb)->pkttype) {
        case SERVAL_PKT_CONN_SYNACK:
                flags |= SVH_ACK;
        case SERVAL_PKT_CONN_SYN:
                flags |= SVH_SYN;
                hdr_len += serval_srv_add_conn_ext(sk, skb, 0);
                break;
        case SERVAL_PKT_CONN_ACK:
                flags |= SVH_ACK;
                hdr_len += serval_srv_add_conn_ext(sk, skb, 0);
                break;
        case SERVAL_PKT_ACK:
        case SERVAL_PKT_CLOSEACK:
                flags |= SVH_ACK;
                hdr_len += serval_srv_add_ctrl_ext(sk, skb, 0);
                break;
        case SERVAL_PKT_CLOSE:
                flags |= SVH_FIN;
                hdr_len += serval_srv_add_ctrl_ext(sk, skb, 0);
                break;
        case SERVAL_PKT_DATA:
                /* Unconnected datagram, add service extension */
                if (sk->sk_state == SERVAL_INIT && 
                    sk->sk_type == SOCK_DGRAM) {
                        hdr_len += serval_srv_add_service_ext(sk, skb, 0);
                }
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
        
        /* If we are connected, transmit immediately */
        if ((1 << sk->sk_state) & (SERVALF_CONNECTED | 
                                   SERVALF_FINWAIT1 | 
                                   SERVALF_FINWAIT2 | 
                                   SERVALF_CLOSING | 
                                   SERVALF_CLOSEWAIT))
		return serval_srv_do_xmit(skb);
        
	/* Unresolved packet, use service id to resolve IP, unless IP
         * is set already by user. */
        if (memcmp(&SERVAL_SKB_CB(skb)->addr, &null_addr,
                   sizeof(null_addr)) != 0) {
                LOG_DBG("Sending packet to user-specified "
                        "advisory address: %u\n", 
                        SERVAL_SKB_CB(skb)->addr.net_un.un_ip.s_addr);
                /* for user-space, need to specify a device - the
                 * kernel will route */
#if defined(OS_USER)
                skb_set_dev(skb, dev_get_by_index(NULL, 0));
#endif
                /* note that the service resolution stats
                 * (packets/bytes) will not be incremented here In the
                 * future, the stats should be defined as SNMP
                 * counters in include/net/snmp.h and incremented with
                 * the appropriate per-cpu atomic inc macros TODO
                 */
                return serval_srv_do_xmit(skb);
        }

        /* TODO - prefix, flags??*/
        //ssk->srvid_flags;
        //ssk->srvid_prefix;
        se = service_find(&SERVAL_SKB_CB(skb)->srvid, 
                          sizeof(struct service_id) * 8);

	if (!se) {
		LOG_INF("service lookup failed for [%s]\n",
                        service_id_to_str(&SERVAL_SKB_CB(skb)->srvid));
                service_inc_stats(-1, -dlen);
                FREE_SKB(skb);
		return -EADDRNOTAVAIL;
	}

	service_resolution_iter_init(&iter, se, 0);
        /*
          Send to all destinations resolved for this service.
        */
	
	dest = service_resolution_iter_next(&iter);
	
        if (!dest) {
                LOG_DBG("No device to transmit on!\n");
                service_resolution_iter_inc_stats(&iter, -1, -dlen);
                FREE_SKB(skb);
                service_resolution_iter_destroy(&iter);
                service_entry_put(se);
                return -EHOSTUNREACH;
        }

	while (dest) {
		struct dest *next_dest;
		
                /* Remember the flow destination */
		if (is_sock_dest(dest)) {
                        /*use a localhost address and bounce it off
                         * the IP layer*/
                        memcpy(&SERVAL_SKB_CB(skb)->addr,
                               &local_addr, sizeof(struct net_addr));
		} else {
                        memcpy(&SERVAL_SKB_CB(skb)->addr, 
                               dest->dst, 
                               sizeof(struct net_addr) < dest->dstlen ? 
                               sizeof(struct net_addr) : dest->dstlen);
                }

                if (cskb == NULL) {
                        service_resolution_iter_inc_stats(&iter, 1, dlen);
                }

                next_dest = service_resolution_iter_next(&iter);
		
                if (next_dest == NULL) {
			cskb = skb;
		} else {
                        /* Always be atomic here since we are holding
                         * socket lock */
                        cskb = skb_clone(skb, GFP_ATOMIC);
			
			if (!cskb) {
				LOG_ERR("Allocation failed\n");
                                FREE_SKB(skb);
                                err = -ENOBUFS;
				break;
			}
                        /* Cloned skb will have no socket set. */
                        skb_serval_set_owner_w(cskb, sk);
		}
                
		/* Set the output device */
                if (is_sock_dest(dest)) {
                        /* kludgey but sets the output device for
                         * reaching a local socket destination to the
                         * default device TODO - make sure this is
                         * appropriate for kernel operation as well
                         */
                        skb_set_dev(cskb, dev_get_by_index(NULL, 0));
                } else if (dest->dest_out.dev) {
                        skb_set_dev(cskb, dest->dest_out.dev);
                }

                //snprintf(buffer, dest->dstlen, "%s", dest->dst)
		err = ssk->af_ops->queue_xmit(cskb);

		if (err < 0) {
			LOG_ERR("xmit failed\n");
		}
		dest = next_dest;
	}

        service_resolution_iter_destroy(&iter);
	service_entry_put(se);

	return err;
}

/* This function is typically called by transport to send data */
int serval_srv_xmit_skb(struct sk_buff *skb) 
{
        return serval_srv_transmit_skb(skb->sk, skb, 0, GFP_ATOMIC);
}
