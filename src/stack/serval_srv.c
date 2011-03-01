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
#include <neighbor.h>
#endif
#include <serval_request_sock.h>
#include <service.h>

#define EXTRA_HDR_SIZE (20)
#define IP_HDR_SIZE
/* payload + LL + IP + extra */
#define SERVAL_MAX_HDR (MAX_HEADER + IP_HDR_SIZE + EXTRA_HDR_SIZE + \
                        sizeof(struct serval_hdr) +                 \
                        sizeof(struct serval_connection_ext))

extern int serval_tcp_rcv(struct sk_buff *);
extern int serval_udp_rcv(struct sk_buff *);
extern atomic_t serval_nr_socks;

static struct net_addr null_addr = { 
        .net_raw = { 0x00, 0x00, 0x00, 0x00 } 
};
/* Backoff multipliers for retransmission, fail when reaching 0. */
static uint8_t backoff[] = { 1, 2, 4, 8, 16, 32, 64, 0 };

static int serval_srv_state_process(struct sock *sk, 
                                    struct serval_hdr *sfh, 
                                    struct sk_buff *skb);

static int serval_srv_transmit_skb(struct sock *sk, struct sk_buff *skb, 
                                   int clone_it, gfp_t gfp_mask);

static inline int has_connection_extension(struct serval_hdr *sfh)
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
        
        if (conn_ext->type != SERVAL_CONNECTION_EXT || 
            ntohs(conn_ext->length) != sizeof(*conn_ext)) {
                LOG_ERR("No connection extension, bad extension type\n");
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
                LOG_ERR("No service extension, hdr_len=%u\n", 
                        hdr_len);
                return 0;
        }
        
        if (srv_ext->type != SERVAL_SERVICE_EXT || 
            ntohs(srv_ext->length) != sizeof(*srv_ext)) {
                LOG_ERR("No service extension, bad extension type\n");
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
                LOG_ERR("Seqno not in sequence received=%u next=%u."
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
                LOG_ERR("Connection extension has bad nonce\n");
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
                LOG_ERR("No control extension, hdr_len=%u\n", 
                        hdr_len);
                return 0;
        }
        
        if (ctrl_ext->type != SERVAL_CONTROL_EXT ||
            ntohs(ctrl_ext->length) != sizeof(*ctrl_ext)) {
                LOG_ERR("No control extension, bad extension type\n");
                return 0;
        }

        if (memcmp(ctrl_ext->nonce, ssk->peer_nonce, 
                   SERVAL_NONCE_SIZE) != 0) {
                LOG_ERR("Control extension has bad nonce\n");
                return 0;
        }

        return 1;
}

static void serval_srv_queue_ctrl_skb(struct sock *sk, struct sk_buff *skb)
{
	skb_header_release(skb);
	serval_srv_add_ctrl_queue_tail(sk, skb);
        LOG_DBG("queue packet seqno=%u\n", SERVAL_SKB_CB(skb)->seqno);
        /* Check if the skb became first in queue, in that case update
         * unacknowledged seqno. */
        if (skb == serval_srv_ctrl_queue_head(sk)) {
                serval_sk(sk)->snd_seq.una = SERVAL_SKB_CB(skb)->seqno;
                LOG_DBG("setting snd_una=%u\n",
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
        
        LOG_DBG("writing from queue snd_una=%u snd_nxt=%u snd_wnd=%u\n",
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

        LOG_DBG("sent %u packets\n", num);

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
                        LOG_DBG("cleaned rtx queue seqno=%u\n", 
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

        LOG_DBG("cleaned up %u packets from rtx queue\n", num);
        
        /* Did we remove the first packet in the queue? */
        if (serval_srv_ctrl_queue_head(sk) != fskb) {
                sk_stop_timer(sk, &serval_sk(sk)->retransmit_timer);
                ssk->retransmits = 0;
        }

        if (serval_srv_ctrl_queue_head(sk)) {
                LOG_DBG("Setting retrans timer\n");
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
        
        skb = ALLOC_SKB(SERVAL_MAX_HDR, GFP_ATOMIC);

        if (!skb)
                return -ENOMEM;
        
        skb_reserve(skb, SERVAL_MAX_HDR);
        skb_serval_set_owner_w(skb, sk);
        skb->protocol = 0;
        
        memcpy(&SERVAL_SKB_CB(skb)->srvid, srvid, sizeof(*srvid));
        SERVAL_SKB_CB(skb)->pkttype = SERVAL_PKT_CONN_SYN;
        SERVAL_SKB_CB(skb)->seqno = ssk->snd_seq.iss;
        ssk->snd_seq.nxt = ssk->snd_seq.iss + 1;
        memcpy(&SERVAL_SKB_CB(skb)->addr, &inet_sk(sk)->inet_daddr, 
               sizeof(inet_sk(sk)->inet_daddr));

        LOG_DBG("Sending SYN seqno=%u\n",
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
                                
                if (sk->sk_state == SERVAL_CLOSEWAIT) {
                        serval_sock_set_state(sk, SERVAL_LASTACK);
                } else {
                        serval_sock_set_state(sk, SERVAL_FINWAIT1);
                }
                /* We are under lock, so allocation must be atomic */
                /* Socket is locked, keep trying until memory is available. */
                for (;;) {
                        skb = ALLOC_SKB(SERVAL_MAX_HDR, GFP_ATOMIC);
                        
                        if (skb)
                                break;
                        yield();
                }
                
                skb_reserve(skb, SERVAL_MAX_HDR);
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

        skb = ALLOC_SKB(SERVAL_MAX_HDR, GFP_ATOMIC);
                        
        if (!skb)
                return -ENOMEM;
        
        skb_reserve(skb, SERVAL_MAX_HDR);
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
        struct serval_request_sock *rsk;
        struct serval_connection_ext *conn_ext = 
                (struct serval_connection_ext *)(sfh + 1);
        unsigned int hdr_len = ntohs(sfh->length);
        struct net_addr saddr;
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

        LOG_DBG("SYN seqno=%u\n", ntohl(conn_ext->seqno));

#if defined(OS_USER)
        /* Cache neighbor */
        neighbor_add((struct net_addr *)&ip_hdr(skb)->saddr, 32, 
                     skb->dev, eth_hdr(skb)->h_source, 
                     ETH_ALEN, GFP_ATOMIC);
#endif

        if (sk->sk_ack_backlog >= sk->sk_max_ack_backlog) 
                goto drop;

        /* Call upper protocol handler */
        err = ssk->af_ops->conn_request(sk, skb);
        
        if (err < 0)
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
        memcpy(rsk->peer_nonce, conn_ext->nonce, SERVAL_NONCE_SIZE);
        rsk->rcv_seq = ntohl(conn_ext->seqno);

        list_add(&rsk->lh, &ssk->syn_queue);
        
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
        SERVAL_SKB_CB(skb)->pkttype = SERVAL_PKT_CONN_SYNACK;
        conn_ext->seqno = htonl(rsk->iss_seq);
        conn_ext->ackno = htonl(rsk->rcv_seq + 1);

        /* Copy our nonce to connection extension */
        memcpy(conn_ext->nonce, rsk->local_nonce, SERVAL_NONCE_SIZE);
       
        sfh->flags = SVH_SYN | SVH_ACK;
        skb->protocol = IPPROTO_SERVAL;

        /* Need to drop dst since this packet is routed for
         * input. Otherwise, kernel IP stack will be confused when
         * transmitting this packet. */
        skb_dst_drop(skb);
#if defined(OS_LINUX_KERNEL)
        {
                /*
                  For kernel, we need to route this packet and
                  associate a dst_entry with the skb for it to be
                  accepted by the kernel IP stack.
                 */
                struct dst_entry *dst;

                dst = serval_ipv4_req_route(sk, rsk, skb->protocol,
                                            saddr.net_ip.s_addr,
                                            ip_hdr(skb)->saddr);

                if (!dst) {
                        LOG_ERR("SYN-ACK not routable\n");
                        goto drop;
                }

                skb_dst_set(skb, dst);
        }
#endif /* OS_LINUX_KERNEL */

        LOG_DBG("Sending SYNACK seqno=%u ackno=%u\n",
                ntohl(conn_ext->seqno),
                ntohl(conn_ext->ackno));
                
        /* Cannot use serval_srv_transmit_skb here since we do not yet
         * have a full accepted socket (sk is the listening sock). */
        err = serval_ipv4_build_and_send_pkt(skb, sk, 
                                             saddr.net_ip.s_addr,
                                             ip_hdr(skb)->saddr, NULL);
done:        
        return err;
drop:
        FREE_SKB(skb);
        goto done;
}

/*
  Create new child socket in RESPOND state. This happens as a result
  of a LISTEN:ing socket receiving an ACK in response to a SYNACK.  */
static struct sock *
serval_srv_create_respond_sock(struct sock *sk, 
                               struct sk_buff *skb,
                               struct serval_request_sock *req,
                               struct dst_entry *dst)
{
        struct sock *nsk;

        nsk = sk_clone(sk, GFP_ATOMIC);

        if (nsk) {
                atomic_inc(&serval_nr_socks);
                serval_sock_init(nsk);

                /* Transport protocol specific init. */                
                serval_sk(sk)->af_ops->conn_child_sock(sk, skb, nsk, NULL);
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
        struct serval_request_sock *rsk;
        struct serval_connection_ext *conn_ext = 
                (struct serval_connection_ext *)(sfh + 1);

        list_for_each_entry(rsk, &ssk->syn_queue, lh) {
                if (memcmp(&rsk->local_flowid, &sfh->dst_flowid, 
                           sizeof(rsk->local_flowid)) == 0) {
                        struct sock *nsk;
                        struct serval_sock *nssk;

                        if (memcmp(rsk->peer_nonce, conn_ext->nonce, 
                                   SERVAL_NONCE_SIZE) != 0) {
                                LOG_ERR("Bad nonce\n");
                                return NULL;
                        }

                        if (ntohl(conn_ext->seqno) != rsk->rcv_seq + 1) {
                                LOG_ERR("Bad seqno received=%u expected=%u\n",
                                        ntohl(conn_ext->seqno), 
                                        rsk->rcv_seq + 1);
                                return NULL;
                        }
                        if (ntohl(conn_ext->ackno) != rsk->iss_seq + 1) {
                                LOG_ERR("Bad ackno received=%u expected=%u\n",
                                        ntohl(conn_ext->ackno), 
                                        rsk->iss_seq + 1);
                                return NULL;
                        }
                        /* Move request sock to accept queue */
                        list_del(&rsk->lh);
                        list_add_tail(&rsk->lh, &ssk->accept_queue);
                        
                        nsk = serval_srv_create_respond_sock(sk, skb, 
                                                             rsk, NULL);
                        
                        if (!nsk)
                                return NULL;
                        
                        nsk->sk_state = SERVAL_RESPOND;
                        nssk = serval_sk(nsk);
                        memcpy(&nssk->local_flowid, &rsk->local_flowid, 
                               sizeof(rsk->local_flowid));
                        memcpy(&nssk->peer_flowid, &rsk->peer_flowid, 
                               sizeof(rsk->peer_flowid));
                        memcpy(&nssk->peer_srvid, &rsk->peer_srvid,
                               sizeof(rsk->peer_srvid));
                        memcpy(&inet_sk(sk)->inet_daddr, &rsk->dst_addr,
                               sizeof(rsk->dst_addr));
                        memcpy(nssk->local_nonce, rsk->local_nonce, 
                               SERVAL_NONCE_SIZE);
                        memcpy(nssk->peer_nonce, rsk->peer_nonce, 
                               SERVAL_NONCE_SIZE);
                        nssk->snd_seq.iss = rsk->iss_seq;
                        nssk->snd_seq.una = rsk->iss_seq;
                        nssk->snd_seq.nxt = rsk->iss_seq + 1;
                        nssk->rcv_seq.iss = rsk->rcv_seq;
                        nssk->rcv_seq.nxt = rsk->rcv_seq + 1;
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
                LOG_DBG("received valid ACK ackno=%u\n", 
                        ackno);
                err = 0;
        } else {
                LOG_ERR("ackno %u out of sequence, expected %u\n",
                        ackno, serval_sk(sk)->snd_seq.una + 1);
        }
done:
        return err;
}

static int serval_srv_rcv_fin(struct sock *sk, struct serval_hdr *sfh,
                              struct sk_buff *skb)
{
        int err = 0;
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_control_ext *ctrl_ext = 
                (struct serval_control_ext *)(sfh + 1);

        LOG_DBG("received FIN\n");
        
        if (!has_valid_control_extension(sk, sfh)) {
                LOG_DBG("Bad control extension\n");
                return -1;
        }
        
        if (has_valid_seqno(ntohl(ctrl_ext->seqno), ssk)) {
                sk->sk_shutdown |= SEND_SHUTDOWN;
                sock_set_flag(sk, SOCK_DONE);
                serval_sk(sk)->rcv_seq.nxt = ntohl(ctrl_ext->seqno) + 1;
                
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

                /* Give transport a chance to chip in */ 
                if (ssk->af_ops->close_request)
                        err = ssk->af_ops->close_request(sk, skb);
                
                err = serval_srv_send_close_ack(sk, sfh, skb);
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
                err = serval_srv_rcv_fin(sk, sfh, skb);

                if (err == 0) {
                        /* Valid FIN means valid ctrl header that may
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
        int err = 0;
                
        if (!has_connection_extension(sfh)) {
                LOG_ERR("No connection extension\n");
                goto drop;
        }
        
        if (!(sfh->flags & SVH_SYN && sfh->flags & SVH_ACK)) {
                LOG_ERR("packet is not a SYNACK\n");
                goto drop;
        }

        LOG_DBG("Got SYNACK seqno=%u ackno=%u\n",
                ntohl(conn_ext->seqno), 
                ntohl(conn_ext->ackno));

#if defined(OS_USER)
        /* Cache neighbor */
        neighbor_add((struct net_addr *)&ip_hdr(skb)->saddr, 32, 
                     skb->dev, eth_hdr(skb)->h_source, 
                     ETH_ALEN, GFP_ATOMIC);
#endif
        serval_sock_set_state(sk, SERVAL_CONNECTED);
        
        /* Let user know we are connected. */
	if (!sock_flag(sk, SOCK_DEAD)) {
                sk->sk_state_change(sk);
                sk_wake_async(sk, SOCK_WAKE_IO, POLL_OUT);
        }

        /* Save device and peer flow id */
        ssk->dev = skb->dev;
        dev_hold(ssk->dev);
        memcpy(&inet_sk(sk)->inet_daddr, &ip_hdr(skb)->saddr, 
               sizeof(inet_sk(sk)->inet_daddr));

        /* Save nonce */
        memcpy(ssk->peer_nonce, conn_ext->nonce, SERVAL_NONCE_SIZE);
        /* Update socket ids */
        memcpy(&ssk->peer_flowid, &sfh->src_flowid, 
               sizeof(sfh->src_flowid));
      
        /* Update expected rcv sequence number */
        ssk->rcv_seq.nxt = ntohl(conn_ext->seqno) + 1;

        /* Process any ACK */
        serval_srv_ack_process(sk, sfh, skb);
        
        /* Update control block */
        SERVAL_SKB_CB(skb)->pkttype = SERVAL_PKT_CONN_ACK;
        memcpy(&SERVAL_SKB_CB(skb)->srvid, &ssk->peer_srvid, 
               sizeof(ssk->peer_srvid));
        memcpy(&SERVAL_SKB_CB(skb)->addr, &inet_sk(sk)->inet_daddr, 
               sizeof(inet_sk(sk)->inet_daddr));

        /* Do not increase sequence number for pure ACK */
        SERVAL_SKB_CB(skb)->seqno = ssk->snd_seq.nxt;
        skb->protocol = IPPROTO_SERVAL;
        skb_serval_set_owner_w(skb, sk);

        /* Xmit, do not queue ACK */
        err = serval_srv_transmit_skb(sk, skb, 0, GFP_ATOMIC);
                
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
        int err = 0;

        if (!has_valid_connection_extension(sk, sfh)) {
                LOG_ERR("No connection extension\n");
                goto drop;
        }

        /* Process ACK */
        if (serval_srv_ack_process(sk, sfh, skb) == 0) {
                
                /* Valid ACK */
                serval_sock_set_state(sk, SERVAL_CONNECTED);
                
                LOG_DBG("\n");
                
                /* Let user know */
                sk->sk_state_change(sk);
                sk_wake_async(sk, SOCK_WAKE_IO, POLL_OUT);

                /* Save device and peer flow id */
                ssk->dev = skb->dev;
                dev_hold(ssk->dev);
                memcpy(&inet_sk(sk)->inet_daddr, &ip_hdr(skb)->saddr, 
                       sizeof(inet_sk(sk)->inet_daddr));
        }
drop:
        FREE_SKB(skb);

        return err;
}

static int serval_srv_finwait1_state_process(struct sock *sk, 
                                             struct serval_hdr *sfh, 
                                             struct sk_buff *skb)
{
        int err;
        
        if (sfh->flags & SVH_FIN) {
                SERVAL_SKB_CB(skb)->pkttype = SERVAL_PKT_CLOSE;
                err = serval_srv_rcv_fin(sk, sfh, skb);

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

        FREE_SKB(skb);
        
        return err;
}

static int serval_srv_finwait2_state_process(struct sock *sk, 
                                             struct serval_hdr *sfh, 
                                             struct sk_buff *skb)
{
        int err = 0;
        
        if (sfh->flags & SVH_FIN) {
                SERVAL_SKB_CB(skb)->pkttype = SERVAL_PKT_CLOSE;
                err = serval_srv_rcv_fin(sk, sfh, skb);

                if (err == 0) {
                        serval_srv_timewait(sk, SERVAL_TIMEWAIT);
                }
        }

        FREE_SKB(skb);

        return err;
}

static int serval_srv_closing_state_process(struct sock *sk, 
                                            struct serval_hdr *sfh, 
                                            struct sk_buff *skb)
{
        int err = 0;

        err = serval_srv_ack_process(sk, sfh, skb);
                
        if (err == 0) {
                /* ACK was valid */
                serval_srv_timewait(sk, SERVAL_TIMEWAIT);
        }

        FREE_SKB(skb);

        return err;
}

static int serval_srv_lastack_state_process(struct sock *sk, 
                                            struct serval_hdr *sfh, 
                                            struct sk_buff *skb)
{
        int err = 0;
        
        err = serval_srv_ack_process(sk, sfh, skb);
                
        if (err == 0) {
                /* ACK was valid */
                serval_sock_done(sk);
        }

        FREE_SKB(skb);

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

void serval_srv_error_rcv(struct sk_buff *skb, u32 info)
{
        LOG_ERR("received ICMP error!\n");

        /* TODO: deal with ICMP errors, e.g., wake user and report. */
}

int serval_srv_rcv(struct sk_buff *skb)
{
        struct sock *sk = NULL;
        struct serval_hdr *sfh = 
                (struct serval_hdr *)skb_transport_header(skb);
        unsigned int hdr_len;
        int err = 0;

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
        
        LOG_DBG("flowid (src,dst)=(%u,%u)\n",
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

                LOG_DBG("Demux on serviceID %s\n", 
                        service_id_to_str(srvid));

                sk = serval_sock_lookup_serviceid(srvid);
                
                if (!sk) {
                        LOG_INF("No matching sock for serviceID %s\n",
                                service_id_to_str(srvid));
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
	struct net_device *dev;
        struct serval_hdr *sfh;
        uint8_t flags = 0;
        int hdr_len = sizeof(*sfh);
	int err = 0;

	if (likely(clone_it)) {
		if (unlikely(skb_cloned(skb)))
			skb = pskb_copy(skb, gfp_mask);
		else
			skb = skb_clone(skb, gfp_mask);
		if (unlikely(!skb))
			return -ENOBUFS;

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
         * guarantess that the socket is not released until skb is
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

        LOG_DBG("Tx length=%u skb->len=%u\n", ntohs(sfh->length), skb->len);

        skb->protocol = IPPROTO_SERVAL;

        /* If we are connected, transmit immediately */
	if (sk->sk_state == SERVAL_CONNECTED)
		return serval_srv_do_xmit(skb);
        
	/* Unresolved packet, use service id to resolve IP, unless IP
         * is set already by user. */
        if (memcmp(&SERVAL_SKB_CB(skb)->addr, &null_addr,
                            sizeof(null_addr)) != 0) {
                return serval_srv_do_xmit(skb);
        }

	se = service_find_type(&SERVAL_SKB_CB(skb)->srvid,
                               SERVICE_ENTRY_GLOBAL);
	
	if (!se) {
		LOG_INF("service lookup failed\n");
                FREE_SKB(skb);
		return -EADDRNOTAVAIL;
	}
        
        /* 
           Send on all interfaces listed for this service.
        */
	service_entry_dev_iterate_begin(se);
	
	dev = service_entry_dev_next(se);
	
        if (!dev) {
                if (se->sk) {
                        LOG_INF("local service routing NOT implemented\n");
                } else {
                        LOG_DBG("No device to transmit on!\n");
                }
                FREE_SKB(skb);
                service_entry_dev_iterate_end(se);
                service_entry_put(se);
                return -EHOSTUNREACH;
        }

	while (dev) {
		struct sk_buff *cskb;
		struct net_device *next_dev;
		
                /* Remember the flow destination */
		service_entry_dev_dst(se, &SERVAL_SKB_CB(skb)->addr,
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
                        /* Cloned skb will have no socket set. */
                        skb_serval_set_owner_w(cskb, sk);

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

/* This function is typically called by transport to send data */
int serval_srv_xmit_skb(struct sk_buff *skb) 
{
        return serval_srv_transmit_skb(skb->sk, skb, 0, GFP_ATOMIC);
}
