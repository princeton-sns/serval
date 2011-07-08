/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/platform.h>
#include <serval/platform_tcpip.h>
#include <serval/skbuff.h>
#include <serval/debug.h>
#include <serval_sock.h>
#include <serval/netdevice.h>
#include <serval_sal.h>
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

static struct net_addr local_addr = {
        .net_raw = { 0x7F, 0x00, 0x00, 0x01 }
};

static struct net_addr zero_addr = {
        .net_raw = { 0x00, 0x00, 0x00, 0x00 }
};

#if defined(ENABLE_DEBUG)
static const char *serval_pkt_names[] = {
        [SERVAL_PKT_DATA]    = "SERVAL_PKT_DATA",
        [SERVAL_PKT_SYN]     = "SERVAL_PKT_SYN",
        [SERVAL_PKT_RESET]   = "SERVAL_PKT_RESET",
        [SERVAL_PKT_CLOSE]   = "SERVAL_PKT_CLOSE",
        [SERVAL_PKT_MIG]     = "SERVAL_PKT_MIG",
        [SERVAL_PKT_RSYN]    = "SERVAL_PKT_RSYN",
        [SERVAL_PKT_MIGDATA] = "SERVAL_PKT_MIGDATA",        
};
#endif /* ENABLE_DEBUG */

/* Backoff multipliers for retransmission, fail when reaching 0. */
static uint8_t backoff[] = { 1, 2, 4, 8, 16, 32, 64, 0 };

atomic_t serval_transit = ATOMIC_INIT(0);

static int serval_sal_state_process(struct sock *sk, 
                                    struct serval_hdr *sh, 
                                    struct sk_buff *skb);

static int serval_sal_transmit_skb(struct sock *sk, struct sk_buff *skb, 
                                   int clone_it, gfp_t gfp_mask);

#if defined(ENABLE_DEBUG)
static const char *serval_hdr_to_str(struct serval_hdr *sh) 
{
#define HDR_BUFLEN 512
        static char buf[HDR_BUFLEN];
        unsigned int hdr_len = ntohs(sh->length);
        int len = 0;
        
        buf[0] = '\0';
        
        len = snprintf(buf + len, HDR_BUFLEN - len, 
                       "[ %s ack=%u len=%u src_fl=%s dst_fl=%s ",
                       serval_pkt_names[sh->type], sh->ack, hdr_len,
                       flow_id_to_str(&sh->src_flowid), 
                       flow_id_to_str(&sh->dst_flowid));
        
        hdr_len -= sizeof(*sh);

        while (hdr_len) {
                struct serval_ext *ext = 
                        (struct serval_ext *)(sh + 1);
                switch (ext->type) {
                case SERVAL_CONNECTION_EXT:
                        {
                                struct serval_connection_ext *cext = 
                                        (struct serval_connection_ext *)ext;
                                len += snprintf(buf + len, HDR_BUFLEN - len,
                                                "CONNEXT {seqno=%u ackno=%u srvid=%s} ",
                                                ntohl(cext->seqno),
                                                ntohl(cext->ackno),
                                                service_id_to_str(&cext->srvid));
                        }
                        break;
                case SERVAL_CONTROL_EXT:
                        {
                                struct serval_control_ext *cext = 
                                        (struct serval_control_ext *)ext;
                                 len += snprintf(buf + len, HDR_BUFLEN - len,
                                                 "CONNEXT {seqno=%u ackno=%u} ",
                                                 ntohl(cext->seqno),
                                                 ntohl(cext->ackno));
                        }
                        break;
                case SERVAL_SERVICE_EXT:
                        {
                                struct serval_service_ext *sext = 
                                        (struct serval_service_ext *)ext;
                                len += snprintf(buf + len, HDR_BUFLEN - len,
                                                "SRVEXT {src=%s dst=%s} ",
                                                service_id_to_str(&sext->src_srvid),
                                                service_id_to_str(&sext->dst_srvid));
                        }
                        break;
                default:
                        break;
                }
                hdr_len -= ext->length;
        }       

        len += snprintf(buf + len, HDR_BUFLEN - len, "]");

        return buf;
}
#endif /* ENABLE_DEBUG */

/* FIXME: should find a better way to distinguish between control
 * packets and data */
static inline int is_control_packet(struct sk_buff *skb)
{
        struct serval_hdr *sh = 
                (struct serval_hdr *)skb_transport_header(skb);

        if (sh->ack || sh->type != SERVAL_PKT_DATA)
                return 1;
        return 0;
}

static inline int is_data_packet(struct sk_buff *skb)
{
        return !is_control_packet(skb);
}

static inline int has_connection_extension(struct serval_hdr *sh)
{
        struct serval_connection_ext *conn_ext = 
                (struct serval_connection_ext *)(sh + 1);
        unsigned int hdr_len = ntohs(sh->length);

        /* Check for connection extension. We require that this
         * extension always directly follows the main Serval
         * header */
        if (hdr_len < sizeof(*sh) + sizeof(*conn_ext)) {
                LOG_PKT("No connection extension, hdr_len=%u\n", 
                        hdr_len);
                return 0;
        }
        
        if (conn_ext->exthdr.type != SERVAL_CONNECTION_EXT || 
            conn_ext->exthdr.length != sizeof(*conn_ext)) {
                LOG_DBG("No connection extension, bad extension type\n");
                return 0;
        }

        return 1;
}

static inline int has_service_extension(struct serval_hdr *sh)
{
        struct serval_service_ext *srv_ext = 
                (struct serval_service_ext *)(sh + 1);
        unsigned int hdr_len = ntohs(sh->length);

        if (hdr_len < sizeof(*sh) + sizeof(*srv_ext)) {
                LOG_PKT("No service extension, hdr_len=%u\n", 
                        hdr_len);
                return 0;
        }
        
        if (srv_ext->exthdr.type != SERVAL_SERVICE_EXT || 
            srv_ext->exthdr.length != sizeof(*srv_ext)) {
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

static inline int packet_has_transport_hdr(struct sk_buff *skb, 
                                           struct serval_hdr *sh)
{
        /* We might have pulled the serval header already. */
        if ((unsigned char *)sh == skb_transport_header(skb))
            return skb->len > ntohs(sh->length);
            
        return skb->len > 0;
}

static inline int has_valid_connection_extension(struct sock *sk, 
                                                 struct serval_hdr *sh)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_connection_ext *conn_ext = 
                (struct serval_connection_ext *)(sh + 1);

        if (!has_connection_extension(sh))
                return 0;

        if (memcmp(conn_ext->nonce, ssk->peer_nonce, 
                   SERVAL_NONCE_SIZE) != 0) {
                LOG_PKT("Connection extension has bad nonce\n");
                return 0;
        }

        return 1;
}

static inline int has_valid_control_extension(struct sock *sk, 
                                              struct serval_hdr *sh)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_control_ext *ctrl_ext = 
                (struct serval_control_ext *)(sh + 1);
        unsigned int hdr_len = ntohs(sh->length);

        /* Check for control extension. We require that this
         * extension always directly follows the main Serval
         * header */
        if (hdr_len < sizeof(*sh) + sizeof(*ctrl_ext)) {
                LOG_PKT("No control extension, hdr_len=%u\n", 
                        hdr_len);
                return 0;
        }
        
        if (ctrl_ext->exthdr.type != SERVAL_CONTROL_EXT ||
            ctrl_ext->exthdr.length != sizeof(*ctrl_ext)) {
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

static void serval_sal_queue_ctrl_skb(struct sock *sk, struct sk_buff *skb)
{
        /* Cannot release header here in case this is an unresolved
           packet. We need the skb_transport_header() pointer to
           calculate checksum */
	//skb_header_release(skb);
	serval_sal_add_ctrl_queue_tail(sk, skb);
        LOG_PKT("queue packet seqno=%u\n", SERVAL_SKB_CB(skb)->seqno);
        /* Check if the skb became first in queue, in that case update
         * unacknowledged seqno. */
        if (skb == serval_sal_ctrl_queue_head(sk)) {
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
static int serval_sal_write_xmit(struct sock *sk, 
                                 unsigned int limit, gfp_t gfp)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *skb;
        unsigned int num = 0;
        int err = 0;
        
        LOG_PKT("writing from queue snd_una=%u snd_nxt=%u snd_wnd=%u\n",
                ssk->snd_seq.una, ssk->snd_seq.nxt, ssk->snd_seq.wnd);
        
	while ((skb = serval_sal_send_head(sk)) && 
               (ssk->snd_seq.nxt - ssk->snd_seq.una) <= ssk->snd_seq.wnd) {
                
                if (limit && num == limit)
                        break;

                err = serval_sal_transmit_skb(sk, skb, 1, gfp);
                
                if (err < 0) {
                        LOG_ERR("xmit failed err=%d\n", err);
                        break;
                }
                serval_sal_advance_send_head(sk, skb);
                num++;
        }

        LOG_PKT("sent %u packets\n", num);

        return err;
}

/*
  Queue packet on control queue and push pending packets.
*/
static int serval_sal_queue_and_push(struct sock *sk, struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err;
        
        serval_sal_queue_ctrl_skb(sk, skb);

        /* 
           Set retransmission timer if this was inserted first in the
           queue */
        if (skb == serval_sal_ctrl_queue_head(sk)) {
                sk_reset_timer(sk, &serval_sk(sk)->retransmit_timer,
                               jiffies + msecs_to_jiffies(ssk->rto)); 
        }
        
        /* 
           Write packets in queue to network.
           NOTE: only one packet for now. Should implement TX window.
        */
        err = serval_sal_write_xmit(sk, 1, GFP_ATOMIC);

        if (err != 0) {
                LOG_ERR("xmit failed err=%d\n", err);
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
static int serval_sal_clean_rtx_queue(struct sock *sk, uint32_t ackno)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *skb, *fskb = serval_sal_ctrl_queue_head(sk);
        unsigned int num = 0;
        int err = 0;
       
        while ((skb = serval_sal_ctrl_queue_head(sk)) && 
               skb != serval_sal_send_head(sk)) {
                if (ackno == SERVAL_SKB_CB(skb)->seqno + 1) {
                        serval_sal_unlink_ctrl_queue(skb, sk);
                        LOG_PKT("cleaned rtx queue seqno=%u\n", 
                                SERVAL_SKB_CB(skb)->seqno);
                        kfree_skb(skb);
                        skb = serval_sal_ctrl_queue_head(sk);
                        if (skb)
                                ssk->snd_seq.una = SERVAL_SKB_CB(skb)->seqno;
                        num++;
                } else {
                        break;
                }
        }

        LOG_PKT("cleaned up %u packets from rtx queue\n", num);
        
        /* Did we remove the first packet in the queue? */
        if (serval_sal_ctrl_queue_head(sk) != fskb) {
                sk_stop_timer(sk, &serval_sk(sk)->retransmit_timer);
                ssk->retransmits = 0;
        }

        if (serval_sal_ctrl_queue_head(sk)) {
                LOG_PKT("Setting retrans timer\n");
                sk_reset_timer(sk, &serval_sk(sk)->retransmit_timer,
                               jiffies + msecs_to_jiffies(ssk->rto));
        }
        return err;
}

int serval_sal_connect(struct sock *sk, struct sockaddr *uaddr, 
                       int addr_len)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *skb;
        struct service_id *srvid = &((struct sockaddr_sv *)uaddr)->sv_srvid;
        int err;
        
	if ((size_t)addr_len < sizeof(struct sockaddr_sv))
		return -EINVAL;

        /* Set the peer serviceID in the socket */
        memcpy(&ssk->peer_srvid, srvid, sizeof(*srvid));
        
        /* Check for extra IP address */
        if ((size_t)addr_len >= sizeof(struct sockaddr_sv) +
            sizeof(struct sockaddr_in)) {
                struct sockaddr_in *saddr =
                        (struct sockaddr_in *)(((struct sockaddr_sv *)uaddr) + 1);
                
                if (saddr->sin_family == AF_INET) {
                        memcpy(&inet_sk(sk)->inet_daddr,
                               &saddr->sin_addr,
                               sizeof(saddr->sin_addr));
                }
        }

        skb = alloc_skb(sk->sk_prot->max_header, GFP_ATOMIC);

        if (!skb)
                return -ENOMEM;
        
        skb_reserve(skb, sk->sk_prot->max_header);
        skb_serval_set_owner_w(skb, sk);
        skb->protocol = IPPROTO_SERVAL;

#if 0
        if (has_dst_ip) {
                nexthop = daddr = usin->sin_addr.s_addr;
                if (inet->opt && inet->opt->srr) {
                        if (!daddr)
                                return -EINVAL;
                        nexthop = inet->opt->faddr;
                }

                tmp = ip_route_connect(&rt, nexthop, inet->inet_saddr,
                                       RT_CONN_FLAGS(sk), sk->sk_bound_dev_if,
                                       IPPROTO_TCP,
                                       inet->inet_sport, usin->sin_port, sk, 1);
                if (tmp < 0) {
                        if (tmp == -ENETUNREACH)
			IP_INC_STATS_BH(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
                        return tmp;
                }
                
                if (rt->rt_flags & (RTCF_MULTICAST | RTCF_BROADCAST)) {
                        ip_rt_put(rt);
                        return -ENETUNREACH;
                }
                
                if (!inet->opt || !inet->opt->srr)
                        daddr = rt->rt_dst;
                
                if (!inet->inet_saddr)
                        inet->inet_saddr = rt->rt_src;
                inet->inet_rcv_saddr = inet->inet_saddr;

                
                /* OK, now commit destination to socket.  */
                //sk->sk_gso_type = SKB_GSO_TCPV4;
                sk->sk_gso_type = 0;
                sk_setup_caps(sk, &rt->dst);
        }
#endif
        /* Disable segmentation offload */
        sk->sk_gso_type = 0;

        /* Ask transport to fill in */
        if (ssk->af_ops->conn_build_syn) {
                err = ssk->af_ops->conn_build_syn(sk, skb);

                if (err) {
                        LOG_ERR("Transport protocol returned error\n");
                        kfree_skb(skb);
                        return err;
                }
        }

        SERVAL_SKB_CB(skb)->pkttype = SERVAL_PKT_SYN;
        SERVAL_SKB_CB(skb)->seqno = ssk->snd_seq.iss;
        ssk->snd_seq.nxt = ssk->snd_seq.iss + 1;

        LOG_DBG("Sending REQUEST seqno=%u srvid=%s\n",
                SERVAL_SKB_CB(skb)->seqno, 
                service_id_to_str(srvid));

        err = serval_sal_queue_and_push(sk, skb);
        
        if (err < 0) {
                LOG_ERR("queuing failed\n");
        }
        
        return err;
}

static void serval_sal_timewait(struct sock *sk, int state)
{
        unsigned long timeout = jiffies;

        serval_sock_set_state(sk, state);
        /* FIXME: Dynamically set timeout */
        if (state == SERVAL_FINWAIT2) {
                timeout += msecs_to_jiffies(60000);
        } else {
                timeout += msecs_to_jiffies(8000);
        }
        sk_reset_timer(sk, &serval_sk(sk)->tw_timer, timeout); 
}

void serval_sal_done(struct sock *sk)
{
        if (serval_sk(sk)->af_ops->done)
                serval_sk(sk)->af_ops->done(sk);
        
        serval_sock_done(sk);
}

/* Called as a result of user app close() */
void serval_sal_close(struct sock *sk, long timeout)
{
        struct sk_buff *skb = NULL;
        int err = 0;

        LOG_DBG("\n");
        
        if (sk->sk_state == SERVAL_CONNECTED ||
            sk->sk_state == SERVAL_RESPOND ||
            sk->sk_state == SERVAL_CLOSEWAIT) {
                struct serval_sock *ssk = serval_sk(sk);
                
                if (ssk->close_received && 
                    sk->sk_state != SERVAL_CLOSEWAIT)
                        serval_sock_set_state(sk, SERVAL_CLOSEWAIT);

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
                        skb = alloc_skb(sk->sk_prot->max_header, GFP_ATOMIC);
                        
                        if (skb)
                                break;
                        yield();
                }
                
                LOG_DBG("Sending Close REQUEST\n");
                skb_reserve(skb, sk->sk_prot->max_header);
                skb_serval_set_owner_w(skb, sk);
                SERVAL_SKB_CB(skb)->pkttype = SERVAL_PKT_CLOSE;
                SERVAL_SKB_CB(skb)->seqno = serval_sk(sk)->snd_seq.nxt++;

                err = serval_sal_queue_and_push(sk, skb);
                
                if (err < 0) {
                        LOG_ERR("queuing failed\n");
                }
        } else {
                serval_sal_done(sk);
        }
}

static int serval_sal_send_ack(struct sock *sk, struct serval_hdr *sh, 
                               struct sk_buff *rskb)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *skb;
        int err = 0;

        LOG_DBG("Sending ACK\n");

        skb = alloc_skb(sk->sk_prot->max_header, GFP_ATOMIC);
                        
        if (!skb)
                return -ENOMEM;
        
        skb_reserve(skb, sk->sk_prot->max_header);
        skb_serval_set_owner_w(skb, sk);
        SERVAL_SKB_CB(skb)->pkttype = SERVAL_PKT_DATA;
        SERVAL_SKB_CB(skb)->flags = SVH_ACK;
        /* Do not increment sequence numbers for pure ACKs */
        SERVAL_SKB_CB(skb)->seqno = ssk->snd_seq.nxt;

        if (err == 0) {
                /* Do not queue pure ACKs */
                err = serval_sal_transmit_skb(sk, skb, 0, GFP_ATOMIC);
        }
               
        if (err < 0) {
                LOG_ERR("xmit failed\n");
        }
   
        return err;
}

static int serval_sal_syn_rcv(struct sock *sk, 
                              struct serval_hdr *sh,
                              struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct request_sock *rsk;
        struct serval_request_sock *srsk;
        struct serval_connection_ext *conn_ext = 
                (struct serval_connection_ext *)(sh + 1);
        struct net_addr saddr;
        struct dst_entry *dst = NULL;
        struct sk_buff *rskb;
        int err = 0;

        /* Make compiler be quiet */
        memset(&saddr, 0, sizeof(saddr));

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
                goto done;


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
                goto done;
        }

        rsk = serval_reqsk_alloc(sk->sk_prot->rsk_prot);

        if (!rsk) {
                err = -ENOMEM;
                goto done;
        }

        srsk = serval_rsk(rsk);

        /* Copy fields in request packet into request sock */
        memcpy(&srsk->peer_flowid, &sh->src_flowid, 
               sizeof(sh->src_flowid));
        memcpy(&inet_rsk(rsk)->rmt_addr, &ip_hdr(skb)->saddr,
               sizeof(inet_rsk(rsk)->rmt_addr));
        memcpy(&inet_rsk(rsk)->loc_addr, &saddr,
               sizeof(inet_rsk(rsk)->rmt_addr));

        memcpy(srsk->peer_nonce, conn_ext->nonce, SERVAL_NONCE_SIZE);
        srsk->rcv_seq = ntohl(conn_ext->seqno);

#if defined(ENABLE_DEBUG)
        {
                char rmtstr[18], locstr[18];
                LOG_DBG("rmt_addr=%s loc_addr=%s\n",
                        inet_ntop(AF_INET, &inet_rsk(rsk)->rmt_addr, 
                                  rmtstr, 18),
                        inet_ntop(AF_INET, &inet_rsk(rsk)->loc_addr, 
                                  locstr, 18));
        }
#endif

        list_add(&srsk->lh, &ssk->syn_queue);
        
        /* Call upper transport protocol handler */
        if (ssk->af_ops->conn_request) {
                err = ssk->af_ops->conn_request(sk, rsk, skb);
                
                if (err)
                        goto done;
        }
        
        /* Allocate RESPONSE reply */
        rskb = alloc_skb(sk->sk_prot->max_header, GFP_ATOMIC);

        if (!rskb) {
                err = -ENOMEM;
                goto drop;
        }
        
        skb_reserve(rskb, sk->sk_prot->max_header);
        skb_serval_set_owner_w(rskb, sk);
        rskb->protocol = 0;

#if defined(OS_LINUX_KERNEL)
        /*
          For kernel, we need to route this packet and
          associate a dst_entry with the skb for it to be
          accepted by the kernel IP stack.
        */
        dst = serval_sock_route_req(sk, rsk);
        
        if (!dst) {
                LOG_ERR("RESPONSE not routable\n");
                goto drop_response;
        }
#endif /* OS_LINUX_KERNEL */

        /* Let transport chip in */
        if (ssk->af_ops->conn_build_synack) {
                err = ssk->af_ops->conn_build_synack(sk, dst, rsk, rskb);
                
                if (err) {
                        goto drop_and_release;
                }
        } else {
                LOG_DBG("Transport has no SYNACK callback\n");
        }

        rskb->protocol = IPPROTO_SERVAL;
        conn_ext = (struct serval_connection_ext *)
                skb_push(rskb, sizeof(*conn_ext));
        conn_ext->exthdr.type = SERVAL_CONNECTION_EXT;
        conn_ext->exthdr.length = sizeof(*conn_ext);
        conn_ext->exthdr.flags = 0;
        conn_ext->seqno = htonl(srsk->iss_seq);
        conn_ext->ackno = htonl(srsk->rcv_seq + 1);
        memcpy(&conn_ext->srvid, &ssk->peer_srvid, 
               sizeof(ssk->peer_srvid));
        /* Copy our nonce to connection extension */
        memcpy(conn_ext->nonce, srsk->local_nonce, SERVAL_NONCE_SIZE);
        
        /* Add Serval header */
        sh = (struct serval_hdr *)skb_push(rskb, sizeof(*sh));
        sh->type = SERVAL_PKT_SYN;
        sh->ack = 1;
        sh->protocol = rskb->protocol;
        sh->length = htons(sizeof(*sh) + sizeof(*conn_ext));

        /* Update info in packet */
        memcpy(&sh->dst_flowid, &srsk->peer_flowid, 
               sizeof(sh->dst_flowid));
        memcpy(&sh->src_flowid, &srsk->local_flowid, 
               sizeof(srsk->local_flowid));
        memcpy(&conn_ext->srvid, &srsk->peer_srvid,            
               sizeof(srsk->peer_srvid));

        skb_dst_set(rskb, dst);

        rskb->dev = skb->dev;

        LOG_PKT("Serval XMIT RESPONSE %s skb->len=%u\n",
                serval_hdr_to_str(sh), rskb->len);
        
        /* 
           Cannot use serval_sal_transmit_skb here since we do not yet
           have a full accepted socket (sk is the listening sock). 
        */
        err = serval_ipv4_build_and_send_pkt(rskb, sk, 
                                             inet_rsk(rsk)->loc_addr,
                                             inet_rsk(rsk)->rmt_addr, NULL);

        /* Free the REQUEST */
 drop:
        kfree_skb(skb);
 done:
        return err;
 drop_and_release:
        dst_release(dst);
#if defined(OS_LINUX_KERNEL)
 drop_response:
#endif
        kfree_skb(rskb);
        goto drop;
}

/*
  Create new child socket in RESPOND state. This happens as a result
  of a LISTEN:ing socket receiving an ACK in response to a SYNACK
  response.  */
static struct sock *
serval_sal_create_respond_sock(struct sock *sk, 
                               struct sk_buff *skb,
                               struct request_sock *req,
                               struct dst_entry *dst)
{
        struct sock *nsk;

        nsk = sk_clone(sk, GFP_ATOMIC);

        if (nsk) {
                int ret;

                atomic_inc(&serval_nr_socks);
                serval_sock_init(nsk);

                /* Transport protocol specific init. */                
                ret = serval_sk(sk)->af_ops->conn_child_sock(sk, skb, 
                                                             req, nsk, dst);

                if (ret < 0) {
                        LOG_ERR("Transport child sock init failed\n");
                        sock_set_flag(nsk, SOCK_DEAD);
                        sk_free(nsk);
                        nsk = NULL;
                }
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
static struct sock * serval_sal_request_sock_handle(struct sock *sk,
                                                    struct serval_hdr *sh,
                                                    struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_request_sock *srsk;
        struct serval_connection_ext *conn_ext = 
                (struct serval_connection_ext *)(sh + 1);

        list_for_each_entry(srsk, &ssk->syn_queue, lh) {
                if (memcmp(&srsk->local_flowid, &sh->dst_flowid, 
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
                        
                        nsk = serval_sal_create_respond_sock(sk, skb, 
                                                             rsk, NULL);
                        
                        if (!nsk)
                                return NULL;

                        /* Move request sock to accept queue */
                        list_del(&srsk->lh);
                        list_add_tail(&srsk->lh, &ssk->accept_queue);

                        newinet = inet_sk(nsk);
                        nssk = serval_sk(nsk);

                        serval_sock_set_state(nsk, SERVAL_RESPOND);

                        memcpy(&nssk->local_flowid, &srsk->local_flowid, 
                               sizeof(srsk->local_flowid));
                        memcpy(&nssk->peer_flowid, &srsk->peer_flowid, 
                               sizeof(srsk->peer_flowid));
                        memcpy(&nssk->peer_srvid, &srsk->peer_srvid,
                               sizeof(srsk->peer_srvid));
                        memcpy(&newinet->inet_daddr, &irsk->rmt_addr,
                               sizeof(newinet->inet_daddr));
                        memcpy(&newinet->inet_saddr, &irsk->loc_addr,
                               sizeof(newinet->inet_saddr));      
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

static int serval_sal_ack_process(struct sock *sk,
                                  struct serval_hdr *sh, 
                                  struct sk_buff *skb)
{
        struct serval_ext *ext = (struct serval_ext *)(sh + 1);
        uint32_t ackno = 0;
        int err = -1;

        if (!sh->ack)
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
                serval_sal_clean_rtx_queue(sk, ackno);
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

static int serval_sal_rcv_close_req(struct sock *sk, 
                                    struct serval_hdr *sh,
                                    struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_control_ext *ctrl_ext = 
                (struct serval_control_ext *)(sh + 1);
        int err = 0;

        LOG_DBG("received Close REQUEST\n");
        
        if (!has_valid_control_extension(sk, sh)) {
                LOG_ERR("Bad control extension\n");
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
                                break;
                        case SERVAL_CLOSING:
                                break;
                        case SERVAL_CLOSEWAIT:
                                /* Must be retransmitted FIN */
                                break;
                        case SERVAL_FINWAIT1:
                                /* Simultaneous close */
                                serval_sock_set_state(sk, SERVAL_CLOSING);
                        case SERVAL_FINWAIT2:
                                // Time-wait
                        default:
                                break;
                        }

                        if (!sock_flag(sk, SOCK_DEAD)) {
                                sk->sk_state_change(sk);
                                
                                /* Do not send POLL_HUP for half
                                   duplex close. */
                                if (sk->sk_shutdown == SHUTDOWN_MASK ||
                                    sk->sk_state == SERVAL_CLOSED)
                                        sk_wake_async(sk, SOCK_WAKE_WAITD, 
                                                      POLL_HUP);
                                else
                                        sk_wake_async(sk, SOCK_WAKE_WAITD, 
                                                      POLL_IN);
                        }
                        
                } else {
                        LOG_DBG("Transport not ready to close\n");
                }
                err = serval_sal_send_ack(sk, sh, skb);
        }
        
        return err;
}

/**
   Called by transport when it has finished.
 */
int serval_sal_rcv_transport_fin(struct sock *sk,
                                 struct sk_buff *skb)
{
        int err = 0;
        struct serval_sock *ssk = serval_sk(sk);
        
        LOG_DBG("Transport FIN received. Serval close received=%d\n", 
                ssk->close_received);

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
                break;
        case SERVAL_CLOSING:
                break;
        case SERVAL_CLOSEWAIT:
                /* Must be retransmitted FIN */
                                
                /* FIXME: is this the right place for async
                 * wake? */
                break;
        case SERVAL_FINWAIT1:
                /* Simultaneous close */
                serval_sock_set_state(sk, SERVAL_CLOSING);
        case SERVAL_FINWAIT2:
                // Time-wait
        default:
                break;
        }

	if (!sock_flag(sk, SOCK_DEAD)) {
		sk->sk_state_change(sk);

		/* Do not send POLL_HUP for half duplex close. */
		if (sk->sk_shutdown == SHUTDOWN_MASK ||
		    sk->sk_state == SERVAL_CLOSED)
			sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_HUP);
		else
			sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_IN);
	}
        
        return err;
}

static int serval_sal_connected_state_process(struct sock *sk, 
                                              struct serval_hdr *sh,
                                              struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;
        
        LOG_PKT("Processing\n");

        serval_sal_ack_process(sk, sh, skb);

        if (sh->type == SERVAL_PKT_CLOSE)
                err = serval_sal_rcv_close_req(sk, sh, skb);

        /* Should also pass FIN to user, as it needs to pick it off
         * its receive queue to notice EOF. */
        if (packet_has_transport_hdr(skb, sh) || 
            sh->type == SERVAL_PKT_CLOSE) {
                /* Set the received service id.

                   NOTE: The transport protocol is free to overwrite
                   the control block with its own information. TCP
                   does this, for sure.
                 */
                SERVAL_SKB_CB(skb)->srvid = &ssk->peer_srvid;

                err = ssk->af_ops->receive(sk, skb);
        } else {
                LOG_PKT("Dropping packet\n");
                kfree_skb(skb);
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
static int serval_sal_child_process(struct sock *parent, struct sock *child,
                                    struct serval_hdr *sh,
                                    struct sk_buff *skb)
{
        int ret = 0;
        int state = child->sk_state;

        serval_sk(child)->dev = NULL;        

        /* Check lock on child socket, similarly to how we handled the
           parent sock for the incoming skb. */
        if (!sock_owned_by_user(child)) {

                ret = serval_sal_state_process(child, sh, skb);

                if (ret == 0 && 
                    state == SERVAL_RESPOND && 
                    child->sk_state != state) {
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

static int serval_sal_listen_state_process(struct sock *sk,
                                           struct serval_hdr *sh,
                                           struct sk_buff *skb)
{
        int err = 0;                         

        /* Is this a SYN? */
        if (sh->type == SERVAL_PKT_SYN) {
                err = serval_sal_syn_rcv(sk, sh, skb);
        } else if (sh->ack) {
                        struct sock *nsk;
                        /* Processing for socket that has received SYN
                           already */

                        LOG_PKT("ACK recv\n");
                        
                        nsk = serval_sal_request_sock_handle(sk, sh, skb);
                        
                        if (nsk && nsk != sk) {
                                return serval_sal_child_process(sk, nsk,
                                                                sh, skb);
                        }
                        kfree_skb(skb);
        } else {
                kfree_skb(skb);
        }

        return err;
}

static int serval_sal_request_state_process(struct sock *sk, 
                                            struct serval_hdr *sh,
                                            struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_connection_ext *conn_ext = 
                (struct serval_connection_ext *)(sh + 1);
        struct sk_buff *rskb;       
        int err = 0;
                
        if (!has_connection_extension(sh))
                goto drop;
        
        if (!(sh->type == SERVAL_PKT_SYN && sh->ack)) {
                LOG_ERR("packet is not a RESPONSE\n");
                goto drop;
        }
        /* Process potential ACK 
         */
        if (serval_sal_ack_process(sk, sh, skb) != 0) {
                LOG_DBG("ACK is invalid\n");
                goto drop;
        }
        
        LOG_DBG("Got RESPONSE seqno=%u ackno=%u TCP off=%u hdrlen=%u\n",
                ntohl(conn_ext->seqno), 
                ntohl(conn_ext->ackno),
                skb_transport_header(skb) - (unsigned char *)sh,
                sizeof(*sh) + sizeof(*conn_ext));

        /* Save device and peer flow id */
        serval_sock_set_dev(sk, skb->dev);

        /* Save IP addresses. These are important for checksumming in
           transport protocols */
        memcpy(&inet_sk(sk)->inet_daddr, &ip_hdr(skb)->saddr, 
               sizeof(inet_sk(sk)->inet_daddr));
        memcpy(&inet_sk(sk)->inet_saddr, &ip_hdr(skb)->daddr, 
               sizeof(inet_sk(sk)->inet_saddr));

        /* Save nonce */
        memcpy(ssk->peer_nonce, conn_ext->nonce, SERVAL_NONCE_SIZE);
        /* Update socket ids */
        memcpy(&ssk->peer_flowid, &sh->src_flowid, 
               sizeof(sh->src_flowid));
      
        /* Update expected rcv sequence number */
        ssk->rcv_seq.nxt = ntohl(conn_ext->seqno) + 1;
        
        /* Let transport know about the response */
        if (ssk->af_ops->request_state_process) {
                skb->ip_summed = CHECKSUM_UNNECESSARY;
                err = ssk->af_ops->request_state_process(sk, skb);

                if (err) {
                        LOG_ERR("Transport drops packet\n");
                        goto error;
                }
        }

        /* Move to connected state */
        serval_sock_set_state(sk, SERVAL_CONNECTED);
        
        /* Let user know we are connected. */
	if (!sock_flag(sk, SOCK_DEAD)) {
                sk->sk_state_change(sk);
                sk_wake_async(sk, SOCK_WAKE_IO, POLL_OUT);
        }

        /* Allocate ACK */
        rskb = alloc_skb(sk->sk_prot->max_header, GFP_ATOMIC);

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
        SERVAL_SKB_CB(rskb)->pkttype = SERVAL_PKT_DATA;
        SERVAL_SKB_CB(rskb)->flags = SVH_ACK | SVH_CONN_ACK;
        /* Do not increase sequence number for pure ACK */
        SERVAL_SKB_CB(rskb)->seqno = ssk->snd_seq.nxt;
        rskb->protocol = IPPROTO_SERVAL;

        /* Xmit, do not queue ACK */
        err = serval_sal_transmit_skb(sk, rskb, 0, GFP_ATOMIC);

drop: 
        kfree_skb(skb);
error:
        return err;
}

static int serval_sal_respond_state_process(struct sock *sk, 
                                            struct serval_hdr *sh,
                                            struct sk_buff *skb)
{
        int err = 0;

        if (!has_valid_connection_extension(sk, sh))
                goto drop;

        /* Process ACK */
        if (serval_sal_ack_process(sk, sh, skb) == 0) {
                struct serval_sock *ssk = serval_sk(sk);
                LOG_DBG("\n");

                /* Save device */
                serval_sock_set_dev(sk, skb->dev);

                memcpy(&inet_sk(sk)->inet_daddr, &ip_hdr(skb)->saddr, 
                       sizeof(inet_sk(sk)->inet_daddr));

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
        }
drop:
        kfree_skb(skb);
error:
        return err;
}

static int serval_sal_finwait1_state_process(struct sock *sk, 
                                             struct serval_hdr *sh, 
                                             struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;
        int ack_ok = 0;

        if (sh->ack && serval_sal_ack_process(sk, sh, skb) == 0)
                ack_ok = 1;

        if (sh->type == SERVAL_PKT_CLOSE) {
                serval_sal_rcv_close_req(sk, sh, skb);

                if (ack_ok)
                        serval_sal_timewait(sk, SERVAL_TIMEWAIT);
                else
                        serval_sal_timewait(sk, SERVAL_CLOSING);
        } else if (ack_ok) {
                serval_sal_timewait(sk, SERVAL_FINWAIT2);
        }
        
        if (packet_has_transport_hdr(skb, sh)) {
                /* Set the received service id */
                SERVAL_SKB_CB(skb)->srvid = &ssk->peer_srvid;
                
                err = ssk->af_ops->receive(sk, skb);
        } else  {
                kfree_skb(skb);
        }
        return err;
}

static int serval_sal_finwait2_state_process(struct sock *sk, 
                                             struct serval_hdr *sh, 
                                             struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;
        
        /* We've received our CLOSE ACK already */
        if (sh->type == SERVAL_PKT_CLOSE) {
                err = serval_sal_rcv_close_req(sk, sh, skb);

                if (err == 0) {
                        serval_sal_timewait(sk, SERVAL_TIMEWAIT);
                }
        }

        if (packet_has_transport_hdr(skb, sh)) {
                /* Set the received service id */
                SERVAL_SKB_CB(skb)->srvid = &ssk->peer_srvid;
                
                err = ssk->af_ops->receive(sk, skb);
        } else {
                kfree_skb(skb);
        }

        return err;
}

static int serval_sal_closing_state_process(struct sock *sk, 
                                            struct serval_hdr *sh, 
                                            struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;
                
        if (sh->ack && serval_sal_ack_process(sk, sh, skb) == 0) {
                /* ACK was valid */
                serval_sal_timewait(sk, SERVAL_TIMEWAIT);
        }

        if (packet_has_transport_hdr(skb, sh)) {
                /* Set the received service id */
                SERVAL_SKB_CB(skb)->srvid = &ssk->peer_srvid;
                
                err = ssk->af_ops->receive(sk, skb);
        } else {
                kfree_skb(skb);
        }

        return err;
}

static int serval_sal_lastack_state_process(struct sock *sk, 
                                            struct serval_hdr *sh, 
                                            struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0, ack_ok;
        
        ack_ok = serval_sal_ack_process(sk, sh, skb) == 0;
                
        if (packet_has_transport_hdr(skb, sh)) {
                /* Set the received service id */
                SERVAL_SKB_CB(skb)->srvid = &ssk->peer_srvid;
                
                err = ssk->af_ops->receive(sk, skb);
        } else {
                kfree_skb(skb);
        }

        if (ack_ok) {
                /* ACK was valid */
                serval_sal_done(sk);
        }

        return err;
}

/*
  Receive for datagram sockets that are not connected.
*/
static int serval_sal_init_state_process(struct sock *sk, 
                                         struct serval_hdr *sh, 
                                         struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_service_ext *srv_ext = 
                (struct serval_service_ext *)(sh + 1);
        int err = 0;

        if (ssk->hash_key && srv_ext && srv_ext){
                //LOG_DBG("Receiving unconnected datagram for service %s at %i from service %s at %s\n", service_id_to_str((struct service_id*) ssk->hash_key),
                //    ip_hdr(skb)->daddr, service_id_to_str(&srv_ext->src_srvid), ip_hdr(skb)->saddr);
                LOG_DBG("Receiving unconnected datagram for service %s\n", 
                        service_id_to_str((struct service_id*) ssk->hash_key));
        }

        if (packet_has_transport_hdr(skb, sh)) {
                /* Set source serviceID */
                SERVAL_SKB_CB(skb)->srvid = &srv_ext->src_srvid;                
                err = ssk->af_ops->receive(sk, skb);
        } else {
                kfree_skb(skb);
        }

        return err;
}

int serval_sal_state_process(struct sock *sk, 
                             struct serval_hdr *sh, 
                             struct sk_buff *skb)
{
        int err = 0;

        LOG_PKT("receive in state %s\n", serval_sock_state_str(sk));

        switch (sk->sk_state) {
        case SERVAL_INIT:
                if (sk->sk_type == SOCK_STREAM) 
                        goto drop;
                err = serval_sal_init_state_process(sk, sh, skb);
                break;
        case SERVAL_CONNECTED:
                err = serval_sal_connected_state_process(sk, sh, skb);
                break;
        case SERVAL_REQUEST:
                err = serval_sal_request_state_process(sk, sh, skb);
                break;
        case SERVAL_RESPOND:
                err = serval_sal_respond_state_process(sk, sh, skb);
                break;
        case SERVAL_LISTEN:
                err = serval_sal_listen_state_process(sk, sh, skb);
                break;
        case SERVAL_FINWAIT1:
                err = serval_sal_finwait1_state_process(sk, sh, skb);
                break;
        case SERVAL_FINWAIT2:
                err = serval_sal_finwait2_state_process(sk, sh, skb);
                break;
        case SERVAL_CLOSING:
                err = serval_sal_closing_state_process(sk, sh, skb);
                break;
        case SERVAL_LASTACK:
                err = serval_sal_lastack_state_process(sk, sh, skb);
                break;
        case SERVAL_TIMEWAIT:
                /* Send ACK again */
                err = serval_sal_send_ack(sk, sh, skb);
                goto drop;
        default:
                LOG_ERR("bad socket state %u\n", sk->sk_state);
                goto drop;
        }

        return err;
drop:
        kfree_skb(skb);
        return err;
}

int serval_sal_do_rcv(struct sock *sk, 
                      struct sk_buff *skb)
{
        struct serval_hdr *sh = 
                (struct serval_hdr *)skb_transport_header(skb);
        unsigned int hdr_len = ntohs(sh->length);
                 
        pskb_pull(skb, hdr_len);

        //SERVAL_SKB_CB(skb)->sh = sh;
        SERVAL_SKB_CB(skb)->pkttype = sh->type;
        SERVAL_SKB_CB(skb)->srvid = NULL;
        skb_reset_transport_header(skb);
                
        return serval_sal_state_process(sk, sh, skb);
}

void serval_sal_error_rcv(struct sk_buff *skb, u32 info)
{
        LOG_PKT("received ICMP error!\n");
        
        /* TODO: deal with ICMP errors, e.g., wake user and report. */
}

static int serval_sal_add_source_ext(struct sk_buff *skb, 
                                     struct serval_hdr* sh, 
                                     struct iphdr *iph, 
                                     unsigned int iph_len) 
{
        //int hdr_len = iph_len;


        /* Add in source header TODO
           skb_push(skb, ntohs(sh->length));

           sh = (struct serval_hdr *)skb_push(skb, sizeof(*sh));
           sh->flags = flags;
           sh->protocol = skb->protocol;
           sh->length = htons(hdr_len);
           memcpy(&sh->src_flowid, &ssk->local_flowid, sizeof(ssk->local_flowid));
           memcpy(&sh->dst_flowid, &ssk->peer_flowid, sizeof(ssk->peer_flowid));
        */
        return 0;
}

/* Resolution return values. */
enum {
        SAL_RESOLVE_ERROR = -1,
        SAL_RESOLVE_FAIL, /* No match */
        SAL_RESOLVE_DEMUX,
        SAL_RESOLVE_FORWARD,
        SAL_RESOLVE_DELAY,
        SAL_RESOLVE_DROP,
};

static int serval_sal_resolve_service(struct sk_buff *skb, 
                                      struct serval_hdr *sh,
                                      struct service_id *srvid,
                                      struct sock **sk)
{
        struct service_entry* se = NULL;
        struct service_resolution_iter iter;
        struct dest* dest = NULL;
        unsigned int num_forward = 0;
        unsigned int hdr_len = ntohs(sh->length);
        struct iphdr *iph = NULL;
        unsigned int iph_len = 0;
        struct sk_buff *cskb = NULL;
        int err = SAL_RESOLVE_FAIL;

        *sk = NULL;

        LOG_DBG("Resolve or demux inbound packet on serviceID %s\n", 
                service_id_to_str(srvid));
        
        /* Match on the highest priority srvid rule, even if it's not
         * the sock TODO - use flags/prefix in resolution This should
         * probably be in a separate function call
         * serval_sal_transit_rcv or resolve something
         */
        se = service_find(srvid, sizeof(*srvid) * 8);

        if (!se) {
                LOG_INF("No matching service entry for serviceID %s\n",
                        service_id_to_str(srvid));
                return SAL_RESOLVE_FAIL;
        }

        LOG_DBG("Service entry count=%u\n", se->count);

	service_resolution_iter_init(&iter, se, SERVICE_ITER_ANYCAST);

        /*
          Send to all destinations listed for this service.
        */
        dest = service_resolution_iter_next(&iter);

        if (!dest) {
                LOG_INF("No dest to forward on!\n");
                service_resolution_iter_inc_stats(&iter, -1, 
                                                  -(skb->len - hdr_len));
                service_resolution_iter_destroy(&iter);
                service_entry_put(se);
                return SAL_RESOLVE_FAIL;
        }

        while (dest) {
                struct dest *next_dest;

                if (cskb == NULL) {
                        service_resolution_iter_inc_stats(&iter, 1, 
                                                          skb->len - hdr_len);
                }

                next_dest = service_resolution_iter_next(&iter);

                if (next_dest == NULL) {
                        cskb = skb;
                } else {
                        cskb = skb_clone(skb, GFP_ATOMIC);

                        if (!cskb) {
                                LOG_ERR("Skb allocation failed\n");
                                kfree_skb(skb);
                                err = -ENOBUFS;
                                break;
                        }
                        /* Cloned skb will have no socket set. */
                        //skb_serval_set_owner_w(cskb, sk);
                }

                if (is_sock_dest(dest)) {
                        /* local resolution */
                        *sk = dest->dest_out.sk;
                        sock_hold(*sk);
                        err = SAL_RESOLVE_DEMUX;
                        break;
                } else {
                        /* Need to drop dst since this packet is
                         * routed for input. Otherwise, kernel IP
                         * stack will be confused when transmitting
                         * this packet. */
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
                                LOG_ERR("Could not forward SAL packet\n");
                                kfree_skb(cskb);
                                continue;
                        }

#else
                        /* Set the output device - ip_forward uses the
                         * out device specified in the dst_entry route
                         * and assumes that skb->dev is the input
                         * interface*/
                        if (dest->dest_out.dev)
                                skb_set_dev(cskb, 
                                            dest->dest_out.dev);

#endif /* OS_LINUX_KERNEL */

                        /* TODO Set the true overlay source address if
                         * the packet may be ingress-filtered
                         * user-level raw socket forwarding may drop
                         * the packet if the source address is
                         * invalid */
                        serval_sal_add_source_ext(cskb, sh, 
                                                  iph, iph_len);

                        //struct serval_sock *ssk = serval_sk(sk);
                        //err = ssk->af_ops->queue_xmit(cskb);
                        err = serval_ipv4_forward_out(cskb);

                        if (err < 0) {
                                LOG_ERR("SAL forwarding failed\n");
                                err = SAL_RESOLVE_ERROR;
                        } else {
                                num_forward++;
                        }
                }
                dest = next_dest;
        }

        if (!cskb) {
                /* TODO this is not going to work since it needs to be
                 * called PRIOR to hitting the end*/
                service_resolution_iter_inc_stats(&iter, -1, 
                                                  -(skb->len - hdr_len));
        }

        service_resolution_iter_destroy(&iter);
        service_entry_put(se);
        
        if (num_forward) 
                err = SAL_RESOLVE_FORWARD;

        return err;
}

static struct sock *serval_sal_demux_service(struct sk_buff *skb, 
                                             struct serval_hdr *sh,
                                             struct service_id *srvid)
{
        struct sock *sk;

        LOG_DBG("Demux on serviceID %s\n", service_id_to_str(srvid));

        /* only allow listening socket demux */
        sk = serval_sock_lookup_serviceid(srvid);
        
        if (!sk) {
                LOG_INF("No matching sock for serviceID %s\n",
                        service_id_to_str(srvid));
        } else {
                LOG_DBG("Socket is %p\n", sk);
        }
        
        return sk;
}

static struct sock *serval_sal_demux_flow(struct sk_buff *skb, 
                                          struct serval_hdr *sh)
{
        struct sock *sk = NULL;
        
        /* If SYN and not ACK is set, we know for sure that we must
         * demux on service id instead of socket id */
        if (!(sh->type == SERVAL_PKT_SYN && !sh->ack)) {
                /* Ok, check if we can demux on socket id */
                sk = serval_sock_lookup_flowid(&sh->dst_flowid);
                
                if (!sk) {
                        LOG_INF("No matching sock for flowid %u\n",
                                ntohl(sh->dst_flowid.s_id));
                }
        } else {
                LOG_DBG("cannot demux on flowid\n");
        }

        return sk;
}

static int serval_sal_resolve(struct sk_buff *skb, 
                              struct serval_hdr *sh,
                              struct sock **sk)
{
        int ret = SAL_RESOLVE_ERROR;
        struct service_id *srvid = NULL;
        struct serval_ext *ext = (struct serval_ext *)(sh + 1);
        
        if (ntohs(sh->length) <= sizeof(struct serval_hdr))
                return ret;
        
        switch (ext->type) {
        case SERVAL_CONNECTION_EXT:
                {
                        struct serval_connection_ext *conn_ext =
                                (struct serval_connection_ext *)ext;
                        /* Check for connection extension and do early
                         * drop if SYN or ACK flags are set. */
                        if (!has_connection_extension(sh))
                                return SAL_RESOLVE_ERROR;
                
                        srvid = &conn_ext->srvid;
                }
                break;
        case SERVAL_SERVICE_EXT:
                {
                        struct serval_service_ext *srv_ext =
                                (struct serval_service_ext *)ext;
                        
                        if (!has_service_extension(sh))
                                return SAL_RESOLVE_ERROR;
                        
                        srvid = &srv_ext->dst_srvid;
                }
                break;
        default:
                break;
        }
       
        if (!srvid)
                return SAL_RESOLVE_ERROR;

        if (atomic_read(&serval_transit)) {
                ret = serval_sal_resolve_service(skb, sh, srvid, sk);
        } else {
                *sk = serval_sal_demux_service(skb, sh, srvid);
                
                if (!(*sk))
                        ret = SAL_RESOLVE_FAIL;
                else 
                        ret = SAL_RESOLVE_DEMUX;
        }
        
        return ret;
}

int serval_sal_rcv(struct sk_buff *skb)
{
        struct sock *sk = NULL;
        struct serval_hdr *sh = 
                (struct serval_hdr *)skb_transport_header(skb);
        unsigned int hdr_len = 0;
        int err = 0;

        if (skb->len < sizeof(*sh)) {
                LOG_ERR("skb length too short (%u bytes)\n", 
                        skb->len);
                goto drop;
        }

        if (!sh) {
                LOG_ERR("No serval header\n");
                goto drop;
        }

        hdr_len = ntohs(sh->length);

        if (hdr_len < sizeof(*sh)) {
                LOG_ERR("Serval header length too short (%u bytes)\n",
                        hdr_len);
                goto drop;
        }
        
        if (sh->type > __SERVAL_PKT_MAX) {
                LOG_ERR("Bad Serval packet type\n");
                goto drop;
        }

        if (!pskb_may_pull(skb, hdr_len)) {
                LOG_ERR("cannot pull header (hdr_len=%u)\n",
                        hdr_len);
                goto drop;
        }
        
        /* FIXME: should add checksum verification and check for
           correct transport protocol. */
        
        LOG_PKT("Serval RECEIVE %s skb->len=%u\n",
                serval_hdr_to_str(sh), skb->len);
        
        /*
          FIXME: We should try to do early transport layer header
          checks here so that we can drop bad packets before we put
          them on, e.g., the backlog queue
        */
        
        /* Try flowID demux first */
        sk = serval_sal_demux_flow(skb, sh);
        
        if (!sk) {
                /* Resolve on serviceID */
                err = serval_sal_resolve(skb, sh, &sk);
                
                switch (err) {
                case SAL_RESOLVE_DEMUX:
                        break;
                case SAL_RESOLVE_FORWARD:
                        return 0;
                case SAL_RESOLVE_FAIL:
                        /* TODO: fix error codes for this function */
                        err = -EHOSTUNREACH;
                case SAL_RESOLVE_DROP:
                case SAL_RESOLVE_DELAY:
                case SAL_RESOLVE_ERROR:
                default:
                        goto drop;
                }
        }
        
        bh_lock_sock_nested(sk);

        /* We only reach this point if a valid local socket destination
         * has been found */
        /* Drop check if control queue is full here - this should
         * increment the per-service drop stats as well*/
        if (is_control_packet(skb) && 
            serval_sal_ctrl_queue_len(sk) >= MAX_CTRL_QUEUE_LEN) {

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
                bh_unlock_sock(sk);
                sock_put(sk);
                goto drop_no_stats;
        }

        if (!sock_owned_by_user(sk)) {
                err = serval_sal_do_rcv(sk, skb);
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
                LOG_PKT("Adding packet to backlog\n");
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
        service_inc_stats(-1, -(skb->len - hdr_len));
drop_no_stats:
        LOG_DBG("Dropping packet\n");
        kfree_skb(skb);
        return 0;
}

static int serval_sal_rexmit(struct sock *sk)
{        
        struct sk_buff *skb;
        int err;

        skb = serval_sal_ctrl_queue_head(sk);
        
        if (!skb) {
                LOG_ERR("No packet to retransmit!\n");
                return -1;
        }
        
        /* Always clone retransmitted packets */
        err = serval_sal_transmit_skb(sk, skb, 1, GFP_ATOMIC);
        
        if (err < 0) {
                LOG_ERR("Retransmit failed\n");
        }

        return err;
}

void serval_sal_rexmit_timeout(unsigned long data)
{
        struct sock *sk = (struct sock *)data;
        struct serval_sock *ssk = serval_sk(sk);

        bh_lock_sock(sk);

        LOG_DBG("Transmit timeout sock=%p num=%u backoff=%u\n", 
                sk, ssk->retransmits, backoff[ssk->retransmits]);
        
        if (backoff[ssk->retransmits + 1] == 0) {
                /* TODO: check error values here */
                LOG_DBG("NOT rescheduling timer!\n");
                sk->sk_err = ETIMEDOUT;
                serval_sal_done(sk);
        } else {
                LOG_DBG("Retransmitting and rescheduling timer\n");
                sk_reset_timer(sk, &serval_sk(sk)->retransmit_timer,
                               jiffies + (msecs_to_jiffies(ssk->rto) * 
                                          backoff[ssk->retransmits]));
                serval_sal_rexmit(sk);
                
                if (backoff[ssk->retransmits + 1] != 0)
                        ssk->retransmits++;
        }
        bh_unlock_sock(sk);
        sock_put(sk);
}

/* This timeout is used for TIMEWAIT and FINWAIT2 */
void serval_sal_timewait_timeout(unsigned long data)
{
        struct sock *sk = (struct sock *)data;
        bh_lock_sock(sk);
        LOG_DBG("Timeout in state %s\n", serval_sock_state_str(sk));
        serval_sal_done(sk);
        bh_unlock_sock(sk);
        /* put for the timer. */
        sock_put(sk);
}

static inline int serval_sal_do_xmit(struct sk_buff *skb)
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
        
        err = ssk->af_ops->queue_xmit(skb);

        if (err < 0) {
                LOG_ERR("xmit failed err=%d\n", err);
        }

        return err;
}

static inline int serval_sal_add_conn_ext(struct sock *sk, 
                                          struct sk_buff *skb,
                                          int flags)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_connection_ext *conn_ext;
 
        conn_ext = (struct serval_connection_ext *)
                skb_push(skb, sizeof(*conn_ext));
        conn_ext->exthdr.type = SERVAL_CONNECTION_EXT;
        conn_ext->exthdr.length = sizeof(*conn_ext);
        conn_ext->exthdr.flags = flags;
        conn_ext->seqno = htonl(SERVAL_SKB_CB(skb)->seqno);
        conn_ext->ackno = htonl(ssk->rcv_seq.nxt);
        memcpy(&conn_ext->srvid, &ssk->peer_srvid, 
               sizeof(conn_ext->srvid));
        memcpy(conn_ext->nonce, ssk->local_nonce, SERVAL_NONCE_SIZE);
        /*
        LOG_DBG("Connection extension srvid=%s\n",
                service_id_to_str(&conn_ext->srvid));
        */
        return sizeof(*conn_ext);
}

static inline int serval_sal_add_ctrl_ext(struct sock *sk, 
                                          struct sk_buff *skb,
                                          int flags)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_control_ext *ctrl_ext;

        ctrl_ext = (struct serval_control_ext *)
                skb_push(skb, sizeof(*ctrl_ext));
        ctrl_ext->exthdr.type = SERVAL_CONTROL_EXT;
        ctrl_ext->exthdr.length = sizeof(*ctrl_ext);
        ctrl_ext->exthdr.flags = flags;
        ctrl_ext->seqno = htonl(SERVAL_SKB_CB(skb)->seqno);
        ctrl_ext->ackno = htonl(ssk->rcv_seq.nxt);
        memcpy(ctrl_ext->nonce, ssk->local_nonce, SERVAL_NONCE_SIZE);
        return sizeof(*ctrl_ext);
}

static inline int serval_sal_add_service_ext(struct sock *sk, 
                                             struct sk_buff *skb,
                                             int flags)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_service_ext *srv_ext;

        srv_ext = (struct serval_service_ext *)
                skb_push(skb, sizeof(*srv_ext));
        srv_ext->exthdr.type = SERVAL_SERVICE_EXT;
        srv_ext->exthdr.length = sizeof(*srv_ext);
        srv_ext->exthdr.flags = flags;
        memcpy(&srv_ext->dst_srvid, &ssk->peer_srvid, 
               sizeof(srv_ext->dst_srvid));
        memcpy(&srv_ext->src_srvid, &ssk->local_srvid, 
               sizeof(srv_ext->src_srvid));

        return sizeof(*srv_ext);
}

int serval_sal_transmit_skb(struct sock *sk, struct sk_buff *skb, 
                            int clone_it, gfp_t gfp_mask)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct inet_sock *inet = inet_sk(sk);
	struct service_entry *se;
	struct dest *dest;
        struct serval_hdr *sh;
        int hdr_len = sizeof(*sh);
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

                skb_serval_set_owner_w(skb, sk);
	}

        /* NOTE:
         *
         * Do not use skb_set_owner_w(skb, sk) here as that will
         * reserve write space for the socket on the transport

         * packets as they might then fill up the write queue/buffer
         * for the socket. However, skb_set_owner_w(skb, sk) also
         * guarantees that the socket is not released until skb is
         * free'd, which is good. I guess we could implement our own
         * version of skb_set_owner_w() and grab a socket refcount
         * instead, which is released in the skb's destructor.
         */

        /* Add appropriate flags and headers */
        switch (SERVAL_SKB_CB(skb)->pkttype) {
        case SERVAL_PKT_SYN:
                hdr_len += serval_sal_add_conn_ext(sk, skb, 0);           
                break;
        case SERVAL_PKT_CLOSE:
                hdr_len += serval_sal_add_ctrl_ext(sk, skb, 0);
                break;
        case SERVAL_PKT_DATA:
                /* Unconnected datagram, add service extension */
                if (sk->sk_state == SERVAL_INIT && 
                    sk->sk_type == SOCK_DGRAM) {
                        hdr_len += serval_sal_add_service_ext(sk, skb, 0);
                }

                if (SERVAL_SKB_CB(skb)->flags & SVH_CONN_ACK)
                        hdr_len += serval_sal_add_conn_ext(sk, skb, 0);
                else if (SERVAL_SKB_CB(skb)->flags & SVH_ACK)
                        hdr_len += serval_sal_add_ctrl_ext(sk, skb, 0);

        default:
                break;
        }

        /* Add Serval header */
        sh = (struct serval_hdr *)skb_push(skb, sizeof(*sh));
        sh->type = SERVAL_SKB_CB(skb)->pkttype;
        sh->ack = SERVAL_SKB_CB(skb)->flags & SVH_ACK;
        sh->protocol = skb->protocol;
        sh->length = htons(hdr_len);
        memcpy(&sh->src_flowid, &ssk->local_flowid, sizeof(ssk->local_flowid));
        memcpy(&sh->dst_flowid, &ssk->peer_flowid, sizeof(ssk->peer_flowid));

        skb->protocol = IPPROTO_SERVAL;
        
        LOG_PKT("Serval XMIT %s skb->len=%u\n",
                serval_hdr_to_str(sh), skb->len);

        /* If we are connected, transmit immediately */
        if ((1 << sk->sk_state) & (SERVALF_CONNECTED | 
                                   SERVALF_FINWAIT1 | 
                                   SERVALF_FINWAIT2 | 
                                   SERVALF_CLOSING | 
                                   SERVALF_CLOSEWAIT))
		return serval_sal_do_xmit(skb);
        
	/* Use service id to resolve IP, unless IP is already set. */
        if (memcmp(&zero_addr, 
                   &inet_sk(sk)->inet_daddr, 
                   sizeof(zero_addr)) != 0) {

                skb_reset_transport_header(skb);
                /*
                char ip[18];
                LOG_DBG("Sending packet to user-specified "
                        "advisory address: %s\n", 
                        inet_ntop(AF_INET, &SERVAL_SKB_CB(skb)->addr, 
                                  ip, 17));
                */
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
                return serval_sal_do_xmit(skb);
        }

        /* TODO - prefix, flags??*/
        //ssk->srvid_flags;
        //ssk->srvid_prefix;
        se = service_find(&ssk->peer_srvid, 
                          sizeof(struct service_id) * 8);

	if (!se) {
		LOG_INF("service lookup failed for [%s]\n",
                        service_id_to_str(&ssk->peer_srvid));
                service_inc_stats(-1, -dlen);
                kfree_skb(skb);
		return -EADDRNOTAVAIL;
	}

	service_resolution_iter_init(&iter, se, SERVICE_ITER_ALL);

        /*
          Send to all destinations resolved for this service.
        */
	dest = service_resolution_iter_next(&iter);
	
        if (!dest) {
                LOG_DBG("No device to transmit on!\n");
                service_resolution_iter_inc_stats(&iter, -1, -dlen);
                kfree_skb(skb);
                service_resolution_iter_destroy(&iter);
                service_entry_put(se);
                return -EHOSTUNREACH;
        }

	while (dest) {
		struct dest *next_dest;
                struct net_device *dev = NULL;
               
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
                                kfree_skb(skb);
                                err = -ENOBUFS;
				break;
			}
                        /* Cloned skb will have no socket set. */
                        skb_serval_set_owner_w(cskb, sk);
		}
                
                /* Remember the flow destination */
		if (is_sock_dest(dest)) {
                        /* use a localhost address and bounce it off
                         * the IP layer*/
                        memcpy(&inet->inet_daddr,
                               &local_addr, sizeof(inet->inet_daddr));

                        /* kludgey but sets the output device for
                         * reaching a local socket destination to the
                         * default device TODO - make sure this is
                         * appropriate for kernel operation as well
                         */
#if defined(OS_USER)
                        dev = dev_get_by_index(NULL, 0);
#else
                        /* FIXME: not sure about getting the device
                           without a refcount here... */
                        dev = __dev_get_by_name(sock_net(sk), "lo");
#endif
		} else {
                        memcpy(&inet->inet_daddr,
                               dest->dst,
                               sizeof(inet->inet_daddr) < dest->dstlen ? 
                               sizeof(inet->inet_daddr) : dest->dstlen);
                       
                        dev = dest->dest_out.dev;
                }
                
                skb_set_dev(cskb, dev);

                /* Need also to set the source address for
                   checksum calculation */
                dev_get_ipv4_addr(dev, &inet->inet_saddr);

#if defined(ENABLE_DEBUG)
                {
                        char src[18], dst[18];
                        LOG_PKT("Resolved service %s with IP %s->%s " 
                                "on device=%s\n",
                                service_id_to_str(&ssk->peer_srvid),
                                inet_ntop(AF_INET, &inet->inet_saddr, 
                                          src, sizeof(src)), 
                                inet_ntop(AF_INET, &inet->inet_daddr, 
                                          dst, sizeof(dst)), 
                                cskb->dev ? cskb->dev->name : "Undefined");
                }
#endif
                /* Make sure no route is associated with the
                   socket. When IP routes a packet which is associated
                   with a socket, it will stick to that route in the
                   future. This will inhibit a re-resolution, which is
                   not what we want here. */
                
                if (__sk_dst_get(sk))
                        __sk_dst_reset(sk);
                
                /*
                  We have to calculate the checksum for resolution
                  packets at this point as it is not until here that
                  we know the destination IP to put in the
                  packet. Normally, the checksum is calculated by the
                  transport protocol before being passed to SAL.
                */
                if (ssk->af_ops->send_check)
                        ssk->af_ops->send_check(sk, cskb);

                /* Cannot reset transport header until after checksum
                   calculation since send_check requires access to
                   transport header */
                skb_reset_transport_header(cskb);

		err = ssk->af_ops->queue_xmit(cskb);

		if (err < 0) {
			LOG_ERR("xmit failed err=%d\n", err);
		}
		dest = next_dest;
	}
        
        /* Reset dst cache since we don't want to potantially cache a
           broadcast destination */
        if (__sk_dst_get(sk))
                __sk_dst_reset(sk);

        service_resolution_iter_destroy(&iter);
	service_entry_put(se);

	return err;
}

/* This function is typically called by transport to send data */
int serval_sal_xmit_skb(struct sk_buff *skb) 
{
        SERVAL_SKB_CB(skb)->pkttype = SERVAL_PKT_DATA;
        return serval_sal_transmit_skb(skb->sk, skb, 0, GFP_ATOMIC);
}
