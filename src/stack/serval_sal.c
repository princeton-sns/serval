/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * The Service Access Layer (SAL).
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 *          David Shue <dshue@cs.princeton.edu>
 *          Rob Kiefer <rkiefer@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
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
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#endif
#include <serval_request_sock.h>
#include <service.h>
#include <af_serval.h>

extern atomic_t serval_nr_socks;

static struct net_addr local_addr = {
        .net_raw = { 0x7F, 0x00, 0x00, 0x01 }
};

static struct net_addr zero_addr = {
        .net_raw = { 0x00, 0x00, 0x00, 0x00 }
};

#define MAX_NUM_SERVAL_EXTENSIONS 5 /* TODO: Set reasonable number */

/*
 * The next routines deal with comparing 32 bit unsigned ints
 * and worry about wraparound (automatic with unsigned arithmetic).
 * Taken from linux/net/tcp.h.
 */
static inline int before(__u32 seq1, __u32 seq2)
{
        return (__s32)(seq1-seq2) < 0;
}

#define after(seq2, seq1) 	before(seq1, seq2)

/* is s2<=s1<=s3 ? */
static inline int between(__u32 seq1, __u32 seq2, __u32 seq3)
{
	return seq3 - seq2 >= seq1 - seq2;
}

/* 
   Context for parsed Serval headers 
*/   
struct serval_context {
        struct sk_buff *skb;
        struct serval_hdr *hdr;
        unsigned short length; /* Total length of all headers */
        unsigned short flags;
        uint32_t seqno; /* Sequence number of control information */
        uint32_t ackno; /* Acknowledgement number of control information */
        struct serval_ext *ext[MAX_NUM_SERVAL_EXTENSIONS];
        struct serval_control_ext *ctrl_ext;
        struct serval_connection_ext *conn_ext;
        struct serval_description_ext *desc_ext;
        struct serval_service_ext *srv_ext;
        struct serval_source_ext *src_ext;
        struct serval_migrate_ext *mig_ext;
};

#if defined(OS_LINUX_KERNEL)
extern int serval_udp_encap_skb(struct sk_buff *skb, 
                                __u32 saddr, __u32 daddr, 
                                u16 sport, u16 dport);
#endif

static int serval_sal_state_process(struct sock *sk,
                                    struct sk_buff *skb,
                                    struct serval_context *ctx);

static int serval_sal_transmit_skb(struct sock *sk, struct sk_buff *skb, 
                                   int use_copy, gfp_t gfp_mask);

static size_t min_ext_length[] = {
        [0] = sizeof(struct serval_hdr),
        [SERVAL_CONNECTION_EXT] = sizeof(struct serval_connection_ext),
        [SERVAL_CONTROL_EXT] = sizeof(struct serval_control_ext),
        [SERVAL_SERVICE_EXT] = sizeof(struct serval_service_ext),
        [SERVAL_DESCRIPTION_EXT] = sizeof(struct serval_description_ext),
        [SERVAL_SOURCE_EXT] = sizeof(struct serval_source_ext),
        [SERVAL_MIGRATE_EXT] = sizeof(struct serval_migrate_ext),
};

#if defined(ENABLE_DEBUG)

static char* serval_ext_name[] = {
        [0] = "INVALID",
        [SERVAL_CONNECTION_EXT] = "CONNECTION",
        [SERVAL_CONTROL_EXT] = "CONTROL",
        [SERVAL_SERVICE_EXT] = "SERVICE",
        [SERVAL_DESCRIPTION_EXT] = "DESCRIPTION",
        [SERVAL_SOURCE_EXT] = "SOURCE",
        [SERVAL_MIGRATE_EXT] = "MIGRATE",
};

static int print_base_hdr(struct serval_hdr *sh, char *buf, int buflen)
{
        return snprintf(buf, buflen,
                        "SYN=%u ACK=%u FIN=%u RST=%u RSYN=%u "
                        "len=%u proto=%u src_fl=%s dst_fl=%s",
                        sh->syn, sh->ack, sh->fin, 
                        sh->rst, sh->rsyn,                        
                        ntohs(sh->length), sh->protocol,
                        flow_id_to_str(&sh->src_flowid), 
                        flow_id_to_str(&sh->dst_flowid));
}

static int print_base_ext(struct serval_ext *xt, char *buf, int buflen)
{
        return snprintf(buf, buflen, "%s length=%u",
                        serval_ext_name[xt->type],
                        xt->length);
}

static int print_connection_ext(struct serval_ext *xt, char *buf, int buflen)
{
        struct serval_connection_ext *cxt = 
                (struct serval_connection_ext *)xt;
        
        return snprintf(buf, buflen,
                        "seqno=%u ackno=%u srvid=%s",
                        ntohl(cxt->seqno),
                        ntohl(cxt->ackno),
                        service_id_to_str(&cxt->srvid));
}

static int print_control_ext(struct serval_ext *xt, char *buf, int buflen)
{
        struct serval_control_ext *cxt = 
                (struct serval_control_ext *)xt;
        
        return snprintf(buf, buflen,
                        "seqno=%u ackno=%u",
                        ntohl(cxt->seqno),
                        ntohl(cxt->ackno));
}

static int print_service_ext(struct serval_ext *xt, char *buf, int buflen)
{
        struct serval_service_ext *sxt = 
                (struct serval_service_ext *)xt;
        
        return snprintf(buf, buflen,
                        "src_srvid=%s dst_srvid=%s",
                        service_id_to_str(&sxt->src_srvid),
                        service_id_to_str(&sxt->dst_srvid));
}

static int print_description_ext(struct serval_ext *xt, char *buf, int buflen)
{
        /* struct serval_description_ext *dxt = 
           (struct serval_description_ext *)xt; */
                
        return 0;
}

static int print_source_ext(struct serval_ext *xt, char *buf, int buflen)
{
        struct serval_source_ext *sxt = 
                (struct serval_source_ext *)xt;
        unsigned char *a = sxt->source;
        int n = SERVAL_SOURCE_EXT_NUM_ADDRS(sxt);
        char addr[18];
        int len = 0;

        while (n > 0) {
                len += snprintf(buf + len, buflen - len, "%s ",
                                inet_ntop(AF_INET, a, addr, 18));
                a += 4;
                n--;
        }
        if (len) {
                /* Remove trailing white space */
                buf[--len] = '\0';
        }
        return len;
}

static int print_migrate_ext(struct serval_ext *xt, char *buf, int buflen)
{
        struct serval_migrate_ext *mxt = 
                (struct serval_migrate_ext *)xt;
        
        return snprintf(buf, buflen,
                        "seqno=%u ackno=%u",
                        ntohl(mxt->seqno),
                        ntohl(mxt->ackno));
}

typedef int (*print_ext_func_t)(struct serval_ext *, char *, int);

static print_ext_func_t print_ext_func[] = {
        [0] = &print_base_ext,
        [SERVAL_CONNECTION_EXT] = &print_connection_ext,
        [SERVAL_CONTROL_EXT] = &print_control_ext,
        [SERVAL_SERVICE_EXT] = &print_service_ext,
        [SERVAL_DESCRIPTION_EXT] = &print_description_ext,
        [SERVAL_SOURCE_EXT] = &print_source_ext,
        [SERVAL_MIGRATE_EXT] = &print_migrate_ext,
};

static int print_ext(struct serval_ext *xt, char *buf, int buflen)
{
        int len;

        len = snprintf(buf, buflen, "{");
        len += print_base_ext(xt, buf + len, buflen - len);
        len += snprintf(buf + len, buflen - len, " ");
        len += print_ext_func[xt->type](xt, buf + len, buflen - len);
        return snprintf(buf + len, buflen - len, "}") + len;
}

static const char *serval_hdr_to_str(struct serval_hdr *sh) 
{
#define HDR_BUFLEN 512
        static char buf[HDR_BUFLEN];
        int hdr_len = ntohs(sh->length);
        struct serval_ext *ext;
        int len = 0;
        
        buf[len++] = '[';
        
        len += print_base_hdr(sh, buf + len, HDR_BUFLEN - len);
        
        if (len < (HDR_BUFLEN - 1)) {
                buf[len++] = ']';
                buf[len] = '\0';
        }
        
        hdr_len -= sizeof(*sh);
        ext = SERVAL_EXT_FIRST(sh);
                
        while (hdr_len > 0) {
                if (ext->type >= __SERVAL_EXT_TYPE_MAX) {
                        LOG_DBG("Bad extension type (=%u)\n",
                                ext->type);
                        return buf;
                }

                if (ext->length < min_ext_length[ext->type]) {
                        LOG_DBG("Bad extension \'%s\' hdr_len=%d "
                                "ext->length=%u\n",
                                serval_ext_name[ext->type], 
                                hdr_len,
                                ext->length);
                        return buf;
                }

                len += print_ext(ext, buf + len, 
                                 HDR_BUFLEN - len);

                hdr_len -= ext->length;
                ext = SERVAL_EXT_NEXT(ext);
        }       

        if (hdr_len) {
                LOG_DBG("hdr_len=%d is not 0, bad header?\n",
                        hdr_len);
        }

        len += snprintf(buf + len, HDR_BUFLEN - len, "]");

        return buf;
}

#endif /* ENABLE_DEBUG */

static int parse_base_ext(struct serval_ext *ext, struct sk_buff *skb,
                          struct serval_context *ctx)
{
        return 0;
}

static int parse_connection_ext(struct serval_ext *ext, struct sk_buff *skb,
                                struct serval_context *ctx)
{
        if (ctx->conn_ext)
                return -1;
        
        ctx->conn_ext = (struct serval_connection_ext *)ext;
        ctx->seqno = ntohl(ctx->conn_ext->seqno);
        ctx->ackno = ntohl(ctx->conn_ext->ackno);
        
        return ext->length;
}

static int parse_control_ext(struct serval_ext *ext, struct sk_buff *skb,
                             struct serval_context *ctx)
{
        if (ctx->ctrl_ext)
                return -1;
        
        ctx->ctrl_ext = (struct serval_control_ext *)ext;
        ctx->seqno = ntohl(ctx->ctrl_ext->seqno);
        ctx->ackno = ntohl(ctx->ctrl_ext->ackno);
        
        return ext->length;
}

static int parse_service_ext(struct serval_ext *ext, struct sk_buff *skb,
                             struct serval_context *ctx)
{
        if (ctx->srv_ext)
                return -1;
        
        ctx->srv_ext = (struct serval_service_ext *)ext;

        return ext->length;
}

static int parse_description_ext(struct serval_ext *ext, struct sk_buff *skb,
                                 struct serval_context *ctx)
{
        return ext->length;
}

static int parse_source_ext(struct serval_ext *ext, struct sk_buff *skb,
                            struct serval_context *ctx)
{
        /*
        int i;
        __u32 addr;
        */      
        if (ctx->src_ext)
                return -1;
        
        ctx->src_ext = (struct serval_source_ext *)ext;

        /* Should be two addresses minimum */
        if (SERVAL_SOURCE_EXT_NUM_ADDRS(ctx->src_ext) < 2)
                return -1;

        /*
        dev_get_ipv4_addr(skb->dev, IFADDR_LOCAL, &addr);

        for (i = 0; i < SERVAL_SOURCE_EXT_NUM_ADDRS(ctx->src_ext); i++) {
                if (memcmp(SERVAL_SOURCE_EXT_GET_ADDR(ctx->src_ext, i),
                           &addr, sizeof(addr)) == 0) {
                        LOG_DBG("Our address already in SOURCE ext. Possible loop!\n");
                        return -1;
                }
        }
        */                  
        return ext->length;
}

static int parse_migrate_ext(struct serval_ext *ext, struct sk_buff *skb,
                             struct serval_context *ctx)
{
        if (ctx->mig_ext)
                return -1;

        ctx->mig_ext = (struct serval_migrate_ext *)ext;
        ctx->seqno = ntohl(ctx->mig_ext->seqno);
        ctx->ackno = ntohl(ctx->mig_ext->ackno);
                    
        return ext->length;
}


typedef int (*parse_ext_func_t)(struct serval_ext *, struct sk_buff *, 
                                struct serval_context *ctx);

static parse_ext_func_t parse_ext_func[] = {
        [0] = &parse_base_ext,
        [SERVAL_CONNECTION_EXT] = &parse_connection_ext,
        [SERVAL_CONTROL_EXT] = &parse_control_ext,
        [SERVAL_SERVICE_EXT] = &parse_service_ext,
        [SERVAL_DESCRIPTION_EXT] = &parse_description_ext,
        [SERVAL_SOURCE_EXT] = &parse_source_ext,
        [SERVAL_MIGRATE_EXT] = &parse_migrate_ext,
};

static inline int parse_ext(struct serval_ext *ext, struct sk_buff *skb,
                            struct serval_context *ctx)
{
        if (ext->type >= __SERVAL_EXT_TYPE_MAX) {
                LOG_DBG("Bad extension type (=%u)\n",
                        ext->type);
                return -1;
        }
        
        if (ext->length < min_ext_length[ext->type]) {
                LOG_DBG("Bad extension \'%s\' length (=%u)\n",
                        serval_ext_name[ext->type], ext->length);
                return -1;
        }
        
        LOG_DBG("EXT %s length=%u\n",
                serval_ext_name[ext->type], 
                ext->length);
        
        return parse_ext_func[ext->type](ext, skb, ctx);
}

enum serval_parse_mode {
        SERVAL_PARSE_BASE,
        SERVAL_PARSE_ALL,
};

/**
   Parse Serval header and all extension, doing basic sanity checks.

   Returns: 0 on success.
*/
static int serval_sal_parse_hdr(struct sk_buff *skb, 
                                struct serval_context *ctx,
                                enum serval_parse_mode mode)
{
        struct serval_ext *ext;
        unsigned int i = 0;
        int hdr_len;

        memset(ctx, 0, sizeof(struct serval_context));
        
        ctx->skb = skb;
        ctx->hdr = serval_hdr(skb);
        ctx->length = ntohs(ctx->hdr->length);
        ext = SERVAL_EXT_FIRST(ctx->hdr);
        
        /* Sanity checks */
        if (ctx->length < sizeof(struct serval_hdr))
                return -1;

        /* Only base header parse, return */
        if (mode == SERVAL_PARSE_BASE)
                return 0;

        /* Parse extensions */
        hdr_len = ctx->length - sizeof(*ctx->hdr);

        while (hdr_len > 0 && i < MAX_NUM_SERVAL_EXTENSIONS) {
                if (parse_ext(ext, skb, ctx) < 0)
                        return -1;

                ctx->ext[i++] = ext;                
                hdr_len -= ext->length;
                ext = SERVAL_EXT_NEXT(ext);
        }

        /* Parse flags */
        if (ctx->hdr->syn)
                ctx->flags |= SVH_SYN;
        if (ctx->hdr->ack)
                ctx->flags |= SVH_ACK;
        if (ctx->hdr->fin)
                ctx->flags |= SVH_FIN;
        if (ctx->hdr->rst)
                ctx->flags |= SVH_RST;
        if (ctx->hdr->rsyn)
                ctx->flags |= SVH_RSYN;

        /* hdr_len should be zero if everything was OK */
        return hdr_len;
}

static inline int has_seqno(struct serval_context *ctx)
{
        /* Real control packets are those with sequence numbers */
        if (ctx->conn_ext || ctx->ctrl_ext || ctx->mig_ext)
                return 1;
        return 0;
}

static inline int is_pure_data(struct serval_context *ctx)
{
        return ctx->flags == 0;
}

static inline int is_pure_ack(struct serval_context *ctx)
{
        return ctx->hdr->ack && !ctx->hdr->fin && 
                !ctx->hdr->syn && !ctx->hdr->rsyn && !ctx->hdr->rst;
}

static inline int has_connection_extension(struct serval_context *ctx)
{
        /* Check for connection extension. We require that this
         * extension always directly follows the main Serval
         * header */
        if (!ctx->conn_ext)
                return 0;

        if (ctx->length < sizeof(*ctx->hdr) + sizeof(*ctx->conn_ext)) {
                LOG_PKT("No connection extension, hdr_len=%u\n", 
                        ctx->length);
                return 0;
        }
        
        if (ctx->conn_ext->exthdr.type != SERVAL_CONNECTION_EXT || 
            ctx->conn_ext->exthdr.length != sizeof(*ctx->conn_ext)) {
                LOG_DBG("No connection extension, bad extension type\n");
                return 0;
        }

        return 1;
}

static inline int has_service_extension(struct serval_context *ctx)
{
        if (!ctx->srv_ext)
                return 0;

        if (ctx->length < sizeof(*ctx->hdr) + sizeof(*ctx->srv_ext)) {
                LOG_PKT("No service extension, hdr_len=%u\n", 
                        ctx->length);
                return 0;
        }
        
        if (ctx->srv_ext->exthdr.type != SERVAL_SERVICE_EXT || 
            ctx->srv_ext->exthdr.length != sizeof(*ctx->srv_ext)) {
                LOG_DBG("No service extension, bad extension type\n");
                return 0;
        }

        return 1;
}

static inline int has_valid_seqno(uint32_t seg_seq, struct sock *sk)
{        
        struct serval_sock *ssk = serval_sk(sk);
        int ret = 0;

        if (sk->sk_state == SERVAL_LISTEN ||
            sk->sk_state == SERVAL_REQUEST)
                return 1;

        if (!before(seg_seq, ssk->rcv_seq.nxt) 
            /* && !after(seg_seq, ssk->rcv_seq.nxt + ssk->rcv_seq.wnd) */) {
                ret = 1;
        }

        if (ret == 0) {
                LOG_DBG("Seqno not in sequence received=%u next=%u."
                        " Could be ACK though...\n",
                        seg_seq, ssk->rcv_seq.nxt);
        }
        return ret;
}

static inline int packet_has_transport_hdr(struct sk_buff *skb, 
                                           struct serval_hdr *sh)
{
        /* We might have pulled the serval header already. */
        if ((unsigned char *)sh == skb_transport_header(skb)) {
                LOG_DBG("skb->len=%u sh->length=%u\n", 
                        skb->len, ntohs(sh->length));
                return skb->len > ntohs(sh->length);
        }
            
        LOG_DBG("skb->len=%u\n", skb->len);
        return skb->len > 0;
}

static inline int has_valid_connection_extension(struct sock *sk, 
                                                 struct serval_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);

        if (!has_connection_extension(ctx))
                return 0;

        if (memcmp(ctx->conn_ext->nonce, ssk->peer_nonce, 
                   SERVAL_NONCE_SIZE) != 0) {
                LOG_PKT("Connection extension has bad nonce\n");
                return 0;
        }

        return 1;
}

static inline int has_valid_control_extension(struct sock *sk, 
                                              struct serval_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);

        if (!ctx->ctrl_ext)
                return 0;

        /* Check for control extension. We require that this
         * extension always directly follows the main Serval
         * header */
        if (ctx->length < sizeof(*ctx->hdr) + sizeof(*ctx->ctrl_ext)) {
                LOG_PKT("No control extension, hdr_len=%u\n", 
                        ctx->length);
                return 0;
        }
        
        if (ctx->ctrl_ext->exthdr.type != SERVAL_CONTROL_EXT ||
            ctx->ctrl_ext->exthdr.length != sizeof(*ctx->ctrl_ext)) {
                LOG_PKT("No control extension, bad extension type\n");
                return 0;
        }

        if (memcmp(ctx->ctrl_ext->nonce, ssk->peer_nonce, 
                   SERVAL_NONCE_SIZE) != 0) {
                LOG_PKT("Control extension has bad nonce\n");
                return 0;
        }

        return 1;
}

static inline int has_valid_migrate_extension(struct sock *sk,
                                              struct serval_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        
        if (!ctx->mig_ext)
                return 0;
        
        if (ctx->length < sizeof(*ctx->hdr) + sizeof(*ctx->mig_ext)) {
                LOG_PKT("No migrate extension, hdr_len=%u\n",
                        ctx->length);
                return 0;
        }
        
        if (ctx->mig_ext->exthdr.type != SERVAL_MIGRATE_EXT ||
            ctx->mig_ext->exthdr.length != sizeof(*ctx->mig_ext)) {
                LOG_PKT("No migrate extension, bad type\n");
                return 0;
        }
        
        if (memcmp(ctx->mig_ext->nonce, ssk->peer_nonce,
                   SERVAL_NONCE_SIZE) != 0) {
                LOG_PKT("Migrate extension has bad nonce\n");
                return 0;
        }
        
        return 1;
}

static inline int has_valid_desc_extension(struct sock *sk,
                                           struct serval_hdr *sfh)
{
        /*struct serval_sock *ssk = serval_sk(sk);
        struct serval_description_ext *desc_ext =
                (struct serval_description_ext *)(sfh + 1);
        unsigned int hdr_len = ntohs(sfh->length);
        unsigned int addr_list_len = (ntohs(sfh->length) - 2 * sizeof(uint8_t) -
                                     sizeof(uint16_t)) / sizeof(net_addr);

        if (hdr_len < sizeof(*sfh) + sizeof(*desc_ext)) {
                LOG_PKT("No desc extension, hdr_len=%u\n", hdr_len);
                return 0;
        }

        if (desc_ext->type != SERVAL_DESCRIPTION_EXT ||
                ntohs(desc_ext->length) != sizeof(*desc_ext)) {
                LOG_PKT("No desc extension, bad extension type\n");
                return 0;
        }

        if (addr_list_len < 1) {
        	    LOG_PKT("No desc extension, no list of addrs\n");
                return 0;
        }*/

        return 1;
}

static inline __sum16 serval_sal_csum(struct serval_hdr *sh, int len)
{
        return ip_compute_csum(sh, len);
}

static inline void serval_sal_send_check(struct serval_hdr *sh)
{
        sh->check = 0;
        sh->check = serval_sal_csum(sh, ntohs(sh->length));
}

/* Compute the actual rto_min value */
static inline u32 serval_sal_rto_min(struct sock *sk)
{
	u32 rto_min = SAL_RTO_MIN;
#if defined(OS_LINUX_KERNEL)
	struct dst_entry *dst = __sk_dst_get(sk);
	if (dst && dst_metric_locked(dst, RTAX_RTO_MIN))
		rto_min = dst_metric_rtt(dst, RTAX_RTO_MIN);
#endif
	return rto_min;
}

/* The RTO estimation for the SAL is taken directly from the Linux
   kernel TCP code. */
/* Called to compute a smoothed rtt estimate. The data fed to this
 * routine either comes from timestamps, or from segments that were
 * known _not_ to have been retransmitted [see Karn/Partridge
 * Proceedings SIGCOMM 87]. The algorithm is from the SIGCOMM 88
 * piece by Van Jacobson.
 * NOTE: the next three routines used to be one big routine.
 * To save cycles in the RFC 1323 implementation it was better to break
 * it up into three procedures. -- erics
 */
static void serval_sal_rtt_estimator(struct sock *sk, const __u32 mrtt)
{
	struct serval_sock *ssk = serval_sk(sk);
	long m = mrtt; /* RTT */

	/*	The following amusing code comes from Jacobson's
	 *	article in SIGCOMM '88.  Note that rtt and mdev
	 *	are scaled versions of rtt and mean deviation.
	 *	This is designed to be as fast as possible
	 *	m stands for "measurement".
	 *
	 *	On a 1990 paper the rto value is changed to:
	 *	RTO = rtt + 4 * mdev
	 *
	 * Funny. This algorithm seems to be very broken.
	 * These formulae increase RTO, when it should be decreased, increase
	 * too slowly, when it should be increased quickly, decrease too quickly
	 * etc. I guess in BSD RTO takes ONE value, so that it is absolutely
	 * does not matter how to _calculate_ it. Seems, it was trap
	 * that VJ failed to avoid. 8)
	 */
	if (m == 0)
		m = 1;
	if (ssk->srtt != 0) {
		m -= (ssk->srtt >> 3);	/* m is now error in rtt est */
		ssk->srtt += m;		/* rtt = 7/8 rtt + 1/8 new */
		if (m < 0) {
			m = -m;		/* m is now abs(error) */
			m -= (ssk->mdev >> 2);   /* similar update on mdev */
			/* This is similar to one of Eifel findings.
			 * Eifel blocks mdev updates when rtt decreases.
			 * This solution is a bit different: we use finer gain
			 * for mdev in this case (alpha*beta).
			 * Like Eifel it also prevents growth of rto,
			 * but also it limits too fast rto decreases,
			 * happening in pure Eifel.
			 */
			if (m > 0)
				m >>= 3;
		} else {
			m -= (ssk->mdev >> 2);   /* similar update on mdev */
		}
		ssk->mdev += m;	    	/* mdev = 3/4 mdev + 1/4 new */
		if (ssk->mdev > ssk->mdev_max) {
			ssk->mdev_max = ssk->mdev;
			if (ssk->mdev_max > ssk->rttvar)
				ssk->rttvar = ssk->mdev_max;
		}
		if (after(ssk->snd_seq.una, ssk->rtt_seq)) {
			if (ssk->mdev_max < ssk->rttvar)
				ssk->rttvar -= (ssk->rttvar - ssk->mdev_max) >> 2;
			ssk->rtt_seq = ssk->snd_seq.nxt;
			ssk->mdev_max = serval_sal_rto_min(sk);
		}
	} else {
		/* no previous measure. */
		ssk->srtt = m << 3;	/* take the measured time to be rtt */
		ssk->mdev = m << 1;	/* make sure rto = 3*rtt */
		ssk->mdev_max = ssk->rttvar = max(ssk->mdev, 
                                                  serval_sal_rto_min(sk));
		ssk->rtt_seq = ssk->snd_seq.nxt;
	}
}

static inline void serval_sal_bound_rto(const struct sock *sk)
{
	if (serval_sk(sk)->rto > SAL_RTO_MAX)
		serval_sk(sk)->rto = SAL_RTO_MAX;
}

static inline u32 __serval_sal_set_rto(const struct serval_sock *ssk)
{
	return (ssk->srtt >> 3) + ssk->rttvar;
}

/* Calculate rto without backoff.  This is the second half of Van Jacobson's
 * routine referred to above.
 */
static inline void serval_sal_set_rto(struct sock *sk)
{
	struct serval_sock *ssk = serval_sk(sk);
	/* Old crap is replaced with new one. 8)
	 *
	 * More seriously:
	 * 1. If rtt variance happened to be less 50msec, it is hallucination.
	 *    It cannot be less due to utterly erratic ACK generation made
	 *    at least by solaris and freebsd. "Erratic ACKs" has _nothing_
	 *    to do with delayed acks, because at cwnd>2 true delack timeout
	 *    is invisible. Actually, Linux-2.4 also generates erratic
	 *    ACKs in some circumstances.
	 */
	ssk->rto = __serval_sal_set_rto(ssk);

	/* 2. Fixups made earlier cannot be right.
	 *    If we do not estimate RTO correctly without them,
	 *    all the algo is pure shit and should be replaced
	 *    with correct one. It is exactly, which we pretend to do.
	 */

	/* NOTE: clamping at SAL_RTO_MIN is not required, current algo
	 * guarantees that rto is higher.
	 */
	serval_sal_bound_rto(sk);
}

static void serval_sal_rearm_rto(struct sock *sk)
{
	struct serval_sock *ssk = serval_sk(sk);

	if (!serval_sal_ctrl_queue_head(sk)) {
		serval_sock_clear_xmit_timer(sk);
	} else {
		serval_sock_reset_xmit_timer(sk, ssk->rto, SAL_RTO_MAX);
	}
}

static inline void serval_sal_ack_update_rtt(struct sock *sk,
                                             const s32 seq_rtt)
{
        serval_sal_rtt_estimator(sk, seq_rtt);
	serval_sal_set_rto(sk);
	serval_sk(sk)->backoff = 0; 

        LOG_DBG("Updated RTO HZ=%u seq_rtt=%d rto=%u\n",
                HZ, seq_rtt, serval_sk(sk)->rto);
}

/*
  Given an ACK, clean all packets from the control queue that this ACK
  acknowledges. Or, alternatively, clean all packets if indicated by
  the 'all' argument.

  Reschedule retransmission timer as neccessary, i.e., if there are
  still unacked packets in the queue and we removed the first packet
  in the queue.
*/
static int serval_sal_clean_rtx_queue(struct sock *sk, uint32_t ackno, int all)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *skb, *fskb = serval_sal_ctrl_queue_head(sk);
        unsigned int num = 0;
        u32 now = sal_time_stamp;
        s32 seq_rtt = -1;
        int err = 0;
       
        while ((skb = serval_sal_ctrl_queue_head(sk)) && 
               skb != serval_sal_send_head(sk)) {
                if (ackno > SERVAL_SKB_CB(skb)->seqno || all) {
                        serval_sal_unlink_ctrl_queue(skb, sk);

                        if (SERVAL_SKB_CB(skb)->flags & SVH_RETRANS) {
                                seq_rtt = -1;
                        } else if (!all) {
                                seq_rtt = now - SERVAL_SKB_CB(skb)->when;
                                serval_sal_ack_update_rtt(sk, seq_rtt);
                                serval_sal_rearm_rto(sk);
                        }

                        LOG_PKT("cleaned rtxQ seqno=%u HZ=%u seq_rtt=%d\n", 
                                SERVAL_SKB_CB(skb)->seqno, 
                                HZ, seq_rtt);

                        kfree_skb(skb);
                        skb = serval_sal_ctrl_queue_head(sk);
                        if (skb)
                                ssk->snd_seq.una = SERVAL_SKB_CB(skb)->seqno;
                        num++;                        
                } else {
                        break;
                }
        }

        LOG_PKT("cleaned up %u packets from rtx queue, queue len=%u\n", 
                num, serval_sal_ctrl_queue_len(sk));
        
        /* Did we remove the first packet in the queue? */
        if (serval_sal_ctrl_queue_head(sk) != fskb) {
                serval_sock_clear_xmit_timer(sk);
        }

        if (serval_sal_ctrl_queue_head(sk)) {
                LOG_PKT("Setting retrans timer, queue len=%u rto=%u (ms)\n",
                        serval_sal_ctrl_queue_len(sk), 
                        jiffies_to_msecs(ssk->rto));
                serval_sock_reset_xmit_timer(sk, ssk->rto, SAL_RTO_MAX);
        }

        return err;
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
static int serval_sal_write_xmit(struct sock *sk, unsigned int limit,
                                 gfp_t gfp)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *skb;
        unsigned int num = 0;
        int err = 0;
        
        LOG_PKT("writing from queue snd_una=%u snd_nxt=%u snd_wnd=%u\n",
                ssk->snd_seq.una, ssk->snd_seq.nxt, ssk->snd_seq.wnd);
        
        LOG_DBG("RTO HZ=%u rto=%u rto_msec=%u\n",
                HZ, ssk->rto, jiffies_to_msecs(ssk->rto));

	while ((skb = serval_sal_send_head(sk)) && 
               (ssk->snd_seq.nxt - ssk->snd_seq.una) <= ssk->snd_seq.wnd) {
                
                if (limit && num == limit)
                        break;

                SERVAL_SKB_CB(skb)->when = sal_time_stamp;
                                
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
   Queue SAL control packets for the purpose of doing retransmissions
   and socket buffer accounting. The TCP SYN is piggy-backed on the
   SAL control SYN and should take one byte send buffer
   space. Therefore, we need to keep the SYN until it is ACKed or
   freed due to reaching max retransmissions. 
*/
static int serval_sal_queue_and_push(struct sock *sk, struct sk_buff *skb)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err;
        
        /* Remove previously queued control packet(s). We currently
           only queue one control packet at a time, allowing control
           packets to override each other (necessary for, e.g.,
           (re)migration). It is not strictly necessary to use a queue
           for this, but we use it anyway for convenience and future
           proofness (in case we want to implement a send window). */
        serval_sal_clean_rtx_queue(sk, 0, 1);

        /* Queue the new packet */
        serval_sal_queue_ctrl_skb(sk, skb);

        /* 
           Set retransmission timer.
        */
        if (skb == serval_sal_ctrl_queue_head(sk))
                serval_sock_reset_xmit_timer(sk, ssk->rto, SAL_RTO_MAX);

        /* 
           Write packets in queue to network.
        */
        err = serval_sal_write_xmit(sk, 1, GFP_ATOMIC);

        if (err != 0) {
                LOG_ERR("xmit failed err=%d\n", err);
        }

        return err;
}

static struct sk_buff *sk_sal_alloc_skb(struct sock *sk, int size, gfp_t gfp)
{
        struct sk_buff *skb;

        skb = alloc_skb(sk->sk_prot->max_header, GFP_ATOMIC);

        if (!skb)
                return NULL;
        
        skb_reserve(skb, sk->sk_prot->max_header);
        skb_serval_set_owner_w(skb, sk);
        skb->protocol = IPPROTO_SERVAL;
        skb->ip_summed = CHECKSUM_NONE;

        return skb;
}

static int serval_sal_send_syn(struct sock *sk, u32 seqno)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *skb;
        int err;

        skb = sk_sal_alloc_skb(sk, sk->sk_prot->max_header, GFP_ATOMIC);

        if (!skb)
                return -ENOMEM;

        /* Ask transport to fill in */
        if (ssk->af_ops->conn_build_syn) {
                err = ssk->af_ops->conn_build_syn(sk, skb);

                if (err) {
                        LOG_ERR("Transport protocol returned error\n");
                        kfree_skb(skb);
                        return err;
                }
        }

        SERVAL_SKB_CB(skb)->flags = SVH_SYN;
        SERVAL_SKB_CB(skb)->seqno = seqno;
        ssk->snd_seq.nxt = seqno + 1;

        LOG_INF("Sending REQUEST seqno=%u local_flowid=%s srvid=%s\n",
                SERVAL_SKB_CB(skb)->seqno,
                flow_id_to_str(&ssk->local_flowid),
                service_id_to_str(&ssk->peer_srvid));

        err = serval_sal_queue_and_push(sk, skb);
        
        if (err < 0) {
                LOG_ERR("queuing failed\n");
        }
        
        return err;
}

int serval_sal_connect(struct sock *sk, struct sockaddr *uaddr, 
                       int addr_len)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct service_id *srvid = &((struct sockaddr_sv *)uaddr)->sv_srvid;
        
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

        /* Disable segmentation offload */
        sk->sk_gso_type = 0;
        
        return serval_sal_send_syn(sk, ssk->snd_seq.iss);
}

static void serval_sal_timewait(struct sock *sk, int state)
{
        unsigned long timeout = jiffies;

        serval_sock_set_state(sk, state);
        /* FIXME: Dynamically set timeout */
        if (state == SERVAL_TIMEWAIT) {
                timeout += msecs_to_jiffies(60000);
        } else {
                timeout += msecs_to_jiffies(10000);
        }
        sk_reset_timer(sk, &serval_sk(sk)->tw_timer, timeout); 
}

/* Called by transport when it is done sending/receiving data */
void serval_transport_done(struct sock *sk)
{
        
}

void serval_sal_done(struct sock *sk)
{
        LOG_DBG("socket DONE!\n");

        if (serval_sk(sk)->af_ops->done)
                serval_sk(sk)->af_ops->done(sk);
        
        serval_sock_done(sk);
}

static int serval_sal_send_rsyn(struct sock *sk, u32 seqno)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *skb;
        int err;

        if (sk->sk_state == SERVAL_REQUEST ||
            sk->sk_state == SERVAL_LISTEN ||
            sk->sk_state == SERVAL_CLOSED) {
                LOG_DBG("Cannot send RSYN in state %s\n",
                        serval_sock_state_str(sk));
                return 0;
        }

        switch (ssk->sal_state) {
        case SAL_INITIAL:
                serval_sock_set_sal_state(sk, SAL_RSYN_SENT);
                break;
        case SAL_RSYN_RECV:
                serval_sock_set_sal_state(sk, SAL_RSYN_SENT_RECV);
                break;
        case SAL_RSYN_SENT:
        case SAL_RSYN_SENT_RECV:
                /* Here we just move to the same state again, so
                   nothing to do. */
                break;
        }

        for (;;) {
                skb = sk_sal_alloc_skb(sk, sk->sk_prot->max_header,
                                       GFP_ATOMIC);
                if (skb)
                        break;
                yield();
        }

        /* Use same sequence number as previous packet for migration
           requests */
        LOG_DBG("Sending Migrate Request\n");
        SERVAL_SKB_CB(skb)->flags = SVH_RSYN;
        SERVAL_SKB_CB(skb)->seqno = seqno;

        if (sk->sk_state == SERVAL_FINWAIT1 ||
            sk->sk_state == SERVAL_CLOSING ||
            sk->sk_state == SERVAL_LASTACK) {
                /* We have sent our FIN, but not received the ACK. We
                   need to add the FIN bit. */
                SERVAL_SKB_CB(skb)->flags |= SVH_FIN;
        }

        err = serval_sal_queue_and_push(sk, skb);
 
        if (err < 0) {
                LOG_ERR("queuing failed\n");
        }

        return err;
}

int serval_sal_migrate(struct sock *sk)
{
        LOG_DBG("Sending RSYN\n");
        return serval_sal_send_rsyn(sk, serval_sk(sk)->snd_seq.nxt++);
}

static int serval_sal_send_fin(struct sock *sk, u32 seqno)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *skb;
        int err;

        /* We are under lock, so allocation must be atomic */
        /* Socket is locked, keep trying until memory is available. */
        for (;;) {
                skb = sk_sal_alloc_skb(sk, sk->sk_prot->max_header, 
                                       GFP_ATOMIC);
                
                if (skb)
                        break;
                yield();
        }
        
        LOG_DBG("Sending SAL FIN\n");
        SERVAL_SKB_CB(skb)->flags = SVH_FIN;
        SERVAL_SKB_CB(skb)->seqno = seqno;
        
        /* If we are in the process of migrating, then we should
           probably add also the RSYN flag. Otherwise, if the previous
           RSYN was lost, this FIN packet will "override" the RSYN and
           the migration will never happen. TODO: verify that this is
           really the way to handle this situation. */
        if (ssk->sal_state == SAL_RSYN_SENT) {
                LOG_DBG("RSYN was in progress, adding RSYN flag\n");
                SERVAL_SKB_CB(skb)->flags |= SVH_RSYN;
        } else if (serval_sk(sk)->sal_state == SAL_RSYN_RECV) {
                SERVAL_SKB_CB(skb)->flags |= SVH_RSYN | SVH_ACK;
        }
        
        serval_sock_set_flag(ssk, SSK_FLAG_FIN_SENT);

        err = serval_sal_queue_and_push(sk, skb);
        
        if (err < 0) {
                LOG_ERR("queuing failed\n");
        }

        return err;
}

/* Called as a result of user app close() */
void serval_sal_close(struct sock *sk, long timeout)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;

        LOG_INF("Closing socket %p in state %s\n",
                sk, serval_sock_state_str(sk));

        sk->sk_shutdown |= SEND_SHUTDOWN;
        
        switch (sk->sk_state) {
        case SERVAL_CONNECTED:
        case SERVAL_RESPOND:
        case SERVAL_CLOSEWAIT:
                if (sk->sk_state == SERVAL_CLOSEWAIT) {
                        serval_sal_timewait(sk, SERVAL_LASTACK);
                } else {
                        serval_sal_timewait(sk, SERVAL_FINWAIT1);
                }

                if (ssk->af_ops->conn_close) {
                        /* Tell transport to, e.g., schedule
                           end-of-stream (i.e., put FIN in the last
                           queued transport segment) */
                        err = ssk->af_ops->conn_close(sk);

                        if (err != 0) {
                                LOG_ERR("Transport error %d\n", err);
                        }
                } else {
                        err = serval_sal_send_shutdown(sk);
                }
                break;
        case SERVAL_FINWAIT1:
        case SERVAL_FINWAIT2:
        case SERVAL_CLOSING:
        case SERVAL_TIMEWAIT:
                LOG_ERR("Close called in post close() state %s\n",
                        serval_sock_state_str(sk));
                break;
        default:
                LOG_DBG("Calling serval_sal_done on socket in state %s\n",
                        serval_sock_state_str(sk));
                serval_sal_done(sk);
                break;
        }
}

static int serval_sal_send_ack(struct sock *sk)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *skb;
        int err = 0;

        skb = sk_sal_alloc_skb(sk, sk->sk_prot->max_header, GFP_ATOMIC);
                        
        if (!skb)
                return -ENOMEM;

        SERVAL_SKB_CB(skb)->flags = SVH_ACK;
        /* Do not increment sequence numbers for pure ACKs */
        SERVAL_SKB_CB(skb)->seqno = ssk->snd_seq.nxt;

        LOG_DBG("Sending ACK seqno=%u\n", ssk->rcv_seq.nxt);

        if (err == 0) {
                /* Do not queue pure ACKs */
                err = serval_sal_transmit_skb(sk, skb, 0, GFP_ATOMIC);
        }
               
        if (err < 0) {
                LOG_ERR("xmit failed\n");
        }
   
        return err;
}

enum source_ext_res {
        SOURCE_EXT_IP_EXISTS,
        SOURCE_EXT_IP_NONE,
        SOURCE_EXT_NONE,
};

static 
enum source_ext_res serval_sal_source_ext_check(struct sk_buff *skb,
                                                struct serval_context *ctx,
                                                __u32 ipaddr)
{
        int i;
        
        if (!ctx->src_ext)
                return SOURCE_EXT_NONE;
        
        for (i = 0; i < SERVAL_SOURCE_EXT_NUM_ADDRS(ctx->src_ext); i++) {
                if (memcmp(SERVAL_SOURCE_EXT_GET_ADDR(ctx->src_ext, i),
                           &ipaddr, 
                           sizeof(ipaddr)) == 0) {
                        return SOURCE_EXT_IP_EXISTS;
                }
        }
        return SOURCE_EXT_IP_NONE;
}

/**
   Add source extension to SAL header. If one already exists, append
   the source IP address of the packet to the existing header.

   @param in_skb the skb to add the extension to.  

   @param ctx the serval header context for the incoming packet (note that
   this context may not point to the headers in in_skb as in_skb may
   be a clone or copy.
*/
static int serval_sal_add_source_ext(struct sk_buff **in_skb,
                                     struct serval_context *ctx)
{
        struct sk_buff *skb = *in_skb;
        struct iphdr *iph;
        struct serval_hdr *sh;
        struct serval_source_ext *sxt = ctx ? ctx->src_ext : NULL;
        unsigned int size, extra_len = 0, serval_len = 0, ext_len = 0;
        unsigned char *ptr;

        iph = ip_hdr(skb);
        sh = serval_hdr(skb);

        if (!ctx) {
                LOG_ERR("No header context\n");
                return -EINVAL;
        }
        
        switch (serval_sal_source_ext_check(skb, ctx, iph->daddr)) {
        case SOURCE_EXT_IP_NONE:
                /* We just add another IP address. */
                LOG_DBG("Appending address to SOURCE extension\n");
                extra_len = 4;
                ext_len = ctx->src_ext->sv_ext_length + extra_len;
                break;
        case SOURCE_EXT_NONE:
                LOG_DBG("Adding new SOURCE extension\n");
                extra_len = SERVAL_SOURCE_EXT_LEN + 4;
                ext_len = extra_len;
                break;
        case SOURCE_EXT_IP_EXISTS:
                LOG_ERR("IP dst address already in "
                        "SOURCE ext. Possible loop!\n");
                return -1;
        }
        
        serval_len = ctx->length + extra_len;
        size = (char *)sh - (char *)iph;

        /* Push back to IP header */
        skb_push(skb, size);

        if (skb_headroom(skb) < (extra_len + size + 
                                 skb->dev->hard_header_len)) {
                LOG_DBG("Expanding SKB headroom\n");
                skb = skb_copy_expand(skb, skb_headroom(skb) + 
                                      extra_len,
                                      skb_tailroom(skb),
                                      GFP_ATOMIC);

                if (!skb) {
                        LOG_ERR("Could not expand skb!\n");
                        return -ENOMEM;
                }

                kfree_skb(*in_skb);
                *in_skb = skb;
        }
        
        skb_reset_network_header(skb);
        iph = ip_hdr(skb);
        skb_set_transport_header(skb, size);
        sh = serval_hdr(skb);

        if (ctx->src_ext) {
                /* Point to just after source extension in the new skb */
                unsigned int off = (SERVAL_SOURCE_EXT_GET_LAST_ADDR(ctx->src_ext) - 
                                    (unsigned char *)ctx->hdr) + 4;
                ptr = ((unsigned char *)sh + off);
        } else {
                /* No previous source extension. Append new header. */
                ptr = ((unsigned char *)sh + ctx->length);
        }

        /* Check if we need to linearize */
        if (skb_is_nonlinear(skb)) {
                if (skb_linearize(skb)) {
                        LOG_ERR("Could not linearize skb\n");
                        return -ENOMEM;
                }
        }

        /* Move back everything from the point of insertion, making
           room for extra_len bytes */
        memmove(skb_push(skb, extra_len), iph,
                ptr - (unsigned char *)iph);
        
        /* Update header pointers */
        skb_set_mac_header(skb, -skb->dev->hard_header_len);
        skb_reset_network_header(skb);
        iph = ip_hdr(skb);
        pskb_pull(skb, size);
        skb_reset_transport_header(skb);
        sh = serval_hdr(skb);

        if (ctx->src_ext) {
                sxt = (struct serval_source_ext *)
                        ((char *)sh + ((char *)ctx->src_ext - 
                                       (char *)ctx->hdr));
        } else {
                sxt = (struct serval_source_ext *)
                        ((unsigned char *)sh + ctx->length);
        }

        sxt->sv_ext_type = SERVAL_SOURCE_EXT;
        sxt->sv_ext_length = ext_len;
        sxt->sv_ext_flags = 0;

        if (ctx->src_ext) {
                memcpy(SERVAL_SOURCE_EXT_GET_LAST_ADDR(sxt), 
                       &iph->daddr, sizeof(iph->daddr));
        } else {
                memcpy(SERVAL_SOURCE_EXT_GET_ADDR(sxt, 0), 
                       &iph->saddr, sizeof(iph->saddr));
                memcpy(SERVAL_SOURCE_EXT_GET_ADDR(sxt, 1), 
                       &iph->daddr, sizeof(iph->daddr));
        }
        
        sh->check = 0;
        sh->length = htons(serval_len);
        
        LOG_DBG("New hdr: skb->len=%u %s\n",
                skb->len,
                serval_hdr_to_str(sh));

        return extra_len;
}

static int serval_sal_send_synack(struct sock *sk,
                                  struct request_sock *rsk,
                                  struct sk_buff *skb,
                                  struct serval_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_request_sock *srsk = serval_rsk(rsk);
        struct sk_buff *rskb;
        struct dst_entry *dst = NULL;
        struct serval_hdr *rsh;
        struct serval_connection_ext *conn_ext;
        unsigned int serval_len = 0;
        int err = 0;

        /* Allocate RESPONSE reply */
        rskb = sk_sal_alloc_skb(sk, sk->sk_prot->max_header, GFP_ATOMIC);

        if (!rskb)
                return -ENOMEM;

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
        skb_dst_set(rskb, dst);
        rskb->dev = skb->dev;
        
        skb_reset_transport_header(rskb);

        /* Add source extension, if necessary */
        if (ctx->src_ext) {
                struct serval_source_ext *sxt;

                LOG_DBG("Adding SOURCE ext to response\n");

                /*
                  The SYN had a source extension, which means we were
                  not the first hop in this resolution and we must
                  therefore also append our source address. Then send
                  back the reply with the initial destination address
                  as source to comply with ingress filtering (e.g.,
                  for clients behind NATs).
                */
                sxt = (struct serval_source_ext *)
                        skb_push(rskb, ctx->src_ext->sv_ext_length + 4);

                if (!sxt) {
                        LOG_DBG("Could not add source extensions\n");
                        goto drop_and_release;
                }

                memcpy(sxt, ctx->src_ext, ctx->src_ext->sv_ext_length);
                sxt->sv_ext_type = SERVAL_SOURCE_EXT;
                sxt->sv_ext_length = ctx->src_ext->sv_ext_length + 4;
                memcpy(SERVAL_SOURCE_EXT_GET_LAST_ADDR(sxt), 
                       &inet_rsk(rsk)->loc_addr,
                       sizeof(inet_rsk(rsk)->loc_addr));
                serval_len += sxt->sv_ext_length;
        } 

        /* Add connection extension */
        conn_ext = (struct serval_connection_ext *)
                skb_push(rskb, sizeof(*conn_ext));
        conn_ext->exthdr.type = SERVAL_CONNECTION_EXT;
        conn_ext->exthdr.length = sizeof(*conn_ext);
        conn_ext->exthdr.flags = 0;
        conn_ext->seqno = htonl(srsk->iss_seq);
        conn_ext->ackno = htonl(srsk->rcv_seq + 1);
        memcpy(&conn_ext->srvid, &srsk->peer_srvid, 
               sizeof(srsk->peer_srvid));

        /* Copy our nonce to connection extension */
        memcpy(conn_ext->nonce, srsk->local_nonce, SERVAL_NONCE_SIZE);
        serval_len += sizeof(*conn_ext);
 
        /* Add Serval header */
        rsh = (struct serval_hdr *)skb_push(rskb, sizeof(*rsh));
        rsh->syn = 1;
        rsh->ack = 1;
        rsh->protocol = ctx->hdr->protocol;
        rsh->length = htons(serval_len + sizeof(*rsh));
        memcpy(&rsh->dst_flowid, &srsk->peer_flowid, 
               sizeof(rsh->dst_flowid));
        memcpy(&rsh->src_flowid, &srsk->local_flowid, 
               sizeof(srsk->local_flowid));

        LOG_PKT("Serval XMIT RESPONSE %s skb->len=%u\n",
                serval_hdr_to_str(rsh), rskb->len);
        
        skb_reset_transport_header(skb);

        /* Calculate SAL header checksum. */
        serval_sal_send_check(rsh);

#if defined(OS_LINUX_KERNEL)
        if (ip_hdr(skb)->protocol == IPPROTO_UDP) {
                struct iphdr *iph = ip_hdr(skb);
                struct udphdr *uh = (struct udphdr *)
                        ((char *)iph + (iph->ihl << 2));

                /* Remember that we should perform UDP
                   encapsulation */
                srsk->udp_encap_sport = ntohs(uh->dest);
                srsk->udp_encap_dport = ntohs(uh->source);

                LOG_DBG("Sending UDP encapsulated response\n");
                
                if (serval_udp_encap_skb(rskb, srsk->reply_saddr,
                                         inet_rsk(rsk)->rmt_addr,
                                         srsk->udp_encap_sport,
                                         srsk->udp_encap_dport)) {
                        LOG_ERR("SYN-ACK encapsulation failed\n");
                        goto drop_and_release;
                }
        }
#endif
        /* 
           Cannot use serval_sal_transmit_skb here since we do not yet
           have a full accepted socket (sk is the listening sock). 
        */
        err = serval_ipv4_build_and_send_pkt(rskb, sk, 
                                             srsk->reply_saddr,
                                             inet_rsk(rsk)->rmt_addr, NULL);
        return 0;
 drop_and_release:
        dst_release(dst);
#if defined(OS_LINUX_KERNEL)
 drop_response:
#endif
        kfree_skb(rskb);
        return 0;
}

static int serval_sal_rcv_syn(struct sock *sk, 
                              struct sk_buff *skb,
                              struct serval_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_connection_ext *conn_ext = ctx->conn_ext;
        struct request_sock *rsk;
        struct serval_request_sock *srsk;
        struct net_addr myaddr;
        int err = 0;

        /* Make compiler be quiet */
        memset(&myaddr, 0, sizeof(myaddr));

        LOG_DBG("REQUEST seqno=%u\n", ctx->seqno);

        if (sk->sk_ack_backlog >= sk->sk_max_ack_backlog) 
                goto drop;

        /* Try to figure out the source address for the incoming
         * interface so that we can use it in our reply.  
         *
         * FIXME:
         * should probably route the reply here somehow in case we
         * want to reply on another interface than the incoming one.
         */
        if (!dev_get_ipv4_addr(skb->dev, IFADDR_LOCAL, &myaddr)) {
                LOG_ERR("No source address for interface %s\n",
                        skb->dev);
                goto drop;
        }

        rsk = serval_reqsk_alloc(sk->sk_prot->rsk_prot);

        if (!rsk)
                goto drop;

        srsk = serval_rsk(rsk);

        /* Copy fields in request packet into request sock */
        memcpy(&srsk->peer_flowid, &ctx->hdr->src_flowid, 
               sizeof(ctx->hdr->src_flowid));
        memcpy(&srsk->peer_srvid, &ctx->conn_ext->srvid,
               sizeof(ctx->conn_ext->srvid));
        memcpy(srsk->peer_nonce, conn_ext->nonce, SERVAL_NONCE_SIZE);
        srsk->rcv_seq = ctx->seqno;

        /* Save our local address that we grabbed from the incoming
         * interface. This address should in most cases be the same
         * address as the IP header destination of the incoming
         * packet, unless the SYN was broadcast. */
        memcpy(&inet_rsk(rsk)->loc_addr, &myaddr,
               sizeof(inet_rsk(rsk)->loc_addr));

        /* 
           Here we need to figure out which addresses to save in our
           sockets, and which ones to use in our reply.
           
           This decision may vary depending on whether we are dealing
           with a client behind a NAT or not. For a NAT'd client we
           need to spoof the source address in the reply to ensure it
           carries the source expected by the NAT (i.e., the
           destination address that the client initially
           targeted---this would be the first SAL forwarder/hop).

           Further, if the request carried a source extension it means
           that the packet was forwarded in the SAL. Then we will find
           the true source address in the extension and otherwise in
           the IP header.

           A source extension should always carry at least two
           addresses: the original source, and the first forwarder.
        */
        if (ctx->src_ext) {
                /* Get the original source and save in our request
                 * socket */
                memcpy(&inet_rsk(rsk)->rmt_addr,
                       SERVAL_SOURCE_EXT_GET_ADDR(ctx->src_ext, 0),
                       sizeof(inet_rsk(rsk)->rmt_addr));
                
                /* If the request was UDP encapsulated due to NAT, we
                 * should spoof our source address in the reply to
                 * make sure we can traverse the NAT on the way
                 * back. */
                if (ip_hdr(skb)->protocol == IPPROTO_UDP) {
                        /* Get the first hop SAL forwarder, i.e., the original
                         * destination in the request that the client
                         * sent. Save this in our request sock and use in our
                         * reply.  */
                        memcpy(&srsk->reply_saddr,
                               SERVAL_SOURCE_EXT_GET_ADDR(ctx->src_ext, 1),
                               sizeof(srsk->reply_saddr));
                } else {
                        /* No NAT, use our own address in the reply. */
                        memcpy(&srsk->reply_saddr,
                               &myaddr,
                               sizeof(srsk->reply_saddr));
                }
        } else {
                /* There was no source extension, so we will find the
                 * addresses in the IP header. */
                memcpy(&inet_rsk(rsk)->rmt_addr, &ip_hdr(skb)->saddr,
                       sizeof(inet_rsk(rsk)->rmt_addr));
                
                /* Packet was broadcasted, so we cannot use the
                 * incoming destination address to figure out which
                 * interface address to use. */
                if (skb->pkt_type == PACKET_BROADCAST)
                        memcpy(&srsk->reply_saddr,
                               &myaddr,
                               sizeof(srsk->reply_saddr));
                else 
                        memcpy(&srsk->reply_saddr,
                               &ip_hdr(skb)->daddr,
                               sizeof(srsk->reply_saddr));
        }
        
#if defined(ENABLE_DEBUG)
        {
                char rmtstr[18], locstr[18], replystr[18];
                LOG_DBG("rmt_addr=%s loc_addr=%s reply_saddr=%s\n",
                        inet_ntop(AF_INET, &inet_rsk(rsk)->rmt_addr, 
                                  rmtstr, 18),
                        inet_ntop(AF_INET, &inet_rsk(rsk)->loc_addr, 
                                  locstr, 18),
                        inet_ntop(AF_INET, &srsk->reply_saddr, 
                                  replystr, 18));
        }
#endif

        /* Add the new request socket to the SYN queue. */
        list_add(&srsk->lh, &ssk->syn_queue);
        sk->sk_ack_backlog++;
        
        /* Call upper transport protocol handler */
        if (ssk->af_ops->conn_request) {
                err = ssk->af_ops->conn_request(sk, rsk, skb);
                
                /* Transport protocol will free the skb on error */
                if (err)
                        goto done;
        }
        
        err = serval_sal_send_synack(sk, rsk, skb, ctx);
 drop:
        /* Free the SYN request */
        kfree_skb(skb);
 done:
        return err;
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
        struct serval_sock *ssk = serval_sk(sk);
        struct sock *nsk;

        nsk = sk_clone_lock(sk, GFP_ATOMIC);

        if (nsk) {
                struct serval_sock *nssk = serval_sk(nsk);
                int ret;
                
                atomic_inc(&serval_nr_socks);
                serval_sock_init(nsk);
                /* Indicate that this is a child socket. Necessary to
                 * know that this socket should not unregister its
                 * serviceID. */
                serval_sock_set_flag(nssk, SSK_FLAG_CHILD);
                
                /* Transport protocol specific init. */                
                ret = ssk->af_ops->conn_child_sock(sk, skb, 
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
  Check if a request sock has previously been created by a SYN, in
  case of receiving retransmitted/duplicate SYNs.  */  
static struct request_sock *serval_sal_find_rsk(struct sock *sk,
                                                struct serval_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_request_sock *srsk;
        
        list_for_each_entry(srsk, &ssk->syn_queue, lh) {
                if (memcmp(&srsk->peer_flowid, &ctx->hdr->src_flowid, 
                           sizeof(srsk->peer_flowid)) == 0) {
                        return &srsk->rsk.req;
                }
        }

        list_for_each_entry(srsk, &ssk->accept_queue, lh) {
                if (memcmp(&srsk->peer_flowid, &ctx->hdr->src_flowid, 
                           sizeof(srsk->peer_flowid)) == 0) {
                        return &srsk->rsk.req;
                }
        }

        return NULL;
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
                                                    struct sk_buff *skb,
                                                    struct serval_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_request_sock *srsk;

        list_for_each_entry(srsk, &ssk->syn_queue, lh) {
                if (memcmp(&srsk->local_flowid, &ctx->hdr->dst_flowid, 
                           sizeof(srsk->local_flowid)) == 0) {
                        struct sock *nsk;
                        struct serval_sock *nssk;
                        struct request_sock *rsk = &srsk->rsk.req;
                        struct inet_request_sock *irsk = &srsk->rsk;
                        struct inet_sock *newinet;
                        
                        if (memcmp(srsk->peer_nonce, ctx->conn_ext->nonce, 
                                   SERVAL_NONCE_SIZE) != 0) {
                                LOG_ERR("Bad nonce\n");
                                return NULL;
                        }

                        if (ctx->seqno != srsk->rcv_seq + 1) {
                                LOG_ERR("Bad seqno received=%u expected=%u\n",
                                        ctx->seqno, 
                                        srsk->rcv_seq + 1);
                                return NULL;
                        }
                        if (ctx->ackno != srsk->iss_seq + 1) {
                                LOG_ERR("Bad ackno received=%u expected=%u\n",
                                        ctx->ackno, 
                                        srsk->iss_seq + 1);
                                return NULL;
                        }
                        
                        nsk = serval_sal_create_respond_sock(sk, skb, 
                                                             rsk, NULL);
                        
                        if (!nsk)
                                return NULL;

                        /* Move request sock to accept queue */
                        list_move_tail(&srsk->lh, &ssk->accept_queue);
                        nsk->sk_ack_backlog = 0;

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

                        memcpy(nssk->local_nonce, srsk->local_nonce, 
                               SERVAL_NONCE_SIZE);
                        memcpy(nssk->peer_nonce, srsk->peer_nonce, 
                               SERVAL_NONCE_SIZE);
                        nssk->snd_seq.iss = srsk->iss_seq;
                        nssk->snd_seq.una = srsk->iss_seq;
                        nssk->snd_seq.nxt = srsk->iss_seq + 1;
                        nssk->rcv_seq.iss = srsk->rcv_seq;
                        nssk->rcv_seq.nxt = srsk->rcv_seq + 1;
                        nssk->udp_encap_sport = srsk->udp_encap_sport;
                        nssk->udp_encap_dport = srsk->udp_encap_dport;
                        rsk->sk = nsk;
                        
                        /* Hash the sock to make it available */
                        nsk->sk_prot->hash(nsk);

                        return nsk;
                }
        }
        
        return sk;
}

static int serval_sal_ack_process(struct sock *sk,
                                  struct sk_buff *skb,
                                  struct serval_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
       
        if (!ctx->hdr->ack)
                return -1;

	/* If the ack is older than previous acks
	 * then we can probably ignore it.
	 */
	if (before(ctx->ackno, ssk->snd_seq.una))
		goto old_ack;

	/* If the ack corresponds to something we haven't sent yet,
           ignore.
	 */
	if (after(ctx->ackno, ssk->snd_seq.nxt))
		goto invalid_ack;

        serval_sal_clean_rtx_queue(sk, ctx->ackno, 0);
        serval_sk(sk)->snd_seq.una = ctx->ackno;

        LOG_PKT("received valid ACK ackno=%u\n", 
                ctx->ackno);

        /* Check for migration handshake ACK */
        switch (ssk->sal_state) {
        case SAL_RSYN_RECV:
                if (!ctx->hdr->rsyn)
                        serval_sock_set_sal_state(sk, SAL_INITIAL);
                break;
        case SAL_RSYN_SENT_RECV:
                if (!ctx->hdr->rsyn)
                        serval_sock_set_sal_state(sk, SAL_RSYN_SENT);
                break;
        default:
                return 0;
        }
        
        if (!ctx->hdr->rsyn) {
                LOG_DBG("Migration complete for flow %s\n",
                        flow_id_to_str(&ssk->local_flowid));
                memcpy(&inet_sk(sk)->inet_daddr, &ssk->mig_daddr, 4);
                memset(&ssk->mig_daddr, 0, 4);
                sk_dst_reset(sk);
                
                /* If we're UDP encapsulating, make sure we
                   now switch to the port used for sending the
                   RSYN-ACK.  */
                ssk->udp_encap_dport = ssk->udp_encap_migration_dport;
                
                if (ssk->af_ops->migration_completed)
                        ssk->af_ops->migration_completed(sk);
        }

        return 0;
 invalid_ack:
        LOG_DBG("invalid ackno %u out of sequence, expected %u\n",
                ctx->ackno, ssk->snd_seq.una + 1);
        return -1;
 old_ack:
        LOG_DBG("old ackno %u, expected %u\n",
                ctx->ackno, ssk->snd_seq.una + 1);
        return -1;
}

static int serval_sal_rcv_rsynack(struct sock *sk,
                                  struct sk_buff *skb,
                                  struct serval_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct net_device *mig_dev = dev_get_by_index(sock_net(sk), 
                                                      ssk->mig_dev_if);
        int err = 0;

        LOG_DBG("Recv RSYN+ACK in %s state\n",
                serval_sock_sal_state_str(sk));

        if (!mig_dev) {
                LOG_ERR("No migration device set\n");
                return -1;
        }

        switch (ssk->sal_state) {
        case SAL_RSYN_SENT:
                LOG_DBG("Migration complete for flow %s!\n",
                        flow_id_to_str(&ssk->local_flowid));
                serval_sock_set_sal_state(sk, SAL_INITIAL);
                
                dev_get_ipv4_addr(mig_dev, IFADDR_LOCAL, 
                                  &inet_sk(sk)->inet_saddr);
                serval_sock_set_dev(sk, mig_dev);
                serval_sock_set_mig_dev(sk, NULL);
                sk_dst_reset(sk);

                if (ssk->af_ops->migration_completed)
                        ssk->af_ops->migration_completed(sk);
                break;
        case SAL_RSYN_SENT_RECV:
                serval_sock_set_sal_state(sk, SAL_RSYN_RECV);
                memcpy(&ssk->mig_daddr, &ip_hdr(skb)->saddr, 4);
                sk_dst_reset(sk);
                break;
        default:
                goto out;
        }
        
        ssk->rcv_seq.nxt = ctx->seqno + 1;

        err = serval_sal_send_ack(sk);
out:        
        dev_put(mig_dev);

        return err;
}

/*
  This function handles the case when we received an RSYN (without
  ACK). */
static int serval_sal_rcv_rsyn(struct sock *sk,
                               struct sk_buff *skb,
                               struct serval_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct sk_buff *rskb = NULL;

        LOG_INF("received Migration REQUEST\n");
        
        if (!has_valid_migrate_extension(sk, ctx)) {
                LOG_ERR("Bad migration extension\n");
                return -1;
        }
       
        /* We ignore migrations in these states */
        if (sk->sk_state == SERVAL_CLOSED ||
            sk->sk_state == SERVAL_LISTEN ||
            sk->sk_state == SERVAL_REQUEST)
                return -1;
        
        LOG_DBG("RSYN received in %s state\n",
                serval_sock_sal_state_str(sk));
        
        switch(ssk->sal_state) {
        case SAL_INITIAL:
                serval_sock_set_sal_state(sk, SAL_RSYN_RECV);
                break;
        case SAL_RSYN_SENT:
                serval_sock_set_sal_state(sk, SAL_RSYN_SENT_RECV);
                break;
        case SAL_RSYN_RECV:
        case SAL_RSYN_SENT_RECV:
                /* Just send another RSYN+ACK to acknowledge the new
                   address change */
                break;
        default:
                LOG_DBG("RSYN in SAL state %s\n", 
                        serval_sock_sal_state_str(sk));
                return 0;
        }
        
        if (ssk->af_ops->freeze_flow)
                ssk->af_ops->freeze_flow(sk);
        
#if defined(OS_LINUX_KERNEL)
                /* Packet is UDP encapsulated, make sure we remember
                 * the port to send the reply on. */
        if (ip_hdr(skb)->protocol == IPPROTO_UDP) {
                struct iphdr *iph = ip_hdr(skb);
                struct udphdr *uh = (struct udphdr *)
                        ((char *)iph + (iph->ihl << 2));
                ssk->udp_encap_migration_dport = ntohs(uh->source);
        }
#endif /* OS_LINUX_KERNEL */

        ssk->rcv_seq.nxt = ctx->seqno + 1;        
        memcpy(&ssk->mig_daddr, &ip_hdr(skb)->saddr, 4);
        rskb = sk_sal_alloc_skb(sk, sk->sk_prot->max_header,
                                GFP_ATOMIC);
        if (!rskb)
                return -ENOMEM;
        
        SERVAL_SKB_CB(rskb)->flags = SVH_RSYN | SVH_ACK;
        SERVAL_SKB_CB(rskb)->seqno = ssk->snd_seq.nxt++;
        
        /* FIXME: should the RSYN-ACK be queued for retransmission? I
           guess it is not necessary since the peer that sent the RSYN
           would retransmit. */
        SERVAL_SKB_CB(skb)->when = sal_time_stamp;

        return serval_sal_transmit_skb(sk, rskb, 0, GFP_ATOMIC);
}

static int serval_sal_rcv_fin(struct sock *sk, 
                              struct sk_buff *skb,
                              struct serval_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;

        LOG_INF("received SAL FIN\n");
        
        if (!has_valid_control_extension(sk, ctx)) {
                LOG_ERR("Bad control extension\n");
                return -1;
        }
        
        /* Just ignore this close request in case transport
           has not yet indicated it is ready. */
        if (!(sk->sk_shutdown & RCV_SHUTDOWN))
                return 1;

        ssk->rcv_seq.nxt = ctx->seqno + 1;
        
        LOG_DBG("Transport is ready to close\n");
        
        sock_set_flag(sk, SOCK_DONE);
        
        /* If there is still an application attached to the
           sock, then wake it up. */
        if (!sock_flag(sk, SOCK_DEAD)) {
                LOG_DBG("Wake user\n");
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

        err = serval_sal_send_ack(sk);
        
        return err;
}

int serval_sal_send_shutdown(struct sock *sk)
{
        struct serval_sock *ssk = serval_sk(sk);

        LOG_DBG("SEND_SHUTDOWN\n");
        
        /* We use this extra flag to not send a FIN
         * twice. Unfortunately, we cannot rely on the socket state as
         * we must wait for transport to send its FIN
         * first. Therefore, we are not necessarily in the state
         * normally expected after having sent a FIN. */
        if (serval_sock_flag(ssk, SSK_FLAG_FIN_SENT))
                return 0;

        /* Not sure we need to set SEND_SHUTDOWN here, since it is
           alread set in serval_sal_close() */
        sk->sk_shutdown |= SEND_SHUTDOWN;
        
        /* SOCK_DEAD would mean there is no user app attached
           anymore */
        if (!sock_flag(sk, SOCK_DEAD))
                /* Wake up lingering close() */
                sk->sk_state_change(sk);

        return serval_sal_send_fin(sk, serval_sk(sk)->snd_seq.nxt++);
}

/* 
   Called by transport protocol when it wants to indicate that it has
   stopped receiving data.
 */
int serval_sal_recv_shutdown(struct sock *sk)
{
        LOG_DBG("RCV_SHUTDOWN\n");

        sk->sk_shutdown |= RCV_SHUTDOWN;

        if (sock_flag(sk, SOCK_DONE))
                return 0;

        sock_set_flag(sk, SOCK_DONE);

        return 0;
}

static int serval_sal_connected_state_process(struct sock *sk,
                                              struct sk_buff *skb,
                                              struct serval_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;
        int should_drop = 0;

        err = serval_sal_ack_process(sk, skb, ctx);
        
        /* Should pass FINs to transport and ultimately the user, as
         * it needs to pick it off its receive queue to notice EOF. */
        if (packet_has_transport_hdr(skb, ctx->hdr) || ctx->hdr->fin) {
                /* Set the received service id.

                   NOTE: The transport protocol is free to overwrite
                   the control block with its own information. TCP
                   does this, for sure.
                 */
                SERVAL_SKB_CB(skb)->srvid = &ssk->peer_srvid;

                err = ssk->af_ops->receive(sk, skb);
        } else {
                LOG_PKT("Dropping packet\n");
                err = 0;
                should_drop = 1;
        }

        if (ctx->hdr->fin) {
                err = serval_sal_rcv_fin(sk, skb, ctx);
                
                if (err == 0) {
                        serval_sal_timewait(sk, SERVAL_CLOSEWAIT);
                }
        }

        if (should_drop)
                kfree_skb(skb);

        return err;
}

static int serval_sal_closewait_state_process(struct sock *sk, 
                                              struct sk_buff *skb,
                                              struct serval_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;

        serval_sal_ack_process(sk, skb, ctx);

        if (packet_has_transport_hdr(skb, ctx->hdr)) {
                /* Set the received service id.

                   NOTE: The transport protocol is free to overwrite
                   the control block with its own information. TCP
                   does this, for sure.
                 */
                SERVAL_SKB_CB(skb)->srvid = &ssk->peer_srvid;

                err = ssk->af_ops->receive(sk, skb);
        } else {
                goto drop;
        }

        return err;
 drop:
        kfree_skb(skb);
        return err;
}

/*
  This function works as the initial receive function for a child
  socket that has just been created by a parent (as a result of
  successful connection handshake).

  The processing resembles that which happened for the parent socket
  when this packet was first received by the parent.

*/
static int serval_sal_child_process(struct sock *parent, 
                                    struct sock *child,
                                    struct sk_buff *skb,
                                    struct serval_context *ctx)
{
        int ret = 0;
        int state = child->sk_state;

        /* child sock is already locked here */

        /* Check lock on child socket, similarly to how we handled the
           parent sock for the incoming skb. */
        if (!sock_owned_by_user(child)) {

                ret = serval_sal_state_process(child, skb, ctx);

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
                                           struct sk_buff *skb,
                                           struct serval_context *ctx)
{
        /* Is this a SYN? */
        if (ctx->hdr->syn && !ctx->hdr->ack) {
                struct request_sock *rsk = serval_sal_find_rsk(sk, ctx);
                
                if (rsk) {
                        LOG_DBG("SYN already received, dropping!\n");
                        serval_sal_send_synack(sk, rsk, skb, ctx);
                        goto drop;
                }
                return serval_sal_rcv_syn(sk, skb, ctx);
        } else if (ctx->hdr->ack) {
                        struct sock *nsk;
                        /* Processing for socket that has received SYN
                           already */

                        LOG_PKT("ACK recv\n");
                        
                        nsk = serval_sal_request_sock_handle(sk, skb, ctx);
                        
                        /* The new sock is already locked here */

                        if (nsk && nsk != sk) {
                                return serval_sal_child_process(sk, nsk,
                                                                skb, ctx);
                        }
                        kfree_skb(skb);
        } else {
                goto drop;
        }

        return 0;

 drop:
        kfree_skb(skb);
        return 0;
}

static int serval_sal_request_state_process(struct sock *sk, 
                                            struct sk_buff *skb,
                                            struct serval_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_hdr *sh = ctx->hdr;
        struct sk_buff *rskb;
        int err = 0;
                
        if (!has_connection_extension(ctx))
                goto drop;
        
        if (!(sh->syn && sh->ack)) {
                LOG_ERR("packet is not a SYN+ACK response\n");
                goto drop;
        }
        /* Process potential ACK */
        if (serval_sal_ack_process(sk, skb, ctx) != 0) {
                LOG_DBG("ACK is invalid\n");
                goto drop;
        }
        
        LOG_DBG("Got RESPONSE seqno=%u ackno=%u TCP off=%u hdrlen=%u\n",
                ctx->seqno, ctx->ackno,
                skb_transport_header(skb) - (unsigned char *)sh,
                sizeof(*sh) + sizeof(*ctx->conn_ext));

        /* Save device and peer flow id */
        serval_sock_set_dev(sk, skb->dev);

        /* Save IP addresses. These are important for checksumming in
           transport protocols */
        if (ctx->src_ext) {
                /* The previous source address is our true destination. */
                memcpy(&inet_sk(sk)->inet_daddr, 
                       SERVAL_SOURCE_EXT_GET_LAST_ADDR(ctx->src_ext), 
                       sizeof(inet_sk(sk)->inet_daddr));
#if defined(ENABLE_DEBUG)
                {
                        char dststr[18];
                        LOG_DBG("Response had source extension, using %s as service IP\n",
                                inet_ntop(AF_INET, &inet_sk(sk)->inet_daddr,
                                          dststr, 18)); 
                }
#endif
        } else {
                memcpy(&inet_sk(sk)->inet_daddr, &ip_hdr(skb)->saddr, 
                       sizeof(inet_sk(sk)->inet_daddr));
        }

        /* This should be our own address of the incoming interface */
        memcpy(&inet_sk(sk)->inet_saddr, &ip_hdr(skb)->daddr, 
               sizeof(inet_sk(sk)->inet_saddr));

        /* Save nonce */
        memcpy(ssk->peer_nonce, ctx->conn_ext->nonce, SERVAL_NONCE_SIZE);
        /* Update socket ids */
        memcpy(&ssk->peer_flowid, &sh->src_flowid, 
               sizeof(sh->src_flowid));
      
        /* Update expected rcv sequence number */
        ssk->rcv_seq.nxt = ctx->seqno + 1;
        
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
        
        /* Let application know we are connected. */
	if (!sock_flag(sk, SOCK_DEAD)) {
                sk->sk_state_change(sk);
                sk_wake_async(sk, SOCK_WAKE_IO, POLL_OUT);
        }

        /* Allocate ACK */
        rskb = sk_sal_alloc_skb(sk, sk->sk_prot->max_header, GFP_ATOMIC);

        if (!rskb) {
                err = -ENOMEM;
                goto error;
        }
        
        /* Ask transport to fill in*/
        if (ssk->af_ops->conn_build_ack) {
                err = ssk->af_ops->conn_build_ack(sk, rskb);

                if (err) {
                        LOG_ERR("Transport drops packet on building ACK\n");
                        goto error;
                }
        }
        
        /* Update control block */
        SERVAL_SKB_CB(rskb)->flags = SVH_ACK | SVH_CONN_ACK;

        /* Do not increase sequence number for pure ACK */
        SERVAL_SKB_CB(rskb)->seqno = ssk->snd_seq.nxt;
        rskb->protocol = IPPROTO_SERVAL;

        /* Xmit, do not queue ACK */
        err = serval_sal_transmit_skb(sk, rskb, 0, GFP_ATOMIC);

drop: 
        kfree_skb(skb);

        return 0;
error:
        return err;
}

static int serval_sal_respond_state_process(struct sock *sk, 
                                            struct sk_buff *skb,
                                            struct serval_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;

        if (!has_valid_connection_extension(sk, ctx))
                goto drop;

        /* Process ACK */
        if (serval_sal_ack_process(sk, skb, ctx) == 0) {
                LOG_DBG("\n");

                /* Save device */
                serval_sock_set_dev(sk, skb->dev);

                memcpy(&inet_sk(sk)->inet_daddr, &ip_hdr(skb)->saddr, 
                       sizeof(inet_sk(sk)->inet_daddr));

                if (ssk->af_ops->respond_state_process) {
                        err = ssk->af_ops->respond_state_process(sk, skb);

                        if (err) {
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
        return 0;
}

static int serval_sal_finwait1_state_process(struct sock *sk, 
                                             struct sk_buff *skb,
                                             struct serval_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;
        int ack_ok = 0;

        if (ctx->hdr->ack && serval_sal_ack_process(sk, skb, ctx) == 0)
                ack_ok = 1;

        if (ctx->hdr->fin) {
                if (serval_sal_rcv_fin(sk, skb, ctx) == 0) {
                        if (ack_ok)
                                serval_sal_timewait(sk, SERVAL_TIMEWAIT);
                        else
                                serval_sal_timewait(sk, SERVAL_CLOSING);
                }
        } else if (ack_ok) {
                serval_sal_timewait(sk, SERVAL_FINWAIT2);
        }
        
        if (packet_has_transport_hdr(skb, ctx->hdr) || 
            ctx->hdr->fin) {
                /* Set the received service id */
                SERVAL_SKB_CB(skb)->srvid = &ssk->peer_srvid;
                
                err = ssk->af_ops->receive(sk, skb);
        } else {
                err = 0;
                goto drop;
        }

        return err;
 drop:
        kfree_skb(skb);
        return err;
}

static int serval_sal_finwait2_state_process(struct sock *sk, 
                                             struct sk_buff *skb,
                                             struct serval_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;
        
        /* We've received our FIN-ACK already */
        if (ctx->hdr->fin) {
                err = serval_sal_rcv_fin(sk, skb, ctx);

                if (err == 0) {
                        serval_sal_timewait(sk, SERVAL_TIMEWAIT);
                }
        }

        if (packet_has_transport_hdr(skb, ctx->hdr) ||
            ctx->hdr->fin) {
                /* Set the received service id */
                SERVAL_SKB_CB(skb)->srvid = &ssk->peer_srvid;
                
                err = ssk->af_ops->receive(sk, skb);
        } else {
                err = 0;
                goto drop;
        }

        return err;
 drop:
        kfree_skb(skb);
        return err;
}

static int serval_sal_closing_state_process(struct sock *sk, 
                                            struct sk_buff *skb,
                                            struct serval_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;
                
        if (ctx->hdr->ack && serval_sal_ack_process(sk, skb, ctx) == 0) {
                /* ACK was valid */
                serval_sal_timewait(sk, SERVAL_TIMEWAIT);
        }

        if (packet_has_transport_hdr(skb, ctx->hdr)) {
                /* Set the received service id */
                SERVAL_SKB_CB(skb)->srvid = &ssk->peer_srvid;
                
                err = ssk->af_ops->receive(sk, skb);
        } else {
                goto drop;
        }

        return err;
 drop:
        kfree_skb(skb);
        return err;
}

static int serval_sal_lastack_state_process(struct sock *sk, 
                                            struct sk_buff *skb,
                                            struct serval_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0, ack_ok;
        
        ack_ok = serval_sal_ack_process(sk, skb, ctx) == 0;
                
        if (packet_has_transport_hdr(skb, ctx->hdr)) {
                /* Set the received service id */
                SERVAL_SKB_CB(skb)->srvid = &ssk->peer_srvid;
                
                err = ssk->af_ops->receive(sk, skb);
        } else {
                err = 0;
                goto drop;
        }

        if (ack_ok) {
                /* ACK was valid */
                LOG_DBG("Valid ACK, closing socket\n");
                serval_sal_done(sk);
        }

        return err;
 drop:
        kfree_skb(skb);
        return err;
}

/*
  Receive for datagram sockets that are not connected.
*/
static int serval_sal_init_state_process(struct sock *sk, 
                                         struct sk_buff *skb,
                                         struct serval_context *ctx)
{
        struct serval_sock *ssk = serval_sk(sk);
        int err = 0;

        if (ssk->hash_key && ctx->srv_ext) {
                LOG_DBG("Receiving unconnected datagram for service %s\n", 
                        service_id_to_str((struct service_id*) ssk->hash_key));
        } else {
                LOG_DBG("Non-matching datagram\n");
                return -1;
        }

        if (packet_has_transport_hdr(skb, ctx->hdr)) {
                /* Set source serviceID */
                SERVAL_SKB_CB(skb)->srvid = &ctx->srv_ext->src_srvid; 
                err = ssk->af_ops->receive(sk, skb);
        } else {
                kfree_skb(skb);
                err = 0;
        }

        return err;
}

int serval_sal_state_process(struct sock *sk, 
                             struct sk_buff *skb,
                             struct serval_context *ctx)
{
        int err = 0;

        LOG_PKT("receive in state %s\n", serval_sock_state_str(sk));

#if defined(ENABLE_DEBUG)
        {
                char buf[512];
                LOG_DBG("SAL PROCESS START %s\n",
                        serval_sock_print_state(sk, buf, 512));
        }
#endif

        if (has_seqno(ctx) && !has_valid_seqno(ctx->seqno, sk))
                goto drop;
        
        /* Check for migration */
        if (ctx->hdr->rsyn) {
                if (ctx->hdr->ack)
                        err = serval_sal_rcv_rsynack(sk, skb, ctx);
                else
                        err = serval_sal_rcv_rsyn(sk, skb, ctx);
        }

        switch (sk->sk_state) {
        case SERVAL_INIT:
                if (sk->sk_type == SOCK_DGRAM) 
                        err = serval_sal_init_state_process(sk, skb, ctx);
                else
                        goto drop;
                break;
        case SERVAL_CONNECTED:
                err = serval_sal_connected_state_process(sk, skb, ctx);
                break;
        case SERVAL_REQUEST:
                err = serval_sal_request_state_process(sk, skb, ctx);
                break;
        case SERVAL_RESPOND:
                err = serval_sal_respond_state_process(sk, skb, ctx);
                break;
        case SERVAL_LISTEN:
                err = serval_sal_listen_state_process(sk, skb, ctx);
                break;
        case SERVAL_FINWAIT1:
                err = serval_sal_finwait1_state_process(sk, skb, ctx);
                break;
        case SERVAL_FINWAIT2:
                err = serval_sal_finwait2_state_process(sk, skb, ctx);
                break;
        case SERVAL_CLOSING:
                err = serval_sal_closing_state_process(sk, skb, ctx);
                break;
        case SERVAL_LASTACK:
                err = serval_sal_lastack_state_process(sk, skb, ctx);
                break;
        case SERVAL_TIMEWAIT:
                /* Resend ACK of FIN in case our previous one got lost */
                if (ctx->hdr->fin)
                        serval_sal_send_ack(sk);
                goto drop;
        case SERVAL_CLOSEWAIT:
                err = serval_sal_closewait_state_process(sk, skb, ctx);
                break;
        case SERVAL_CLOSED:
                goto drop;
        default:
                LOG_ERR("bad socket state %s %u\n", 
                        serval_sock_state_str(sk), sk->sk_state);
                goto drop;
        }

#if defined(ENABLE_DEBUG)
        {
                char buf[512];
                LOG_DBG("SAL PROCESS END %s\n",
                        serval_sock_print_state(sk, buf, 512));
        }
#endif
                
        if (err) {
                LOG_ERR("Error on receive: %d\n", err);
        }

        return 0;
drop:

#if defined(ENABLE_DEBUG)
        {
                char buf[512];
                LOG_DBG("SAL PROCESS END %s\n",
                        serval_sock_print_state(sk, buf, 512));
        }
#endif

        kfree_skb(skb);

        return 0;
}

int serval_sal_do_rcv(struct sock *sk, struct sk_buff *skb)
{
        struct serval_context ctx;

        if (serval_sal_parse_hdr(skb, &ctx, SERVAL_PARSE_ALL)) {
                LOG_ERR("Could not parse Serval header\n");
                kfree_skb(skb);
                return -1;
        }

        pskb_pull(skb, ctx.length);
        skb_reset_transport_header(skb);

        SERVAL_SKB_CB(skb)->flags = ctx.flags;
        SERVAL_SKB_CB(skb)->srvid = NULL;
                
        return serval_sal_state_process(sk, skb, &ctx);
}

void serval_sal_error_rcv(struct sk_buff *skb, u32 info)
{
        LOG_WARN("ICMP error handling not implemented!\n");
        
        /* TODO: deal with ICMP errors, e.g., wake user and report. */
}

/* Resolution return values. */
enum {
        SAL_RESOLVE_ERROR = -1,
        SAL_RESOLVE_NO_MATCH,
        SAL_RESOLVE_DEMUX,
        SAL_RESOLVE_FORWARD,
        SAL_RESOLVE_DELAY,
        SAL_RESOLVE_DROP,
};

static int serval_sal_update_transport_csum(struct sk_buff *skb,
                                            int protocol)
{
        struct iphdr *iph = ip_hdr(skb);

        skb->ip_summed = CHECKSUM_NONE;
        
        switch (protocol) {
        case SERVAL_PROTO_TCP:
                tcp_hdr(skb)->check = 0;
                skb->csum = csum_partial(tcp_hdr(skb),
                                         skb->len, 0);
                tcp_hdr(skb)->check = 
                        csum_tcpudp_magic(iph->saddr, 
                                          iph->daddr, 
                                          skb->len, 
                                          IPPROTO_TCP, 
                                          skb->csum);
                break;
        case SERVAL_PROTO_UDP:
                udp_hdr(skb)->check = 0;
                skb->csum = csum_partial(udp_hdr(skb),
                                         skb->len, 0);
                udp_hdr(skb)->check = 
                        csum_tcpudp_magic(iph->saddr, 
                                          iph->daddr, 
                                          skb->len, 
                                          IPPROTO_UDP, 
                                          skb->csum);
                break;
        default:
                LOG_INF("Unknown transport protocol %u, "
                        "forgoing checksum calculation\n",
                        protocol);
                break;
        }
        
        return 0;
}

#if defined(OS_LINUX_KERNEL)
static int serval_sal_update_encap_csum(struct sk_buff *skb)
{
        struct udphdr *uh;
        
        uh = udp_hdr(skb);
        uh->check = 0;
        uh->check = csum_tcpudp_magic(ip_hdr(skb)->saddr,
                                      ip_hdr(skb)->daddr, 
                                      skb->len,
                                      IPPROTO_UDP,
                                      csum_partial(uh, skb->len, 0));
        return 0;
}
#endif /* OS_LINUX_KERNEL */

static int serval_sal_resolve_service(struct sk_buff *skb, 
                                      struct serval_context *ctx,
                                      struct service_id *srvid,
                                      struct sock **sk)
{
        struct service_entry* se = NULL;
        struct service_iter iter;
        struct target *target = NULL;
        unsigned int hdr_len = ctx->length;
        unsigned int num_forward = 0;
        unsigned int data_len = skb->len - hdr_len;
        int err = SAL_RESOLVE_NO_MATCH;

        *sk = NULL;

        LOG_DBG("Resolve or demux inbound packet on serviceID %s\n", 
                service_id_to_str(srvid));

        /* Match on the highest priority srvid rule, even if it's not
         * the sock TODO - use flags/prefix in resolution This should
         * probably be in a separate function call
         * serval_sal_transit_rcv or resolve something
         */
        se = service_find(srvid, SERVICE_ID_MAX_PREFIX_BITS);

        if (!se) {
                LOG_INF("No matching service entry for serviceID %s\n",
                        service_id_to_str(srvid));
                return SAL_RESOLVE_NO_MATCH;
        }
        
	if (service_iter_init(&iter, se, SERVICE_ITER_ANYCAST) < 0)
                return SAL_RESOLVE_ERROR;
        
        /*
          Send to all targets listed for this service.
        */
        target = service_iter_next(&iter);

        if (!target) {
                LOG_INF("No target to forward on!\n");
                service_iter_inc_stats(&iter, -1, data_len);
                service_iter_destroy(&iter);
                service_entry_put(se);
                return SAL_RESOLVE_NO_MATCH;
        }

        service_iter_inc_stats(&iter, 1, data_len);
                
        while (target) {
                struct target *next_target;
                struct sk_buff *cskb = NULL;
                struct iphdr *iph;
                unsigned int iph_len;
                unsigned int protocol = serval_hdr(skb)->protocol;
                int ret = 0;
                
                next_target = service_iter_next(&iter);
                
                /* It is kind of unclear how to handle DEMUX vs
                   FORWARD rules here. Does it make sense to have both
                   a socket and forward rule for one single serviceID?
                   It seems that if we have a socket, we shouldn't
                   forward at all. But what if the socket is not first
                   in the iteration? I guess for now we just forward
                   until we hit a socket, and then break (i.e., DEMUX
                   to socket but stop forwarding). */
                if (is_sock_target(target)) {
                        /* local resolution */
                        *sk = target->out.sk;
                        sock_hold(*sk);
                        err = SAL_RESOLVE_DEMUX;
                        break;
                } 

                err = SAL_RESOLVE_FORWARD;

                if (skb->pkt_type != PACKET_HOST &&
                    skb->pkt_type != PACKET_OTHERHOST) {
                        /* Do not forward, e.g., broadcast
                           packets as they may cause
                           resolution loops. */
                        LOG_DBG("Broadcast packet. Not forwarding\n");
                        err = SAL_RESOLVE_DROP;
                        break;
                }
                
                if (next_target == NULL) {
                        cskb = skb;
                } else {
                        cskb = skb_copy(skb, GFP_ATOMIC);
                        
                        if (!cskb) {
                                LOG_ERR("Skb allocation failed\n");
                                err = SAL_RESOLVE_DROP;
                                break;
                        }
                }
                
                iph = ip_hdr(cskb);
                iph_len = iph->ihl << 2;
#if defined(OS_USER)
                /* Set the output device - ip_forward uses the
                 * out device specified in the dst_entry route
                 * and assumes that skb->dev is the input
                 * interface*/
                if (target->out.dev)
                        cskb->dev = target->out.dev;
#endif /* OS_LINUX_KERNEL */
                
                /* Set the true overlay source address if the
                 * packet may be ingress-filtered user-level
                 * raw socket forwarding may drop the packet
                 * if the source address is invalid */
                ret = serval_sal_add_source_ext(&cskb, ctx);
                
                if (ret < 0) {
                        LOG_ERR("Failed to add source extension, err=%d\n", 
                                ret);
                        
                        /* Need to free the skb if it's a copy */
                        if (cskb != skb) {
                                LOG_ERR("Freeing skb copy\n");
                                kfree_skb(cskb);
                        }
                        /* Try next target */
                } else {
                        iph = ip_hdr(cskb);
                        hdr_len += ret;
                        
                        LOG_DBG("new serval header len=%u\n", hdr_len);
                        
                        /* Update destination address */
                        memcpy(&iph->daddr, target->dst, sizeof(iph->daddr));
                        
                        /* Must recalculate transport checksum. Pull
                           to reveal transport header */
                        pskb_pull(cskb, hdr_len);
                        skb_reset_transport_header(cskb);
                        
                        serval_sal_update_transport_csum(cskb,
                                                         protocol);
                        
                        /* Push back to Serval header */
                        skb_push(cskb, hdr_len);
                        skb_reset_transport_header(cskb);
                        
                        /* Recalculate SAL checksum */
                        serval_sal_send_check(serval_hdr(cskb));
                        
#if defined(OS_LINUX_KERNEL)
                        /* Packet is UDP encapsulated, push back UDP
                         * encapsulation header */
                        if (ip_hdr(cskb)->protocol == IPPROTO_UDP) {
                                skb_push(cskb, sizeof(struct udphdr));
                                skb_reset_transport_header(cskb);
                                udp_hdr(cskb)->len = htons(cskb->len);
                                LOG_DBG("Pushed back UDP encapsulation [%u:%u]\n",
                                        ntohs(udp_hdr(skb)->source),
                                        ntohs(udp_hdr(skb)->dest));
                                serval_sal_update_encap_csum(cskb);
                        }
#endif
                        /* Push back to IP header */
                        skb_push(cskb, iph_len);
                                                
                        ret = serval_ipv4_forward_out(cskb);
                        
                        if (ret) {
                                /* serval_ipv4_forward_out has taken
                                   custody of packet, no need to
                                   free. */
                                LOG_ERR("Forwarding failed err=%d\n", ret);
                        } else 
                                num_forward++;
                }
                target = next_target;
        }
        
        if (num_forward == 0)
                service_iter_inc_stats(&iter, -1, -data_len);
        
        service_iter_destroy(&iter);
        service_entry_put(se);

        return err;
}

static struct sock *serval_sal_demux_service(struct sk_buff *skb, 
                                             struct service_id *srvid,
                                             int protocol)
{
        struct sock *sk;

        LOG_DBG("Demux on serviceID %s\n", service_id_to_str(srvid));

        /* only allow listening socket demux */
        sk = serval_sock_lookup_service(srvid, protocol);
        
        if (!sk) {
                LOG_INF("No matching sock for serviceID %s\n",
                        service_id_to_str(srvid));
        } else {
                LOG_DBG("Socket is %p\n", sk);
        }
        
        return sk;
}

static struct sock *serval_sal_demux_flow(struct sk_buff *skb, 
                                          struct serval_context *ctx)
{
        struct sock *sk = NULL;
        
        /* If SYN and not ACK is set, we know for sure that we must
         * demux on service id instead of socket id */
        if (!(ctx->hdr->syn && !ctx->hdr->ack)) {
                /* Ok, check if we can demux on socket id */
                sk = serval_sock_lookup_flow(&ctx->hdr->dst_flowid);
                
                if (!sk) {
                        LOG_INF("No matching sock for flowid %s\n",
                                flow_id_to_str(&ctx->hdr->dst_flowid));
                }
        } else {
                LOG_DBG("cannot demux on flowid\n");
        }

        return sk;
}

static int serval_sal_resolve(struct sk_buff *skb, 
                              struct serval_context *ctx,
                              struct sock **sk)
{
        int ret = SAL_RESOLVE_ERROR;
        struct service_id *srvid = NULL;
        
        if (ctx->length <= sizeof(struct serval_hdr))
                return ret;
        
        if (ctx->conn_ext)
                srvid = &ctx->conn_ext->srvid;
        else if (ctx->srv_ext)
                srvid = &ctx->srv_ext->dst_srvid;
        else 
                return SAL_RESOLVE_ERROR;

        if (net_serval.sysctl_sal_forward) {
                ret = serval_sal_resolve_service(skb, ctx, srvid, sk);
        } else {
                *sk = serval_sal_demux_service(skb, srvid, ctx->hdr->protocol);
                
                if (!(*sk))
                        ret = SAL_RESOLVE_NO_MATCH;
                else 
                        ret = SAL_RESOLVE_DEMUX;
        }
        
        return ret;
}

int serval_sal_rcv(struct sk_buff *skb)
{
        struct sock *sk = NULL;
        struct serval_context ctx;
        int err = 0;
        
        if (skb->len < sizeof(struct serval_hdr)) {
                LOG_DBG("skb length too short (%u bytes)\n", 
                        skb->len);
                goto drop;
        }

        if (serval_sal_parse_hdr(skb, &ctx, SERVAL_PARSE_ALL)) {
                LOG_DBG("Bad Serval header %s\n",
                        ctx.hdr ? serval_hdr_to_str(ctx.hdr) : "NULL");
                goto drop;
        }
        
        if (!pskb_may_pull(skb, ctx.length)) {
                LOG_DBG("Cannot pull header (hdr_len=%u)\n",
                        ctx.length);
                goto drop;
        }
        
        if (unlikely(serval_sal_csum(ctx.hdr, ctx.length))) {
                LOG_DBG("SAL checksum error!\n");
                goto drop;
        }

#if defined(ENABLE_DEBUG)
        {
                struct iphdr *iph = ip_hdr(skb);
                char src[18], dst[18];

                LOG_PKT("SAL RECEIVE %s skb->len=%u : %s -> %s\n",
                        serval_hdr_to_str(ctx.hdr), skb->len, 
                        inet_ntop(AF_INET, &iph->saddr, src, 18),
                        inet_ntop(AF_INET, &iph->daddr, dst, 18));
        }
#endif
        /*
          FIXME: We should try to do early transport layer header
          checks here so that we can drop bad packets before we put
          them on, e.g., the backlog queue
        */
        
        /* Try flowID demux first */
        sk = serval_sal_demux_flow(skb, &ctx);
        
        if (!sk) {
                /* Resolve on serviceID */
                err = serval_sal_resolve(skb, &ctx, &sk);
                
                switch (err) {
                case SAL_RESOLVE_DEMUX:
                        break;
                case SAL_RESOLVE_FORWARD:                        
                        return 0;
                case SAL_RESOLVE_NO_MATCH:
                        /* TODO: fix error codes for this function */
                        err = -EHOSTUNREACH;
                case SAL_RESOLVE_DROP:
                case SAL_RESOLVE_DELAY:
                case SAL_RESOLVE_ERROR:
                default:
                        if (sk)
                                sock_put(sk);
                        goto drop;
                }
        }
        
        bh_lock_sock_nested(sk);

        /* We only reach this point if a valid local socket destination
         * has been found */
        /* Drop check if control queue is full here - this should
         * increment the per-service drop stats as well*/
        if (!is_pure_data(&ctx) &&
            serval_sal_ctrl_queue_len(sk) >= MAX_CTRL_QUEUE_LEN) {
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

        bh_unlock_sock(sk);
        sock_put(sk);

        /*
          IP will resubmit packet if return value is less than
          zero. Therefore, make sure we always return 0, even if we drop the
          packet.
        */

	return 0;
drop:
        service_inc_stats(-1, -(skb->len - ctx.length));
drop_no_stats:
        LOG_DBG("Dropping packet\n");
        kfree_skb(skb);
        return 0;
}

static int serval_sal_rexmit(struct sock *sk)
{        
        struct sk_buff *skb;
        int err = 0;

        skb = serval_sal_ctrl_queue_head(sk);
        
        if (!skb) {
                LOG_ERR("No packet to retransmit!\n");
                return -1;
        }

        SERVAL_SKB_CB(skb)->flags |= SVH_RETRANS;

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

        LOG_DBG("Transmit timeout sock=%p rto=%u (ms) backoff=%u\n", 
                sk, jiffies_to_msecs(ssk->rto), ssk->backoff);
        
        if (ssk->retransmits == 10) {
                /* TODO: check error values here */
                LOG_DBG("NOT rescheduling timer! Closing socket\n");
                sk->sk_err = ETIMEDOUT;
                serval_sal_done(sk);
        } else {
                LOG_DBG("ReXmit and rescheduling timer\n");
                serval_sal_rexmit(sk);

                ssk->backoff++;
                ssk->retransmits++;
                
                serval_sock_reset_xmit_timer(sk, min(ssk->rto << ssk->backoff, 
                                                     SAL_RTO_MAX),
                                             SAL_RTO_MAX);
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

static int serval_sal_do_xmit(struct sk_buff *skb)
{
        struct sock *sk = skb->sk;
        struct serval_sock *ssk = serval_sk(sk);
      	uint32_t temp_daddr = 0;
        u8 skb_flags = SERVAL_SKB_CB(skb)->flags;
        struct net_device *mig_dev = NULL; 
        int err = 0;

        if (skb_flags & SVH_RSYN) {
                mig_dev = dev_get_by_index(sock_net(sk), 
                                           ssk->mig_dev_if);

                if (mig_dev) {
                        dev_get_ipv4_addr(mig_dev,
                                          IFADDR_LOCAL,
                                          &inet_sk(sk)->inet_saddr);
#if defined(ENABLE_DEBUG)
                        {
                                char src[18];
                                LOG_DBG("Sending on mig_dev %s src=%s\n",
                                        mig_dev->name, 
                                        inet_ntop(AF_INET, 
                                                  &inet_sk(sk)->inet_saddr, 
                                                  src, 18));
                        }
#endif
                        skb->dev = mig_dev;
                }
                
                if (ssk->sal_state == SAL_RSYN_RECV) {
#if defined(ENABLE_DEBUG)
                        char dst[18];
                        LOG_DBG("Sending to MIG dest addr %s\n",
                                inet_ntop(AF_INET, 
                                              &ssk->mig_daddr, 
                                          dst, 18));
#endif
                        memcpy(&temp_daddr, &inet_sk(sk)->inet_daddr, 4);
        	            memcpy(&inet_sk(sk)->inet_daddr, 
                                   &ssk->mig_daddr, 4);
                }
                
                /* Must remove any cached route */
                sk_dst_reset(sk);
        }

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
        err = ssk->af_ops->queue_xmit(skb);
        
        if (skb_flags & SVH_RSYN) {
                /* Restore inet_sk(sk)->daddr */
                if (mig_dev) {
                        struct net_device *dev = 
                                dev_get_by_index(sock_net(sk), 
                                                 sk->sk_bound_dev_if);
                                
                        if (dev) {
                                dev_get_ipv4_addr(dev,
                                                  IFADDR_LOCAL,
                                                  &inet_sk(sk)->inet_saddr);
                                dev_put(dev);
                        }
                }
                
                if (ssk->sal_state == SAL_RSYN_RECV) {
                        memcpy(&inet_sk(sk)->inet_daddr, &temp_daddr, 4);
                }
                /* Reset cached route again */
                sk_dst_reset(sk);
        }

        if (err < 0) {
                LOG_ERR("xmit failed err=%d\n", err);
        }

        if (mig_dev)
                dev_put(mig_dev);

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

static inline int serval_sal_add_migrate_ext(struct sock *sk,
                                             struct sk_buff *skb,
                                             int flags)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct serval_migrate_ext *mig_ext;

        LOG_DBG("Adding migrate ext\n");
        mig_ext = (struct serval_migrate_ext *)
                  skb_push(skb, sizeof(*mig_ext));
        mig_ext->exthdr.type = SERVAL_MIGRATE_EXT;
        mig_ext->exthdr.length = sizeof(*mig_ext);
        mig_ext->exthdr.flags = flags;
        mig_ext->seqno = htonl(SERVAL_SKB_CB(skb)->seqno);
        mig_ext->ackno = htonl(ssk->rcv_seq.nxt);
        memcpy(mig_ext->nonce, ssk->local_nonce, SERVAL_NONCE_SIZE);

        return sizeof(*mig_ext);
}

int serval_sal_transmit_skb(struct sock *sk, struct sk_buff *skb, 
                            int use_copy, gfp_t gfp_mask)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct inet_sock *inet = inet_sk(sk);
	struct service_entry *se;
	struct target *target;
        struct serval_hdr *sh;
        int hdr_len = sizeof(*sh);
	int err = -1;
        struct service_iter iter;
        struct sk_buff *cskb = NULL;
        int dlen = skb->len - 8; /* KLUDGE?! TODO not sure where the
                                    extra 8 bytes are coming from at
                                    this point */
    
	if (likely(use_copy)) {
                /* pskb_copy will make a copy of header and
                   non-fragmented data. Making a copy is necessary
                   since we are changing the TCP header checksum for
                   every copy we send (retransmission or copies for
                   packets matching multiple rules). */
                skb = pskb_copy(skb, gfp_mask);

		if (unlikely(!skb)) {
                        /* Shouldn't free the passed skb here, since
                         * we were asked to use a copy. That probably
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
        if (SERVAL_SKB_CB(skb)->flags & SVH_SYN || 
            SERVAL_SKB_CB(skb)->flags & SVH_CONN_ACK)
                hdr_len += serval_sal_add_conn_ext(sk, skb, 0);
        else if (SERVAL_SKB_CB(skb)->flags & SVH_RSYN)
                hdr_len += serval_sal_add_migrate_ext(sk, skb, 0);
        else if (SERVAL_SKB_CB(skb)->flags & SVH_FIN ||
                 SERVAL_SKB_CB(skb)->flags & SVH_RST ||
                 SERVAL_SKB_CB(skb)->flags & SVH_ACK)
                hdr_len += serval_sal_add_ctrl_ext(sk, skb, 0);
        else {
                /* Unconnected datagram, add service extension */
                if (sk->sk_state == SERVAL_INIT && 
                    sk->sk_type == SOCK_DGRAM) {
                        hdr_len += serval_sal_add_service_ext(sk, skb, 0);
                }
        }

        /* Add Serval header */
        sh = (struct serval_hdr *)skb_push(skb, sizeof(*sh));
        sh->syn = SERVAL_SKB_CB(skb)->flags & SVH_SYN ? 1 : 0;
        sh->ack = SERVAL_SKB_CB(skb)->flags & SVH_ACK ? 1 : 0;
        sh->fin = SERVAL_SKB_CB(skb)->flags & SVH_FIN ? 1 : 0;
        sh->rst = SERVAL_SKB_CB(skb)->flags & SVH_RST ? 1 : 0;
        sh->rsyn = SERVAL_SKB_CB(skb)->flags & SVH_RSYN ? 1 : 0;
        sh->protocol = sk->sk_protocol;
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
                                   SERVALF_CLOSEWAIT)) {
                serval_sal_send_check(sh);

                return serval_sal_do_xmit(skb);
        }
        
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
                serval_sal_send_check(sh);
                
                /* note that the service resolution stats
                 * (packets/bytes) will not be incremented here In the
                 * future, the stats should be defined as SNMP
                 * counters in include/net/snmp.h and incremented with
                 * the appropriate per-cpu atomic inc macros TODO
                 */
                return serval_sal_do_xmit(skb);
        }

        LOG_DBG("Resolving service %s\n",
                service_id_to_str(&ssk->peer_srvid));

        se = service_find(&ssk->peer_srvid, 
                          sizeof(struct service_id) * 8);

	if (!se) {
		LOG_DBG("service lookup failed for [%s]\n",
                        service_id_to_str(&ssk->peer_srvid));
                service_inc_stats(-1, -dlen);
                kfree_skb(skb);
		return -EADDRNOTAVAIL;
	}

	if (service_iter_init(&iter, se, SERVICE_ITER_ANYCAST) < 0)
                return -1;

        /*
          Send to all destinations resolved for this service.
        */
	target = service_iter_next(&iter);
	
        if (!target) {
                LOG_DBG("No device to transmit on!\n");
                service_iter_inc_stats(&iter, -1, -dlen);
                kfree_skb(skb);
                service_iter_destroy(&iter);
                service_entry_put(se);
                return -EHOSTUNREACH;
        }

	while (target) {
		struct target *next_target;
                struct net_device *dev = NULL;
                int local_err = 0;

                if (cskb == NULL) {
                        service_iter_inc_stats(&iter, 1, dlen);
                }
                
                next_target = service_iter_next(&iter);
		
                if (next_target == NULL) {
			cskb = skb;
		} else {
                        /* Always be atomic here since we are holding
                         * socket lock */
                        cskb = pskb_copy(skb, GFP_ATOMIC);
                        
			if (!cskb) {
				LOG_ERR("Allocation failed\n");
                                kfree_skb(skb);
                                err = -ENOBUFS;
				break;
			}
                        /* skb copy will have no socket set. */
                        skb_serval_set_owner_w(cskb, sk);
		}
                
                /* Remember the flow destination */
		if (is_sock_target(target)) {
                        /* use a localhost address and bounce it off
                         * the IP layer*/
                        memcpy(&inet->inet_daddr,
                               &local_addr, sizeof(inet->inet_daddr));

                        /* kludgey but sets the output device for
                         * reaching a local socket destination to the
                         * default device TODO - make sure this is
                         * appropriate for kernel operation as well
                         */
                        dev = __dev_get_by_name(sock_net(sk), "lo");
		} else {
                        memcpy(&inet->inet_daddr,
                               target->dst,
                               sizeof(inet->inet_daddr) < target->dstlen ? 
                               sizeof(inet->inet_daddr) : target->dstlen);
                       
                        dev = target->out.dev;
                }
                
                cskb->dev = dev;

                /* Need also to set the source address for
                   checksum calculation */
                if (!dev_get_ipv4_addr(dev, IFADDR_LOCAL,
                                       &inet->inet_saddr)) {
                        LOG_ERR("No source IPv4 address for interface %s\n",
                                dev->name);
                        target = next_target;
                        continue;
                }

#if defined(ENABLE_DEBUG)
                {
                        char src[18], dst[18];
                        LOG_DBG("Resolved service %s with IP %s->%s " 
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
                        sk_dst_reset(sk);
                
                /*
                  We have to calculate the checksum for resolution
                  packets at this point as it is not until here that
                  we know the destination IP to put in the
                  packet. Normally, the checksum is calculated by the
                  transport protocol before being passed to SAL.
                */
                if (ssk->af_ops->send_check &&
                    packet_has_transport_hdr(cskb, sh)) {
                        LOG_DBG("Calculating transport checksum\n");
                        ssk->af_ops->send_check(sk, cskb);
                }

                /* Compute SAL header checksum */
                serval_sal_send_check((struct serval_hdr *)cskb->data);

                /* Cannot reset transport header until after checksum
                   calculation since send_check requires access to
                   transport header */
                skb_reset_transport_header(cskb);

		local_err = ssk->af_ops->queue_xmit(cskb);

		if (local_err < 0) {
			LOG_ERR("xmit failed on queue_xmit err=%d\n", 
                                local_err);
                        /* Only set error in case we haven't succeeded
                           in transmitting any packet. See comment
                           below. */
                        if (err != 0)
                                err = local_err;
		} else {
                        /* Since we may send a SYN on multiple
                           interfaces, we only want to return an error
                           message in case transmission failed on all
                           interfaces. Once we succeed on any
                           interface, we set return value to
                           success. */
                        err = 0;
                }
                
		target = next_target;
	}
        
        /* Reset dst cache since we don't want to potantially cache a
           broadcast destination */
        if (__sk_dst_get(sk))
                sk_dst_reset(sk);

        /* Zero the address again so that we do not confuse the
           resolution in case of retransmission. */
        memset(&inet_sk(sk)->inet_daddr, 0, 
               sizeof(inet_sk(sk)->inet_daddr));
                   
        service_iter_destroy(&iter);
	service_entry_put(se);

	return err;
}

/* This function is typically called by transport to send data */
int serval_sal_xmit_skb(struct sk_buff *skb) 
{
        return serval_sal_transmit_skb(skb->sk, skb, 0, GFP_ATOMIC);
}
