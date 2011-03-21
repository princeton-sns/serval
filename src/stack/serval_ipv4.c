/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/platform.h>
#include <serval/skbuff.h>
#include <serval/debug.h>
#include <serval/netdevice.h>
#include <serval_sock.h>
#include <serval_ipv4.h>
#include <serval_srv.h>
#include <input.h>
#include <output.h>
#include <neighbor.h>
#if defined(OS_LINUX_KERNEL)
#include <linux/if_ether.h>
#include <linux/inetdevice.h>
#include <linux/netfilter_ipv4.h>
#include <net/route.h>
#include <net/ip.h>
#elif !defined(OS_ANDROID)
#include <netinet/if_ether.h>
#endif

extern int serval_srv_rcv(struct sk_buff *);

#if defined(OS_USER)
static inline void ip_send_check(struct iphdr *iph)
{
        iph->check = 0;
        /* iph->check = in_cksum(iph, iph->ihl << 2); */
}

int serval_ipv4_rcv(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	unsigned int hdr_len = iph->ihl << 2;
	int ret = 0;

	switch (iph->protocol) {
        case IPPROTO_SERVAL:
                break;
	case IPPROTO_ICMP:
		LOG_DBG("icmp packet\n");
	case IPPROTO_UDP:
	case IPPROTO_TCP:
        default:
                ret = INPUT_DELIVER;
                goto out;
	}

#if defined(ENABLE_DEBUG)
        {
                char srcstr[18], dststr[18];
                LOG_DBG("%s %s->%s hdr_len=%u tot_len=%u prot=%u\n",
                        skb->dev->name,
                        inet_ntop(AF_INET, &iph->saddr, srcstr, 18),
                        inet_ntop(AF_INET, &iph->daddr, dststr, 18),
                        hdr_len, ntohs(iph->tot_len), iph->protocol);
        }
#endif
        if (!pskb_may_pull(skb, hdr_len)) {
                LOG_ERR("pskb_may_pull failed! skb->len=%u hdr_len=%u\n",
                        skb->len, hdr_len);
                goto inhdr_error;
        }
        
        pskb_pull(skb, hdr_len);                
        skb_reset_transport_header(skb);
        
        ret = serval_srv_rcv(skb);
out:
	return ret;
inhdr_error:
        LOG_ERR("header error\n");
        FREE_SKB(skb);

        return ret;
}

#endif

static inline int serval_ip_local_out(struct sk_buff *skb)
{
        int err;
        
#if defined(OS_LINUX_KERNEL)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
	err = ip_local_out(skb);
#else
        struct iphdr *iph = ip_hdr(skb);
        
        iph->tot_len = htons(skb->len);
	ip_send_check(iph);

        err = NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, skb->dst->dev,
                      dst_output);
#endif
#else
        /* Calculate checksum */
        ip_send_check(ip_hdr(skb));

        err = dev_queue_xmit(skb);

        if (err < 0) {
		LOG_ERR("packet_xmit failed\n");
	}
        
        //err = serval_output(skb);
#endif
        return err;
}

#if defined(OS_LINUX_KERNEL)

/* A wrapper around ip_route_output_flow to handle differences between
 * various kernel versions. */
static inline
int serval_ip_route_output_flow(struct net *net, struct rtable **rp, 
                                struct flowi *flp, struct sock *sk, int flags)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
        return ip_route_output_flow(net, rp, flp, sk, flags);
#else
        return ip_route_output_flow(rp, flp, sk, flags);
#endif       
}

/*
  This will route a SYN-ACK, i.e., the response to a request to open a
  new connection.
 */
struct dst_entry *serval_ipv4_req_route(struct sock *sk,
                                        struct serval_request_sock *rsk,
                                        int protocol,
                                        uint32_t saddr,
                                        uint32_t daddr)
{
	struct rtable *rt;
	struct ip_options *opt = NULL; /* inet_rsk(req)->opt; */
	struct flowi fl = { .oif = sk->sk_bound_dev_if,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
			    .mark = sk->sk_mark,
#endif
			    .nl_u = { .ip4_u =
				      { .daddr = daddr,
					.saddr = saddr,
					.tos = RT_CONN_FLAGS(sk) } },
			    .proto = protocol,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28))
			    .flags = inet_sk_flowi_flags(sk),
#endif
			    .uli_u = { .ports =
				       { .sport = 0,
					 .dport = 0 } } };
        /*
          FIXME:

          We should probably make serval_request_sock inherit from
          inet_request_sock so that we can pass it to the security
          routine here.
          
         */
	/* security_req_classify_flow(req, &fl); */

	if (serval_ip_route_output_flow(sock_net(sk), &rt, &fl, sk, 0))
		goto no_route;
	if (opt && opt->is_strictroute && rt->rt_dst != rt->rt_gateway)
		goto route_err;
	return &rt->u.dst;

route_err:
	ip_rt_put(rt);
no_route:
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
	IP_INC_STATS_BH(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
#else
	IP_INC_STATS(IPSTATS_MIB_OUTNOROUTES);
#endif
	return NULL;
}

#endif

const char *ipv4_hdr_dump(const void *hdr, char *buf, int buflen)
{
        int i = 0, len = 0;
        const unsigned char *h = (const unsigned char *)hdr;

        while (i < 20) {
                len += snprintf(buf + len, buflen - len, 
                                "%02x%02x ", h[i], h[i+1]);
                i += 2;
        }
        return buf;
}

int serval_ipv4_fill_in_hdr(struct sock *sk, struct sk_buff *skb,
                            uint32_t saddr, uint32_t daddr)
{
	struct inet_sock *inet = inet_sk(sk);
        struct iphdr *iph;
        unsigned int iph_len = sizeof(struct iphdr);

        iph = (struct iphdr *)skb_push(skb, iph_len);
	skb_reset_network_header(skb);

        /* Build IP header */
        memset(iph, 0, iph_len);
        iph->version = 4; 
        iph->ihl = iph_len >> 2;
        iph->tos = inet->tos;
        iph->tot_len = htons(skb->len);
        iph->id = 0;
        iph->frag_off = 0;
        iph->ttl = inet->uc_ttl < 0 ? SERVAL_DEFTTL : inet->uc_ttl;
        iph->protocol = skb->protocol;
        iph->saddr = saddr;
        iph->daddr = daddr;
	skb->protocol = htons(ETH_P_IP);
	skb->priority = sk->sk_priority;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
	skb->mark = sk->sk_mark;
#endif

#if defined(ENABLE_DEBUG)
        {
                unsigned int iph_len = iph->ihl << 2;
                char srcstr[18], dststr[18];
                /* 
                   char buf[256];
                   LOG_DBG("ip dump %s\n", ipv4_hdr_dump(iph, buf, 256));
                */
                LOG_DBG("%s %s->%s tot_len=%u iph_len=[%u %u]\n",
                        skb->dev->name,
                        inet_ntop(AF_INET, &iph->saddr, srcstr, 18),
                        inet_ntop(AF_INET, &iph->daddr, dststr, 18),
                        skb->len, iph_len, iph->ihl);
        }
#endif
        
        return 0;
}

int serval_ipv4_build_and_send_pkt(struct sk_buff *skb, struct sock *sk,
                                   uint32_t saddr, uint32_t daddr, 
                                   struct ip_options *opt)
{
        int err = 0;

        if (saddr == 0) {
                if (!skb->dev) {
                        LOG_ERR("no device set\n");
                        FREE_SKB(skb);
                        return -ENODEV;
                }
                dev_get_ipv4_addr(skb->dev, &saddr);
        }

        err = serval_ipv4_fill_in_hdr(sk, skb, saddr, daddr);
        
        if (err < 0) {
                LOG_ERR("hdr failed\n");
                FREE_SKB(skb);
                return err;
        }

        /* Transmit */
        err = serval_ip_local_out(skb);

        if (err < 0) {
                LOG_ERR("xmit failed\n");
        }
        return err;
}

#if defined(OS_LINUX_KERNEL)
static inline int ip_select_ttl(struct inet_sock *inet, struct dst_entry *dst)
{
	int ttl = inet->uc_ttl;

	if (ttl < 0)
		ttl = dst_metric(dst, RTAX_HOPLIMIT);
	return ttl;
}
#endif

int serval_ipv4_xmit_skb(struct sk_buff *skb)
{
        struct sock *sk = skb->sk;
        int err = 0;
#if defined(OS_LINUX_KERNEL)
        /*
          This is pretty much a copy paste from ip_queue_xmit
          (ip_output.c), but which modifications that take into
          account Serval specific stuff.
          
          It will route the packet according to the IP stack's routing
          table and output for standard IP output processing.
         */
        struct iphdr *iph;
        struct rtable *rt;
        struct inet_sock *inet = inet_sk(sk);
	struct ip_options *opt = inet->opt;
        struct flowi fl = { .oif = sk->sk_bound_dev_if,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
                            .mark = sk->sk_mark,
#endif
                            .nl_u = { .ip4_u =
                                      { .daddr = SERVAL_SKB_CB(skb)->addr.net_ip.s_addr,
                                        .saddr = inet->inet_saddr,
                                        .tos = RT_CONN_FLAGS(sk) } },
                            .proto = skb->protocol,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28))
                            .flags = inet_sk_flowi_flags(sk),
#endif
        };
        
	rcu_read_lock();
        
        security_sk_classify_flow(sk, &fl);

        if (serval_ip_route_output_flow(sock_net(sk), &rt, &fl, sk, 0)) {
                LOG_DBG("No route!\n");
                err = -EHOSTUNREACH;
                rcu_read_unlock();
                goto drop;
        } else {
#if defined(ENABLE_DEBUG)                
                char src[18], dst[18];
                LOG_PKT("Route found - src %s dst %s\n",
                        inet_ntop(AF_INET, &rt->rt_src, 
                                  src, sizeof(src)),
                        inet_ntop(AF_INET, &rt->rt_dst, 
                                  dst, sizeof(dst)));
#endif
                sk_setup_caps(sk, &rt->u.dst);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35))
                skb_dst_set(skb, dst_clone(&rt->u.dst));
#else
                skb_dst_set_noref(skb, &rt->u.dst);
#endif
        }

        if (opt && opt->is_strictroute && rt->rt_dst != rt->rt_gateway) {
                err = -EHOSTUNREACH;
                rcu_read_unlock();
                goto drop;
        }

	/* OK, we know where to send it, allocate and build IP header. */
	skb_push(skb, sizeof(struct iphdr) + (opt ? opt->optlen : 0));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	*((__be16 *)iph) = htons((4 << 12) | (5 << 8) | (inet->tos & 0xff));
	if (ip_dont_fragment(sk, &rt->u.dst) && !skb->local_df)
		iph->frag_off = htons(IP_DF);
	else
		iph->frag_off = 0;
	iph->ttl      = ip_select_ttl(inet, &rt->u.dst);
	iph->protocol = skb->protocol;
	iph->saddr    = rt->rt_src;
	iph->daddr    = rt->rt_dst;

	if (opt && opt->optlen) {
                LOG_WARN("IP options not implemented\n");
                /* For some reason, enabling the code below gives the
                 * error: "Unknown symbol ip_options_build (err 0)"
                 * when loading the serval.ko module. Seems the
                 * ip_options_build function is not exported.
                 */
                /*
		iph->ihl += opt->optlen >> 2;
		ip_options_build(skb, opt, inet->inet_daddr, rt, 0);
                */
	}
        
        ip_select_ident_more(iph, &rt->u.dst, sk,
			     (skb_shinfo(skb)->gso_segs ?: 1) - 1);

	skb->priority = sk->sk_priority;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
	skb->mark = sk->sk_mark;
#endif

	err = serval_ip_local_out(skb);

	rcu_read_unlock();
#else
        //struct net_addr saddr;

        /*
          FIXME: We should not rely on an outgoing interface here.
          Instead, we should route the packet like we do in the
          kernel. But, we currently do not have an IP routing table
          for userlevel.
         */
        /*
        if (!skb->dev) {
                LOG_ERR("no device set in skb!\n");
                err = -ENODEV;
                goto drop;
        }
        
        if (!dev_get_ipv4_addr(skb->dev, &saddr)) {
                LOG_ERR("No device IP set for device %s\n",
                        skb->dev->name);
                err = -ENODEV;
                goto drop;
        }
        */

        err = serval_ipv4_fill_in_hdr(sk, skb, 0,
                                      SERVAL_SKB_CB(skb)->addr.net_ip.s_addr);
        
        if (err < 0) {
                LOG_ERR("hdr failed\n");
                goto drop;
        }

        /* Transmit */
        err = serval_ip_local_out(skb);
#endif        
out:
        if (err < 0) {
                LOG_ERR("xmit failed\n");
        }

        return err;
drop:
        LOG_DBG("Dropping skb!\n");

        FREE_SKB(skb);
        
        goto out;
}
