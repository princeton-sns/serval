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
#elif !defined(OS_ANDROID)
#include <netinet/if_ether.h>
#endif

extern int serval_srv_rcv(struct sk_buff *);

#define SERVAL_TTL_DEFAULT 250

/* Taken from Click */
uint16_t in_cksum(const void *data, size_t len)
{
        int nleft = len;
        const uint16_t *w = (const uint16_t *)data;
        uint32_t sum = 0;
        uint16_t answer = 0;
        
        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }
        
        /* mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(unsigned char *)(&answer) = *(const unsigned char *)w ;
                sum += answer;
        }
        
        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum & 0xffff) + (sum >> 16);
        sum += (sum >> 16);
        /* guaranteed now that the lower 16 bits of sum are correct */
        
        answer = ~sum;              /* truncate to 16 bits */
        return answer;
}

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
                            struct ipcm_cookie *ipcm)
{
        struct iphdr *iph;
        unsigned int iph_len = sizeof(struct iphdr);
        
        LOG_DBG("1. skb->len=%u\n", skb->len);

        iph = (struct iphdr *)skb_push(skb, iph_len);
	skb_reset_network_header(skb);
      
        LOG_DBG("1. skb->len=%u\n", skb->len);

        /* Build IP header */
        memset(iph, 0, iph_len);
        iph->version = 4; 
        iph->ihl = iph_len >> 2;
        iph->tos = 0;
        iph->tot_len = htons(skb->len);
        iph->id = 0;
        iph->frag_off = 0;
        iph->ttl = SERVAL_TTL_DEFAULT;
        iph->protocol = skb->protocol;
        dev_get_ipv4_addr(skb->dev, &iph->saddr);
        memcpy(&iph->daddr, &ipcm->addr, sizeof(struct in_addr));
        iph->check = in_cksum(iph, iph_len);

	skb->protocol = htons(ETH_P_IP);

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
        if (!pskb_may_pull(skb, hdr_len))
                goto inhdr_error;
        
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

int serval_ipv4_build_and_send_pkt(struct sk_buff *skb, struct sock *sk,
                                   uint32_t daddr, struct ip_options *opt)
{
	struct ipcm_cookie ipcm;
        int err = 0;

	memset(&ipcm, 0, sizeof(ipcm));

        ipcm.addr = daddr;
        
        if (!skb->dev) {
                LOG_ERR("no device set\n");
                FREE_SKB(skb);
                return -ENODEV;
        }

        err = serval_ipv4_fill_in_hdr(sk, skb, &ipcm);
        
        if (err < 0) {
                LOG_ERR("hdr failed\n");
                FREE_SKB(skb);
                return err;
        }

        /* Transmit */
        err = serval_output(skb);

        if (err < 0) {
                LOG_ERR("xmit failed\n");
        }
        return err;
}

int serval_ipv4_xmit_skb(struct sk_buff *skb)
{
        struct sock *sk = skb->sk;
	struct ipcm_cookie ipcm;
        int err = 0;

        if (!skb->dev) {
                LOG_ERR("no device set\n");
                FREE_SKB(skb);
                return -ENODEV;
        }

        LOG_DBG("skb->len=%u\n", skb->len);

	memset(&ipcm, 0, sizeof(ipcm));
        memcpy(&ipcm.addr, &SERVAL_SKB_CB(skb)->dst_addr,
               sizeof(ipcm.addr));

        err = serval_ipv4_fill_in_hdr(sk, skb, &ipcm);
        
        if (err < 0) {
                LOG_ERR("hdr failed\n");
                FREE_SKB(skb);
                return err;
        }

        /* Transmit */
        err = serval_output(skb);

        if (err < 0) {
                LOG_ERR("xmit failed\n");
        }

        return err;
}
