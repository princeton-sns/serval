/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/platform.h>
#include <scaffold/skbuff.h>
#include <scaffold/debug.h>
#include <scaffold_sock.h>
#include <scaffold_ipv4.h>
#include <scaffold/netdevice.h>
#include <scaffold_srv.h>
#include <input.h>
#include <output.h>
#if defined(OS_LINUX_KERNEL)
#include <linux/if_ether.h>
#include <linux/inetdevice.h>
#elif !defined(OS_ANDROID)
#include <netinet/if_ether.h>
#endif

extern int scaffold_srv_rcv(struct sk_buff *);

#define SCAFFOLD_TTL_DEFAULT 250

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

int scaffold_ipv4_fill_in_hdr(struct sock *sk, struct sk_buff *skb,
                              struct ipcm_cookie *ipcm)
{
        struct iphdr *iph;
        unsigned int iph_len = sizeof(struct iphdr);

        iph = (struct iphdr *)skb_push(skb, iph_len);
	skb_reset_network_header(skb);
      
        /* Build IP header */
        memset(iph, 0, iph_len);
        iph->version = 4; 
        iph->ihl = iph_len >> 2;
        iph->tos = 0;
        iph->tot_len = htons(skb->len);
        iph->id = 0;
        iph->frag_off = 0;
        iph->ttl = SCAFFOLD_TTL_DEFAULT;
        iph->protocol = skb->protocol;
        dev_get_ipv4_addr(skb->dev, &iph->saddr);
        memcpy(&iph->daddr, &ipcm->addr, sizeof(struct in_addr));
        iph->check = in_cksum(iph, iph_len);

	skb->protocol = htons(ETH_P_IP);

        return 0;
}

const char *ipv4_hdr_dump(unsigned char *hdr, char *buf, int buflen)
{
        int i = 0, len = 0;
        
        while (i < 20) {
                len += snprintf(buf + len, buflen - len, 
                                "%02x%02x ", hdr[i], hdr[i+1]);
                i += 2;
        }
        return buf;
}

int scaffold_ipv4_rcv(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	unsigned int hdr_len = iph->ihl << 2;
	int ret = 0;

	switch (iph->protocol) {
        case IPPROTO_SCAFFOLD:
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
                char srcstr[18];
                LOG_DBG("%s %s hdr_len=%u prot=%u\n",
                        skb->dev->name,
                        inet_ntop(AF_INET, &iph->saddr, srcstr, 18), 
                        hdr_len, iph->protocol);
        }
#endif
        if (!pskb_may_pull(skb, hdr_len))
                goto inhdr_error;
        
        pskb_pull(skb, hdr_len);                
        skb_reset_transport_header(skb);
    
        ret = scaffold_srv_rcv(skb);
out:
	return ret;
inhdr_error:
        FREE_SKB(skb);

        return ret;
}

int scaffold_ipv4_build_and_send_pkt(struct sk_buff *skb, struct sock *sk,
                                     uint32_t daddr, struct ip_options *opt)
{
	struct ipcm_cookie ipcm;
        int err = 0;

	memset(&ipcm, 0, sizeof(ipcm));

        ipcm.addr = daddr;

        err = scaffold_ipv4_fill_in_hdr(sk, skb, &ipcm);
        
        if (err < 0) {
                LOG_ERR("hdr failed\n");
                FREE_SKB(skb);
                return err;
        }

#if defined(ENABLE_DEBUG)
        {                
                struct iphdr *iph = ip_hdr(skb);
                unsigned int iph_len = iph->ihl << 2;

                LOG_DBG("ip packet tot_len=%u iph_len=[%u %u]\n", 
                        skb->len, iph_len, iph->ihl);
        }
#endif

        /* Transmit */
        err = scaffold_output(skb);

        if (err < 0) {
                LOG_ERR("xmit failed\n");
                FREE_SKB(skb);
        }
        return err;
}

int scaffold_ipv4_xmit_skb(struct sock *sk, struct sk_buff *skb)
{
	struct ipcm_cookie ipcm;
        int err = 0;

	memset(&ipcm, 0, sizeof(ipcm));

        ipcm.addr = 0xffffffff;

        err = scaffold_ipv4_fill_in_hdr(sk, skb, &ipcm);
        
        if (err < 0) {
                LOG_ERR("hdr failed\n");
                FREE_SKB(skb);
                return err;
        }

#if defined(ENABLE_DEBUG)
        {
                struct iphdr *iph = ip_hdr(skb);
                unsigned int iph_len = iph->ihl << 2;
                
                LOG_DBG("ip packet tot_len=%u iph_len=[%u %u]\n", 
                        skb->len, iph_len, iph->ihl);
        }
#endif
        /* Transmit */
        err = scaffold_output(skb);

        if (err < 0) {
                LOG_ERR("xmit failed\n");
                FREE_SKB(skb);
        }

        return err;
}
