/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <net/sock.h>
#include <net/udp.h>
#include <net/inet_common.h>
#include <linux/net.h>
#include <linux/file.h>
#include <serval_sock.h>
#include <serval_sal.h>
#include <serval_ipv4.h>
#include <serval/debug.h>

#define UDP_ENCAP_PORT (54324)
#define UDP_ENCAP_MAGIC	0x61114EDA

struct udp_encap {
        int                     magic;
        struct sock		*sk_parent;		/* Parent socket */
        struct sock		*sk;
	void (*old_sk_destruct)(struct sock *);
};

static struct sock *encap_sk = NULL;

int serval_udp_encap_skb(struct sk_buff *skb, 
                         __u32 saddr, __u32 daddr, 
                         u16 dport)
{
        struct udphdr *uh;

        uh = (struct udphdr *)skb_push(skb, sizeof(struct udphdr));
        
        if (!uh)
                return -1;

        skb_reset_transport_header(skb);
        
        /* Build UDP header */
        uh->source = htons(UDP_ENCAP_PORT);
        uh->dest = htons(dport == 0 ? UDP_ENCAP_PORT : dport);
        uh->len = htons(skb->len);
        skb->ip_summed = CHECKSUM_NONE;
        uh->check = 0;
        uh->check = csum_tcpudp_magic(saddr,
                                      daddr, 
                                      skb->len,
                                      IPPROTO_UDP,
                                      csum_partial(uh, skb->len, 0));
        skb->protocol = IPPROTO_UDP;

        return 0;
}

int serval_udp_encap_xmit(struct sk_buff *skb)
{ 
        struct sock *sk = skb->sk;

        if (!sk)
                return -1;

        LOG_PKT("Transmitting UDP packet len=%u\n", skb->len);

        if (serval_udp_encap_skb(skb, 
                                 inet_sk(sk)->inet_saddr, 
                                 inet_sk(sk)->inet_daddr,
                                 serval_sk(sk)->udp_encap_port)) {
                kfree_skb(skb);
                return NET_RX_DROP;
        }
        
        return serval_sk(sk)->af_ops->encap_queue_xmit(skb);
}

static inline struct udp_encap *sock_to_encap(struct sock *sk)
{
	struct udp_encap *encap;

	if (sk == NULL)
		return NULL;

	//sock_hold(sk);
	encap = (struct udp_encap *)(sk->sk_user_data);

	if (encap == NULL) {
		//sock_put(sk);
		goto out;
	}

	BUG_ON(encap->magic != UDP_ENCAP_MAGIC);

out:
	return encap;
}

/* UDP encapsulation receive handler. See net/ipv4/udp.c.
 * Return codes:
 * 0 : success.
 * <0: error
 * >0: skb should be passed up to userspace as UDP.
 */
int udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct udp_encap *encap;
        
        LOG_PKT("Received encapsulated Serval packet\n");
        
	encap = sock_to_encap(sk);

	if (encap == NULL)
		goto pass_up;

	/* UDP always verifies the packet length. */
	__skb_pull(skb, sizeof(struct udphdr));
        skb_reset_transport_header(skb);

        return serval_sal_rcv(skb);

        //pass_up_put:
	//sock_put(sk);
pass_up:
	return 1;
}

static int udp_sock_create(u16 src_port, u16 dst_port, struct socket **sockp)
{
        int err = -EINVAL;
        struct sockaddr_in udp_addr;
        struct socket *sock = NULL;

        err = sock_create(AF_INET, SOCK_DGRAM, 0, sockp);
        
        if (err < 0)
                goto out;
        
        sock = *sockp;
        memset(&udp_addr, 0, sizeof(udp_addr));
        udp_addr.sin_family = AF_INET;
        udp_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        udp_addr.sin_port = htons(src_port);
        err = kernel_bind(sock, (struct sockaddr *) &udp_addr, 
                          sizeof(udp_addr));
        if (err < 0)
                goto out;
        /*
        udp_addr.sin_family = AF_INET;
        udp_addr.sin_addr = 0;
        udp_addr.sin_port = htons(dst_port);
        err = kernel_connect(sock, (struct sockaddr *) &udp_addr, 
                             sizeof(udp_addr), 0);
        if (err < 0)
                goto out;
        */
        //sock->sk->sk_no_check = UDP_CSUM_NOXMIT;
        

 out:
        if ((err < 0) && sock) {
                sock_release(sock);
		*sockp = NULL;
	}

        return err;
}

static void udp_encap_destruct(struct sock *sk)
{
        struct udp_encap *encap = sk->sk_user_data;

	(udp_sk(sk))->encap_type = 0;
        (udp_sk(sk))->encap_rcv = NULL;

        sk->sk_destruct = encap->old_sk_destruct;
	sk->sk_user_data = NULL;

        /* Call the original destructor */
	if (sk->sk_destruct)
		(*sk->sk_destruct)(sk);
        
        LOG_DBG("encap destroyed\n");

        kfree(encap);
}        

void udp_encap_fini(void)
{
        if (!encap_sk)
                return;

        inet_release(encap_sk->sk_socket);
        
        LOG_DBG("UDP encapsulation socket destroyed\n");
        encap_sk = NULL;
}

int udp_encap_init(void)
{
        struct socket *sock = NULL;
        u16 src_port, dst_port;
        struct udp_encap *encap;
        struct sock *sk;
        int err;
        /*
        if (sk->sk_state == SERVAL_LISTEN) {
                src_port = UDP_ENCAP_PORT;
                dst_port = UDP_ENCAP_PORT;
        } else {
        }
        */
        LOG_DBG("Initializing UDP encapsulation for Serval\n");

        src_port = UDP_ENCAP_PORT;
        dst_port = UDP_ENCAP_PORT;

        err = udp_sock_create(src_port, dst_port, &sock);

        if (err < 0) {
                LOG_ERR("Could not create UDP socket\n");
                goto error;
        }
	sk = sock->sk;
        encap_sk = sk;

        encap = kzalloc(sizeof(struct udp_encap), gfp_any());
        
        if (!encap) {
                err = -ENOMEM;
                goto error;
        }

        encap->magic = UDP_ENCAP_MAGIC;
        //encap->sk_parent = sk_parent;
        encap->sk = sk;
        encap->old_sk_destruct = sk->sk_destruct;

	sk->sk_user_data = encap;
        sk->sk_destruct = udp_encap_destruct;

        udp_sk(sk)->encap_type = 4; /* This is an unallocated type */
        udp_sk(sk)->encap_rcv = udp_encap_recv;
 error:
	/* If tunnel's socket was created by the kernel, it doesn't
	 *  have a file.
	 */
	if (sock && sock->file)
		sockfd_put(sock);

        return err;
}
