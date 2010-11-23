/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <net/sock.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <libstack/ctrlmsg.h>
#include <scaffold/debug.h>
#include <ctrl.h>

static struct sock *nl_sk = NULL;
static int peer_pid = -1;

static void ctrl_recv_skb(struct sk_buff *skb)
{
	int flags, nlmsglen, skblen;
	struct nlmsghdr *nlh;

        skblen = skb->len;

        if (skblen < sizeof(*nlh))
                return;

        nlh = nlmsg_hdr(skb);
        nlmsglen = nlh->nlmsg_len;

        if (nlmsglen < sizeof(*nlh) || skblen < nlmsglen)
                return;

        peer_pid = nlh->nlmsg_pid;
        flags = nlh->nlmsg_flags;

	LOG_DBG("received skb\n");

	if (flags & NLM_F_ACK)
                netlink_ack(skb, nlh, 0);
}

int ctrl_sendmsg(struct ctrlmsg *msg, int mask)
{
        struct sk_buff *skb;
        struct nlmsghdr *nlh;

        skb = alloc_skb(NLMSG_LENGTH(msg->len), mask);

        if (!skb)
                return -ENOMEM;

        NETLINK_CB(skb).dst_group = 1;
        nlh = (struct nlmsghdr *)skb_put(skb, NLMSG_LENGTH(msg->len));
        nlh->nlmsg_type = NLMSG_SCAFFOLD;
        nlh->nlmsg_len = NLMSG_LENGTH(msg->len);
        
        memcpy(NLMSG_DATA(nlh), msg, msg->len);

        LOG_DBG("broadcast netlink msg type=%d\n", msg->type);

        return netlink_broadcast(nl_sk, skb, 0, 1, mask);
}

int __init ctrl_init(void)
{
	nl_sk = netlink_kernel_create(&init_net, NETLINK_SCAFFOLD, 1, 
				      ctrl_recv_skb, NULL, THIS_MODULE);

	if (!nl_sk)
		return -ENOMEM;

	LOG_DBG("created netlink socket\n");

        /* Allow non-root daemons to receive notifications */
	netlink_set_nonroot(NETLINK_SCAFFOLD, NL_NONROOT_RECV);

	return 0;
}

void __exit ctrl_fini(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	struct sock *sk = nl_sk;

	if (sk) {
                nl_sk = NULL;
                sock_release(sk->sk_socket);
	}
#else
        netlink_kernel_release(nl_sk);
#endif
}

MODULE_ALIAS_NET_PF_PROTO(PF_NETLINK, NETLINK_SCAFFOLD);
