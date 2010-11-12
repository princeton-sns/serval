#include <net/sock.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#include "scaffold_netlink.h"
#include <scaffold/debug.h>

static struct sock *nl_sk = NULL;

static void scaffold_netlink_recv_skb(struct sk_buff *skb)
{
	int pid, flags, nlmsglen, skblen;
	struct nlmsghdr *nlh;

        skblen = skb->len;

        if (skblen < sizeof(*nlh))
                return;

        nlh = nlmsg_hdr(skb);
        nlmsglen = nlh->nlmsg_len;

        if (nlmsglen < sizeof(*nlh) || skblen < nlmsglen)
                return;

        pid = nlh->nlmsg_pid;
        flags = nlh->nlmsg_flags;

	LOG_DBG("received skb\n");

	if (flags & NLM_F_ACK)
                netlink_ack(skb, nlh, 0);
}

int __init scaffold_netlink_init(void)
{
	nl_sk = netlink_kernel_create(&init_net, NETLINK_SCAFFOLD, 1, 
				      scaffold_netlink_recv_skb, NULL, THIS_MODULE);

	if (!nl_sk)
		return -ENOMEM;

	LOG_DBG("created netlink socket\n");

	return 0;
}

void __exit scaffold_netlink_fini(void)
{
	netlink_kernel_release(nl_sk);
}

MODULE_ALIAS_NET_PF_PROTO(PF_NETLINK, NETLINK_SCAFFOLD);
