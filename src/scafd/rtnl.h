/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _RTNL_H_
#define _RTNL_H_

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>

struct netlink_handle {
        int fd;
        int seq;
        struct sockaddr_nl local;
        struct sockaddr_nl peer;
};

int nl_init_handle(struct netlink_handle *nlh);
int nl_close_handle(struct netlink_handle *nlh);
int nl_get_fd(struct netlink_handle *nlh);

#define netlink_getlink(nl) netlink_request(nl, RTM_GETLINK)
#define netlink_getneigh(nl) netlink_request(nl, RTM_GETNEIGH)
#define netlink_getaddr(nl) netlink_request(nl, RTM_GETADDR | RTM_GETLINK)
int netlink_request(struct netlink_handle *nlh, int type);
int read_netlink(struct netlink_handle *nlh);

#endif /* _RTNL_H_ */
