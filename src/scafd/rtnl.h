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

int rtnl_init(struct netlink_handle *nlh);
int rtnl_close(struct netlink_handle *nlh);
int rtnl_get_fd(struct netlink_handle *nlh);

#define rtnl_getlink(nl) rtnl_request(nl, RTM_GETLINK)
#define rtnl_getneigh(nl) rtnl_request(nl, RTM_GETNEIGH)
#define rtnl_getaddr(nl) rtnl_request(nl, RTM_GETADDR | RTM_GETLINK)
int rtnl_request(struct netlink_handle *nlh, int type);
int rtnl_read(struct netlink_handle *nlh);

#endif /* _RTNL_H_ */
