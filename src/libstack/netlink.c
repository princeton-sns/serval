/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <stdlib.h>
#include <stdio.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <libstack/msg.h>
#include "init.h"
#include "debug.h"
#include "event.h"

#define NETLINK_SCAFFOLD 17

struct netlink_handle {
	struct event_handler *eh;
	int sock;
	struct sockaddr_nl peer;
	pthread_t thread;
};

static int netlink_handle_init(struct event_handler *eh)
{
	struct netlink_handle *nlh = (struct netlink_handle *)eh->private;
	int ret;

	memset(nlh, 0, sizeof(*nlh));
	nlh->peer.nl_family = AF_NETLINK;
	nlh->peer.nl_pid = getpid();
	nlh->peer.nl_groups = 0;

	nlh->sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_SCAFFOLD);

	if (nlh->sock == -1) {
		LOG_ERR("Could not open Scaffold netlink socket\n");
		return -1;
	}
	
	ret = bind(nlh->sock, (struct sockaddr*)&nlh->peer, 
		   sizeof(nlh->peer));
	
	if (ret == -1) {
		LOG_ERR("Could not bind netlink socket\n");
		goto error;
	}
out:
	return ret;
error:
	close(nlh->sock);
	goto out;
}

static void netlink_handle_destroy(struct event_handler *eh)
{
	struct netlink_handle *nlh = (struct netlink_handle *)eh->private;
	if (nlh->sock != -1)
		close(nlh->sock);
}

static int netlink_handle_event(struct event_handler *eh)
{
	struct netlink_handle *nlh = (struct netlink_handle *)eh->private;

	int len, num_msgs = 0;
	socklen_t addrlen;
	struct nlmsghdr *nlm;
#define BUFLEN 2000
	char buf[BUFLEN];

	addrlen = sizeof(struct sockaddr_nl);

	memset(buf, 0, BUFLEN);

	len = recvfrom(nlh->sock, buf, BUFLEN, MSG_DONTWAIT, 
		       (struct sockaddr *) &nlh->peer, &addrlen);

	if (len == EAGAIN) {
		LOG_DBG("Netlink recv would block\n");
		return 0;
	}
	if (len < 0) {
		LOG_DBG("len negative\n");
		return len;
	}

	for (nlm = (struct nlmsghdr *) buf; 
	     NLMSG_OK(nlm, (unsigned int) len); 
	     nlm = NLMSG_NEXT(nlm, len)) {
		struct nlmsgerr *nlmerr = NULL;
		//int ret = 0;

		num_msgs++;

		switch (nlm->nlmsg_type) {
		case NLMSG_ERROR:
			nlmerr = (struct nlmsgerr *) NLMSG_DATA(nlm);
			if (nlmerr->error == 0) {
				LOG_DBG("NLMSG_ACK");
			} else {
				LOG_DBG("NLMSG_ERROR, error=%d type=%d\n", 
					nlmerr->error, nlmerr->msg.nlmsg_type);
			}
			break;
		case NLMSG_DONE:
			//LOG_DBG("NLMSG_DONE\n");
			break;
		case MSG_TYPE_JOIN:
			LOG_DBG("join message\n");
			break;
		case MSG_TYPE_LEAVE:
			LOG_DBG("leave message\n");
			break;
		case MSG_TYPE_REGISTER:
			LOG_DBG("register message\n");
			break;
		case MSG_TYPE_UNREGISTER:
			LOG_DBG("unregister message\n");
			break;
		default:
			LOG_DBG("Unknown netlink message\n");
			break;
		}
	}
	return num_msgs;
}

static int netlink_getfd(struct event_handler *eh)
{
	struct netlink_handle *nlh = (struct netlink_handle *)eh->private;
	return nlh->sock;
}

static struct netlink_handle nlh;

static struct event_handler eh = {
	.name = "netlink",
	.init = netlink_handle_init,
	.cleanup = netlink_handle_destroy,
	.getfd = netlink_getfd,
	.handle_event = netlink_handle_event,
	.private = (void *)&nlh
};

__onload
void netlink_init(void)
{
	event_register_handler(&eh);
}

__onexit
void netlink_fini(void)
{
	event_unregister_handler(&eh);
}


