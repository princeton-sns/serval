/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <stdlib.h>
#include <stdio.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <pthread.h>
#include <unistd.h>
#include <libstack/ctrlmsg.h>
#include "init.h"
#include "debug.h"
#include "event.h"

int ctrlmsg_handle(struct ctrlmsg *cm, unsigned int);

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
        
        LOG_DBG("initializing SCAFFOLD netlink control\n");

	memset(nlh, 0, sizeof(*nlh));
	nlh->peer.nl_family = AF_NETLINK;
	nlh->peer.nl_pid = getpid();
	nlh->peer.nl_groups = 1;

	nlh->sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_SCAFFOLD);

	if (nlh->sock == -1) {
                if (errno == EPROTONOSUPPORT) {
                        /* This probably means we are not running the
			 * kernel space version of the Scaffold stack,
			 * therefore unregister this handler and exit
			 * without error. */
                        LOG_DBG("netlink not supported, disabling\n");
                        event_unregister_handler(eh);
                        return 0;
                }
		LOG_ERR("netlink control failure: %s\n",
                        strerror(errno));
		goto error;
	}
	
	ret = bind(nlh->sock, (struct sockaddr*)&nlh->peer, 
		   sizeof(nlh->peer));
	
	if (ret == -1) {
		LOG_ERR("Could not bind netlink control socket\n");
		goto error;
	}

        /* Set peer address to indicate kernel as target */
        nlh->peer.nl_pid = 0;
        nlh->peer.nl_groups = 0;
out:
	return ret;
error:
	close(nlh->sock);
        nlh->sock = -1;
        event_unregister_handler(eh);
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

	int ret, num_msgs = 0;
	socklen_t addrlen;
	struct nlmsghdr *nlm;
#define BUFLEN 2000
	char buf[BUFLEN];

	addrlen = sizeof(struct sockaddr_nl);

	memset(buf, 0, BUFLEN);

	ret = recvfrom(nlh->sock, buf, BUFLEN, MSG_DONTWAIT, 
		       (struct sockaddr *) &nlh->peer, &addrlen);

	if (ret == -1) {
                if (errno == EAGAIN) {
                        LOG_DBG("Netlink recv would block\n");
                        return 0;
                }

		LOG_ERR("recv error: %s\n", strerror(errno));
		return ret;
	}

	for (nlm = (struct nlmsghdr *) buf; 
	     NLMSG_OK(nlm, (unsigned int) ret); 
	     nlm = NLMSG_NEXT(nlm, ret)) {
		struct nlmsgerr *nlmerr = NULL;
		//int ret = 0;

		num_msgs++;

		switch (nlm->nlmsg_type) {
		case NLMSG_ERROR:
			nlmerr = (struct nlmsgerr *)NLMSG_DATA(nlm);
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
		case NLMSG_SCAFFOLD:
			ret = ctrlmsg_handle((struct ctrlmsg *)NLMSG_DATA(nlm),
                                             ret - NLMSG_LENGTH(0));
			break;
		default:
			LOG_DBG("Unknown netlink message\n");
			break;
		}
	}
	return ret;
}

static int netlink_getfd(struct event_handler *eh)
{
	struct netlink_handle *nlh = (struct netlink_handle *)eh->private;
	return nlh->sock;
}

static int netlink_send(struct event_handler *eh, const void *data, size_t datalen)
{
        struct netlink_handle *nlh = (struct netlink_handle *)eh->private;
        struct nlmsghdr nh;
	struct iovec iov[2] = { { (void *)&nh, sizeof(nh) }, 
                                { (void *)data, datalen } };
        struct msghdr mh = { &nlh->peer, sizeof(nlh->peer), 
                             iov, 2, NULL, 0, 0 };
        static int sequence_number = 0;

        memset(&nh, 0, sizeof(nh));
	nh.nlmsg_pid = 0;
	nh.nlmsg_seq = ++sequence_number;
        nh.nlmsg_len = NLMSG_LENGTH(datalen);
	/* Request an ack from kernel by setting NLM_F_ACK. */
	/* nh.nlmsg_flags |= NLM_F_ACK; */

        return sendmsg(nlh->sock, &mh, 0);
}

static struct netlink_handle nlh;

static struct event_handler eh = {
	.name = "netlink",
	.init = netlink_handle_init,
	.cleanup = netlink_handle_destroy,
	.getfd = netlink_getfd,
	.handle_event = netlink_handle_event,
        .send = netlink_send,
	.private = (void *)&nlh
};

void netlink_fini(void)
{
	event_unregister_handler(&eh);
}

void netlink_init(void)
{
	event_register_handler(&eh);
}


