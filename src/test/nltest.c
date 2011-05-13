/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <stdlib.h>
#include <stdio.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define NETLINK_SERVAL 17

int nltest_sendmsg(int sock, struct nlmsghdr *nh)
{
	struct sockaddr_nl sa;
	struct iovec iov = { (void *) nh, nh->nlmsg_len };
	struct msghdr msg = { (void *)&sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
	static int sequence_number = 0;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	nh->nlmsg_pid = 0;
	nh->nlmsg_seq = ++sequence_number;
	/* Request an ack from kernel by setting NLM_F_ACK. */
	nh->nlmsg_flags |= NLM_F_ACK;
	
	printf("Sending message\n");
	return sendmsg(sock, &msg, 0);
}

int nltest_recvmsg(int sock)
{
	int len;
	char buf[4096];
	struct iovec iov = { buf, sizeof(buf) };
	struct sockaddr_nl sa;
	struct msghdr msg = { (void *)&sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
	struct nlmsghdr *nh = (struct nlmsghdr *)buf;
	
	len = recvmsg(sock, &msg, 0);
	
	for (; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
		switch (nh->nlmsg_type) {
		case NLMSG_DONE:
			printf("NLMSG_DONE\n");
			break;
		case NLMSG_ERROR:
		{
			struct nlmsgerr *nlmerr = (struct nlmsgerr *)NLMSG_DATA(nh);
			if (nlmerr->error == 0) {
				printf("NLMSG_ACK\n");
			} else {
				printf("NLMSG_ERROR\n");
			}
			break;
		}
		default:
			printf("NLMSG type %d\n", nh->nlmsg_type);
		}		
	}

	return len;
}
	
int main(int argc, char **argv)
{
	int sock, ret = 0;
	struct sockaddr_nl sa;
	struct {
		struct nlmsghdr nh;
		char payload[8];
	} msg;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = 0;
	
	sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_SERVAL);

	if (sock == -1) {
		fprintf(stderr, "Could not open Serval netlink socket\n");
		return -1;
	}
	
	ret = bind(sock, (struct sockaddr*)&sa, sizeof(sa));
	
	if (ret == -1) {
		fprintf(stderr, "Could not bind netlink socket\n");
		goto error;
	}

	memset(&msg, 0, sizeof(msg));

	msg.nh.nlmsg_len = NLMSG_LENGTH(8);
	msg.nh.nlmsg_pid = getpid();

	ret = nltest_sendmsg(sock, &msg.nh);

	nltest_recvmsg(sock);
	
done:
	printf("Closing socket\n");
	close(sock);

	return ret;
error:
	ret = -1;
	goto done;
}
