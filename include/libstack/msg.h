#ifndef _LIBSTACK_MSG_H
#define _LIBSTACK_MSG_H

#include <linux/netlink.h>

enum stack_msg_type {
	MSG_TYPE_JOIN = NLMSG_MIN_TYPE,
	MSG_TYPE_LEAVE,
	MSG_TYPE_REGISTER,
	MSG_TYPE_UNREGISTER,
};

struct stack_msg {
	unsigned int data;
};

#endif /* LIBSTACK_MSG_H */
