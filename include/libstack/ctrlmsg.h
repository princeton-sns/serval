#ifndef _LIBSTACK_CTRLMSG_H
#define _LIBSTACK_CTRLMSG_H

#include <netinet/scaffold.h>

enum ctrlmsg_type {
	CTRLMSG_TYPE_JOIN = 0,
	CTRLMSG_TYPE_LEAVE,
	CTRLMSG_TYPE_REGISTER,
	CTRLMSG_TYPE_UNREGISTER,
};

struct ctrlmsg {
	unsigned char type;
	unsigned int len; /* Length, including header and payload */
	unsigned char payload[0];
};

struct ctrlmsg_register {
	struct ctrlmsg msgh;
	struct service_id srvid;
};

#if defined(__linux__)
#include <linux/netlink.h>
#define NETLINK_SCAFFOLD 17
#define NLMSG_SCAFFOLD NLMSG_MIN_TYPE
#endif /* __linux__ */


#if defined(OS_ANDROID)
#define SCAFFOLD_STACK_CTRL_PATH "/cache/scaffold-stack-ctrl.sock"
#define SCAFFOLD_SCAFD_CTRL_PATH "/cache/scaffold-scafd-ctrl.sock"
#else
#define SCAFFOLD_STACK_CTRL_PATH "/tmp/scaffold-stack-ctrl.sock"
#define SCAFFOLD_SCAFD_CTRL_PATH "/tmp/scaffold-scafd-ctrl.sock"
#endif

#endif /* LIBSTACK_CTRLMSG_H */
