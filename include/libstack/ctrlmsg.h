#ifndef _LIBSTACK_CTRLMSG_H
#define _LIBSTACK_CTRLMSG_H

#include <netinet/scaffold.h>
#if !defined(__KERNEL__)
#include <net/if.h>
#endif

enum ctrlmsg_type {
	CTRLMSG_TYPE_JOIN = 0,
	CTRLMSG_TYPE_LEAVE,
	CTRLMSG_TYPE_REGISTER,
	CTRLMSG_TYPE_UNREGISTER,
	CTRLMSG_TYPE_IFACE_CONF,
	CTRLMSG_TYPE_SET_SERVICE,
	CTRLMSG_TYPE_UNKNOWN,
};

struct ctrlmsg {
	unsigned char type;
	unsigned int len; /* Length, including header and payload */
	unsigned char payload[0];
} __attribute__((packed));

#define CTRLMSG_SIZE (sizeof(struct ctrlmsg))

struct ctrlmsg_register {
	struct ctrlmsg cmh;
	struct service_id srvid;
};

#define CTRLMSG_REGISTER_SIZE (sizeof(struct ctrlmsg_register))
#define CTRLMSG_UNREGISTER_SIZE (sizeof(struct ctrlmsg_register))

#define IFFLAG_UP 0x1
#define IFFLAG_HOST_CTRL_MODE 0x2

struct ctrlmsg_iface_conf {
	struct ctrlmsg cmh;
	char ifname[IFNAMSIZ];
	struct as_addr asaddr;
	struct host_addr haddr;
	unsigned short flags;
};

#define CTRLMSG_IFACE_CONF_SIZE (sizeof(struct ctrlmsg_iface_conf))

enum {
	CTRL_MODE_NET = 0,
	CTRL_MODE_HOST = 1
};

struct ctrlmsg_service {
	struct ctrlmsg cmh;
	struct service_id srvid;
	char ifname[IFNAMSIZ];
};

#define CTRLMSG_SERVICE_SIZE (sizeof(struct ctrlmsg_service))

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
