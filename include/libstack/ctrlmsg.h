#ifndef _LIBSTACK_CTRLMSG_H
#define _LIBSTACK_CTRLMSG_H

#include <netinet/serval.h>
#if !defined(__KERNEL__)
#include <net/if.h>
#include <netinet/in.h>
#endif

enum ctrlmsg_type {

    CTRLMSG_TYPE_JOIN = 0,
    CTRLMSG_TYPE_LEAVE = 1,
    CTRLMSG_TYPE_REGISTER = 2,
    CTRLMSG_TYPE_UNREGISTER = 3,
    CTRLMSG_TYPE_RESOLVE = 4,

    CTRLMSG_TYPE_IFACE_CONF = 5,
    CTRLMSG_TYPE_ADD_SERVICE = 6,
    CTRLMSG_TYPE_DEL_SERVICE = 7,
    CTRLMSG_TYPE_MOD_SERVICE = 8,
    CTRLMSG_TYPE_GET_SERVICE = 9,
    CTRLMSG_TYPE_SERVICE_STATS = 10,
    CTRLMSG_TYPE_CAPABILITIES = 11,
    CTRLMSG_TYPE_UNKNOWN = 1000,
};

/* this should simply use sv_instance_addr
 * and include an extension with stat values
 * */
struct service_resolution {
    /*service desc up top*/
    uint16_t type;
    uint8_t sv_prefix_bits;
    uint8_t sv_flags;
    struct service_id srvid;
    struct net_addr address;
    int if_index;

    uint32_t priority; /* Priority level of flow entry. */
    uint32_t weight;

    uint32_t idle_timeout; /* Idle time before discarding (seconds). */
    uint32_t hard_timeout; /* Max time before discarding (seconds). */

    //if address is zero'd out, then resolve "up" to the user-space process
};

struct service_resolution_stat {
    struct service_resolution res;
    uint32_t duration_sec;
    uint32_t duration_nsec;
    uint32_t packets_resolved;
    uint32_t bytes_resolved;
    uint32_t packets_dropped;
    uint32_t bytes_dropped;
    uint32_t tokens_consumed;
};

enum sv_stack_capabilities {
    SVSTK_TRANSIT = 1 << 0, /*Can perform resolution/redireciton - if not set, then the SR is terminal for non-specified prefixes*/

};

struct service_stat {
    uint32_t capabilities;
    uint32_t services;
    uint32_t instances;
    uint32_t packets_resolved;
    uint32_t bytes_resolved;
    uint32_t bytes_dropped;
    uint32_t packets_dropped;
};

struct ctrlmsg {
    unsigned char type;
    unsigned int len; /* Length, including header and payload */
    unsigned char payload[0];
}__attribute__((packed));

#define CTRLMSG_SIZE (sizeof(struct ctrlmsg))

/* this should probably include address as well - whatever was passed in to bind()*/
struct ctrlmsg_register {
    struct ctrlmsg cmh;
    uint8_t sv_flags;
    uint8_t sv_prefix_bits;
    struct service_id srvid;
};

#define CTRLMSG_REGISTER_SIZE (sizeof(struct ctrlmsg_register))
#define CTRLMSG_UNREGISTER_SIZE (sizeof(struct ctrlmsg_register))

/* resolution up call for service router process to resolve
 * the response should be a ctrlmsg with a resolution and either
 * a buffer (skb) ID or the packet data
 */
struct ctrlmsg_resolve {
    struct ctrlmsg cmh;
    uint32_t xid;

    uint8_t src_flags;
    uint8_t src_prefix_bits;
    struct service_id src_srvid;
    struct net_addr src_address;

    /* address? */
    uint8_t dst_flags;
    uint8_t dst_prefix_bits;
    struct service_id dst_srvid;
};

#define CTRLMSG_RESOLVE_SIZE (sizeof(struct ctrlmsg_resolve))

/* resolution lookup for a service id (prefix), returns all
 * matching resolutions
 */
struct ctrlmsg_get_service {
    struct ctrlmsg cmh;
    uint32_t xid;
    uint8_t sv_flags;
    uint8_t sv_prefix_bits;
    struct service_id srvid;
};

struct ctrlmsg_resolution {
    struct ctrlmsg cmh;
    uint32_t xid;
    struct service_resolution resolution[0];
};

#define CTRLMSG_GET_SERVICE_SIZE (sizeof(struct ctrlmsg_get_service))
#define CTRLMSG_ADD_SERVICE_SIZE (sizeof(struct ctrlmsg_resolution))
#define CTRLMSG_REM_SERVICE_SIZE (sizeof(struct ctrlmsg_resolution))
#define CTRLMSG_MOD_SERVICE_SIZE (sizeof(struct ctrlmsg_resolution))

#define CTRL_NUM_SERVICES(ctrlmsg, size) ((size - sizeof(*ctrlmsg)) % sizeof(struct service_resolution) == 0 ? \
        (size - sizeof(*ctrlmsg)) / sizeof(struct service_resolution) : 0)

#define CTRL_NUM_STAT_SERVICES(ctrlmsg, size) ((size - sizeof(*ctrlmsg)) %  sizeof(struct service_resolution_stat) == 0 ? \
        (size - sizeof(*ctrlmsg)) / sizeof(struct service_resolution_stat) : 0)

struct ctrlmsg_stats {
    struct ctrlmsg cmh;
    uint32_t xid;
    struct service_stat stats;
};

#define CTRLMSG_STATS_SIZE (sizeof(struct ctrlmsg_stats))

struct ctrlmsg_capabilities {
    struct ctrlmsg cmh;
    int capabilities;
};

#define CTRLMSG_CAPABILITIES_SIZE (sizeof(struct ctrlmsg_capabilities))

#define IFFLAG_UP 0x1
#define IFFLAG_HOST_CTRL_MODE 0x2

struct ctrlmsg_iface_conf {
    struct ctrlmsg cmh;
    char ifname[IFNAMSIZ];
    struct net_addr ipaddr;
    unsigned short flags;
};

#define CTRLMSG_IFACE_CONF_SIZE (sizeof(struct ctrlmsg_iface_conf))

enum {
    CTRL_MODE_NET = 0, CTRL_MODE_HOST = 1
};

struct ctrlmsg_service {
    struct ctrlmsg cmh;
    struct service_id srvid;
    unsigned int prefix_bits;
    struct in_addr ipaddr;
    char ifname[IFNAMSIZ];
};

#define CTRLMSG_SERVICE_SIZE (sizeof(struct ctrlmsg_service))

#if defined(__linux__)
#include <linux/netlink.h>
#define NETLINK_SERVAL 17
#define NLMSG_SERVAL NLMSG_MIN_TYPE
#endif /* __linux__ */

#if defined(OS_ANDROID)
#define SERVAL_STACK_CTRL_PATH "/data/local/tmp/serval-stack-ctrl.sock"
#define SERVAL_SCAFD_CTRL_PATH "/data/local/tmp/serval-libstack-ctrl.sock"
#else
#define SERVAL_STACK_CTRL_PATH "/tmp/serval-stack-ctrl.sock"
#define SERVAL_SCAFD_CTRL_PATH "/tmp/serval-libstack-ctrl.sock"
#endif

#endif /* LIBSTACK_CTRLMSG_H */
