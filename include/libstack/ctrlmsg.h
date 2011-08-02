/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _LIBSTACK_CTRLMSG_H
#define _LIBSTACK_CTRLMSG_H

#include <netinet/serval.h>
#if !defined(__KERNEL__)
#include <net/if.h>
#include <netinet/in.h>
#endif

/*
  Control message types.

  NOTE: when adding a new type, also make sure the size array in
  ctrlmsg.c is updated accordingly.
*/
enum ctrlmsg_type {
        CTRLMSG_TYPE_REGISTER = 0,
        CTRLMSG_TYPE_UNREGISTER,
        CTRLMSG_TYPE_RESOLVE,
        CTRLMSG_TYPE_IFACE_CONF,
        CTRLMSG_TYPE_ADD_SERVICE,
        CTRLMSG_TYPE_DEL_SERVICE,
        CTRLMSG_TYPE_MOD_SERVICE,
        CTRLMSG_TYPE_GET_SERVICE,
        CTRLMSG_TYPE_SERVICE_STATS,
        CTRLMSG_TYPE_CAPABILITIES,
        _CTRLMSG_TYPE_MAX,
};

struct service_info {
        /*service desc up top*/
        uint16_t type;
        struct sockaddr_sv service;
        struct net_addr address;
        int if_index;

        uint32_t priority; /* Priority level of flow entry. */
        uint32_t weight;

        uint32_t idle_timeout; /* Idle time before discarding (seconds). */
        uint32_t hard_timeout; /* Max time before discarding (seconds). */

        /* if address is zero'd out, then resolve "up" to the
           user-space process */
} __attribute__((packed));

struct service_info_stat {
        struct service_info service;
        uint32_t duration_sec;
        uint32_t duration_nsec;
        uint32_t packets_resolved;
        uint32_t bytes_resolved;
        uint32_t packets_dropped;
        uint32_t bytes_dropped;
        uint32_t tokens_consumed;
} __attribute__((packed));

enum sv_stack_capabilities {
        SVSTK_TRANSIT = 1 << 0, /*Can perform resolution/redireciton -
                                 * if not set, then the SR is terminal
                                 * for non-specified prefixes*/

};

struct service_stat {
        uint32_t capabilities;
        uint32_t services;
        uint32_t instances;
        uint32_t packets_resolved;
        uint32_t bytes_resolved;
        uint32_t bytes_dropped;
        uint32_t packets_dropped;
} __attribute__((packed));

struct ctrlmsg {
        unsigned short type;
        unsigned short len; /* Length, including header and payload */
        unsigned char payload[0];
}__attribute__((packed));

#define CTRLMSG_SIZE (sizeof(struct ctrlmsg))

/* this should probably include address as well - whatever was passed
 * in to bind()*/
struct ctrlmsg_register {
        struct ctrlmsg cmh;
        struct sockaddr_sv service;
} __attribute__((packed));

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
} __attribute__((packed));

#define CTRLMSG_RESOLVE_SIZE (sizeof(struct ctrlmsg_resolve))

/* resolution lookup for a service id (prefix), returns all
 * matching resolutions
 */
struct ctrlmsg_service {
        struct ctrlmsg cmh;
        uint32_t xid;
        struct service_info services[1]; /* Always at least one
                                            service entry */
} __attribute__((packed));

#define CTRLMSG_GET_SERVICE_SIZE (sizeof(struct ctrlmsg_service))
#define CTRLMSG_ADD_SERVICE_SIZE (sizeof(struct ctrlmsg_service))
#define CTRLMSG_DEL_SERVICE_SIZE (sizeof(struct ctrlmsg_service))
#define CTRLMSG_MOD_SERVICE_SIZE (sizeof(struct ctrlmsg_service))

#define CTRLMSG_SERVICE_LEN(num)                                        \
        (sizeof(struct ctrlmsg_service) +                               \
         ((num-1) * sizeof(struct service_info)))

#define CTRLMSG_SERVICE_NUM(cmsg)                                   \
        (((cmsg)->cmh.len - sizeof(struct ctrlmsg_service) +        \
          sizeof(struct service_info)) /                            \
         sizeof(struct service_info))

struct ctrlmsg_service_stat {
        struct ctrlmsg cmh;
        uint32_t xid;
        struct service_info_stat services[1]; /* Always at least one
                                                 service entry */
} __attribute__((packed));

#define CTRLMSG_SERVICE_STAT_LEN(num)                                   \
        (sizeof(struct ctrlmsg_service) +                               \
         ((num-1) * sizeof(struct service_info_stat)))

#define CTRLMSG_SERVICE_STAT_NUM(cmsg)                            \
        (((cmsg)->cmh.len - sizeof(struct ctrlmsg) +              \
          sizeof(struct service_info_stat)) /                     \
         sizeof(struct service_info_stat))

struct ctrlmsg_service_stats {
        struct ctrlmsg cmh;
        uint32_t xid;
        struct service_stat stats;
} __attribute__((packed));

#define CTRLMSG_SERVICE_STATS_SIZE (sizeof(struct ctrlmsg_service_stats))

struct ctrlmsg_capabilities {
        struct ctrlmsg cmh;
        int capabilities;
} __attribute__((packed));

#define CTRLMSG_CAPABILITIES_SIZE (sizeof(struct ctrlmsg_capabilities))

#define IFFLAG_UP 0x1
#define IFFLAG_HOST_CTRL_MODE 0x2

struct ctrlmsg_iface_conf {
        struct ctrlmsg cmh;
        char ifname[IFNAMSIZ];
        struct net_addr ipaddr;
        unsigned short flags;
} __attribute__((packed));

#define CTRLMSG_IFACE_CONF_SIZE (sizeof(struct ctrlmsg_iface_conf))

enum {
        CTRL_MODE_NET = 0, CTRL_MODE_HOST = 1
};

#if defined(__linux__)
#include <linux/netlink.h>
#define NETLINK_SERVAL 17
#define NLMSG_SERVAL NLMSG_MIN_TYPE
#endif /* __linux__ */

#if defined(OS_ANDROID)
#define SERVAL_STACK_CTRL_PATH "/data/local/tmp/serval-stack-ctrl.sock"
#define SERVAL_SERVD_CTRL_PATH "/data/local/tmp/serval-libstack-ctrl.sock"
#else
#define SERVAL_STACK_CTRL_PATH "/tmp/serval-stack-ctrl.sock"
#define SERVAL_SERVD_CTRL_PATH "/tmp/serval-libstack-ctrl.sock"
#endif

#endif /* LIBSTACK_CTRLMSG_H */
