/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SCAFFOLD_H
#define _SCAFFOLD_H

#if defined(__linux__) && defined(__KERNEL__)
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/in.h>
#else
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#if defined(__linux__)
#include <asm/byteorder.h>
#include <linux/types.h>
#include <endian.h>
#elif defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__)
#include <machine/endian.h>
#endif
#endif

#define AF_SCAFFOLD 27
#define PF_SCAFFOLD AF_SCAFFOLD   /* include/linux/socket.h */

#define SCAFFOLD_PROTO_TCP 6
#define SCAFFOLD_PROTO_UDP 17

/* Ethernet protocol number */
#define ETH_P_SCAFFOLD 0x0809

/* IP Protocol number */
#define IPPROTO_SCAFFOLD 144

struct service_id {
        union { 
                uint8_t	u_id8[2];
                uint16_t u_id16;
                /* uint32_t u_sid32[]; */
        } u_id;
#define s_sid u_id.u_id8
#define s_sid16 u_id.u_id16
#define s_sid32 u_id.u_id32
};

struct sockaddr_sf {
        sa_family_t sf_family;
        uint16_t sf_flags;
        struct service_id sf_srvid;
};

struct sock_id {
        uint16_t s_id;
};

struct host_addr {
        uint8_t s_addr;
};

struct as_addr {
        uint8_t s_addr;
};

struct flow_id {
        union {
                struct {
                        struct as_addr as;
                        struct host_addr host;
                        struct sock_id sock;
                } fl_s;
#define fl_as fl_s.as
#define fl_host fl_s.host
#define fl_sock fl_s.sock
                struct in_addr fl_ip;
        };
};

static inline const char *service_id_to_str(struct service_id *srvid)
{
        static char str[20];
        snprintf(str, 20, "%u", ntohs(srvid->s_sid16));
        return str;
}

static inline const char *socket_id_to_str(struct sock_id *sockid)
{
        static char str[20];
        snprintf(str, 20, "%u", ntohs(sockid->s_id));
        return str;
}

enum scaffold_packet_type { 
        SCAFFOLD_PKT_DATA = 1,
        SCAFFOLD_PKT_SYN,
        SCAFFOLD_PKT_SYNACK,
        SCAFFOLD_PKT_ACK,
        SCAFFOLD_PKT_RESET,
        SCAFFOLD_PKT_CLOSE,
        SCAFFOLD_PKT_MIG,
        SCAFFOLD_PKT_RSYN,
        SCAFFOLD_PKT_MIGDATA,
        SCAFFOLD_PKT_RSYNACK
};

struct scaffold_hdr {
        uint16_t length;  
        uint8_t flags;
        uint8_t protocol;
#define SFH_FIN	0x01
#define SFH_SYN	0x02
#define SFH_RST	0x04
#define SFH_MIG	0x08
#define SFH_ACK	0x10
#define SFH_RSYN	0x20
        struct sock_id src_sid;
        struct sock_id dst_sid;
};

/* Generic extension header */
struct scaffold_hdr_ext {
        uint8_t type;
        uint8_t flags;
        uint16_t length;
};

#define SCAFFOLD_FLOW_EXT 1

struct scaffold_flow_ext {
        uint8_t type;
        uint8_t flags;
        uint16_t length;
        struct flow_id src;
        struct flow_id dst;
};

#define SCAFFOLD_SERVICE_EXT 2

struct scaffold_service_ext {
        uint8_t type;
        uint8_t flags;
        uint16_t length;
        struct service_id src_srvid;
        struct service_id dst_srvid;
};

#define SCAFFOLD_DATA_EXT 3

struct scaffold_data_ext {
        uint8_t type;
        uint8_t flags;
        uint16_t length;
        uint32_t seqno;
};


#endif /* _SCAFFOLD_H */
