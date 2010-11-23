/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SCAFFOLD_H
#define _SCAFFOLD_H

#include <linux/types.h>
#include <asm/byteorder.h>

#if defined(__KERNEL__)
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
#include <endian.h>
#elif defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__)
#include <sys/endian.h>
#endif
#endif

#define AF_SCAFFOLD 27
#define PF_SCAFFOLD AF_SCAFFOLD   /* include/linux/socket.h */

#define SF_PROTO_TCP 6
#define SF_PROTO_UDP 17

/* Ethernet protocol number */
#define ETH_P_SCAFFOLD 0x0809

/* IP Protocol number */
#define IPPROTO_SCAFFOLD 43

enum scaffold_sock_state { 
        SF_NEW = 0, 
        SF_REGISTER,
        SF_UNBOUND,
        SF_REQUEST,
        SF_LISTEN,
        SF_RESPOND,
        SF_BOUND,
        SF_CLOSING,
        SF_TIMEWAIT,
        SF_CLOSED,
        SF_UNREGISTER,
        SF_MIGRATE,
        SF_RECONNECT,
        SF_RRESPOND,
        SF_GARBAGE,
        /* TCP only */
        TCP_FINWAIT1,
        TCP_FINWAIT2,
        TCP_CLOSEWAIT,
        TCP_LASTACK,
        TCP_SIMCLOSE,
};

#define SCAFFOLD_SOCK_STATE_MIN (0)
#define SCAFFOLD_SOCK_STATE_MAX (TCP_SIMCLOSE)

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

static inline const char *service_id_to_str(struct service_id *srvid)
{
        static char str[20];
        snprintf(str, 20, "%u", ntohs(srvid->s_sid16));
        return str;
}

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

enum scaffold_packet_type { 
        PKT_TYPE_DATA = 0, 
        PKT_TYPE_SYN, 
        PKT_TYPE_SYNACK, 
        PKT_TYPE_ACK, 
        PKT_TYPE_RESET, 
        PKT_TYPE_CLOSE,
        PKT_TYPE_MIG,
        PKT_TYPE_RSYN, 
        PKT_TYPE_MIGDATA, 
        PKT_TYPE_RSYNACK
};

#endif /* _SCAFFOLD_H */
