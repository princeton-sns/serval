/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SCAFFOLD_H
#define _SCAFFOLD_H

#include <linux/types.h>
#include <asm/byteorder.h>

#if defined(__KERNEL__)
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/string.h>
#else
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
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
                uint8_t	u_sid8[2];
                uint16_t u_sid16;
                /* uint32_t u_sid32[]; */
        } sid_u;
#define s_sid sid_u.u_sid8
#define s_sid16 sid_u.u_sid16
#define s_sid32 sid_u.u_sid32
};

static inline const char *service_id_to_str(struct service_id *srvid)
{
        static char str[20];
        snprintf(str, 20, "%u", ntohs(srvid->s_sid16));
        return str;
}

struct sockaddr_sf {
        sa_family_t ssf_family;
        struct service_id ssf_sid;
};

struct sock_id {
        uint16_t sid_id;
};

struct host_addr {
        uint8_t h_addr;
};

struct as_addr {
        uint8_t a_addr;
};

struct flow_id {
        union {
                struct {
                        struct as_addr as;
                        struct host_addr host;
                        struct sock_id sock;
                } __fl;
#define fl_as __fl.as
#define fl_host __fl.host
#define fl_sock __fl.sock
                struct in_addr fl_addr;
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

/*
typedef struct {
    uint16_t s_ssid;
} sf_ssid_t;

typedef struct { 
     uint8_t v; 
} sf_host_t;

typedef struct { 
     uint16_t v; 
} sf_sock_t;

struct flow_id {
        uint16_t ssid;
        uint32_t hostid;
        uint32_t sockid;
};

struct scaffold_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
        struct object_id soid;
        struct object_id doid;
        struct flow_id sflow;
        struct flow_id dflow;
        
}
*/
  
#endif /* _SCAFFOLD_H */
