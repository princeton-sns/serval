/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SCAFFOLD_H
#define _SCAFFOLD_H

#include <linux/types.h>
#include <asm/byteorder.h>

#if defined(__KERNEL__)
#include <linux/socket.h>
#else
#include <stdint.h>
#include <sys/socket.h>
#endif

#define AF_SCAFFOLD 27
#define PF_SCAFFOLD AF_SCAFFOLD   /* include/linux/socket.h */

#define SF_PROTO_TCP 6
#define SF_PROTO_UDP 17

/* Ethernet protocol number */
#define ETH_P_SCAFFOLD 0x0809

/* IP Protocol number */
#define IPPROTO_SCAFFOLD 43

enum scaffold_state { 
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
        
        // TCP only
        TCP_FINWAIT1,
        TCP_FINWAIT2,
        TCP_CLOSEWAIT,
        TCP_LASTACK,
        TCP_SIMCLOSE,
};

struct service_id {
        union { 
                uint8_t	u_sid8[20];
                uint16_t u_sid16[10];
                uint32_t u_sid32[5];
        } sid_u;
#define s_sid sid_u.u_oid8
#define s_sid16 sid_u.u_oid16
#define s_sid32 sid_u.u_oid32
};

struct sock_id {
        uint16_t sid_id;
};

struct sockaddr_sf {
        sa_family_t ssf_family;
        struct service_id ssf_sid;
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
