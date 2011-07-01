/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SERVAL_H
#define _SERVAL_H

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

#define AF_SERVAL 27
#define PF_SERVAL AF_SERVAL   /* include/linux/socket.h */

#define SERVAL_PROTO_TCP 6
#define SERVAL_PROTO_UDP 17

/* Ethernet protocol number */
#define ETH_P_SERVAL 0x0809

/* IP Protocol number */
#define IPPROTO_SERVAL 144

struct service_id {
        union { 
                struct {
                        __u8 un_ss[4];
                        __u8 un_local[4];
                        __u8 un_group[4];
                        __u8 un_selfcert[20];
                };
                __u8	un_id8[32];
                __u16   un_id16[16];
                __u32   un_id32[8];
        } srv_un;
#define s_ss srv_un.un_ss;
#define s_local srv_un.un_local;
#define s_group srv_un.un_group;
#define s_sfc srv_un.un_selfcert;
#define s_sid srv_un.un_id8
#define s_sid16 srv_un.un_id16
#define s_sid32 srv_un.un_id32
};

enum sv_service_flags {
    //bottom 2 bits reserved for scope - resolution and registration
    SVSF_HOST_SCOPE = 0,
    SVSF_LOCAL_SCOPE = 1,
    SVSF_DOMAIN_SCOPE = 2,
    SVSF_GLOBAL_SCOPE = 3,
    SVSF_STRICT_SCOPE = 1 << 4, //interpret scope strictly, by default, scopes are inclusive
    SVSF_ANYCAST = 1 << 5, //service instance can be anycasted, 0 = backup or strict match only
    SVSF_MULTICAST = 1 << 6, //service instance can be multicasted
    SVSF_INVALID = 0xFF
};

struct sockaddr_sv {
        sa_family_t sv_family;
        __u8 sv_flags;
        __u8 sv_prefix_bits;
        struct service_id sv_srvid;
};

struct flow_id {
        union {
                __u8 s_id8[4];
                __be16 s_id16[2];
                __be32 s_id;       
        };
};

struct net_addr {
        union {
                /* IPv6 address too big to fit in serval_skb_cb
                   together with 256-bit service_id atm. */
                /* struct in6_addr net_ip6; */
                struct in_addr un_ip;
                __u8 un_raw[4];
        } net_un;
#define net_ip net_un.un_ip
#define net_raw net_un.un_raw
};

static inline const char *__hexdump(const void *data, int datalen, 
                                    char *buf, int buflen)
{
        const unsigned char *h = (const unsigned char *)data;
        int len = 0;

        while (datalen > 0 && len < buflen) {
                len += snprintf(buf + len, buflen - len, 
                                "%02x",
                                *h++);

                if (datalen && datalen % 2 && datalen != 1)
                        len += snprintf(buf + len, buflen - len, " ");
                datalen--;
        }

        return buf;
}

static inline const char *service_id_to_str(const struct service_id *srvid)
{
        static char str[82];
        return __hexdump(srvid, sizeof(*srvid), str, 82);  
}

static inline const char *flow_id_to_str(const struct flow_id *flowid)
{
        static char str[11];
        snprintf(str, 11, "%u", ntohl(flowid->s_id));
        return str;
}

enum serval_packet_type {
        SERVAL_PKT_DATA = 0,
        SERVAL_PKT_SYN,
        SERVAL_PKT_RESET,
        SERVAL_PKT_CLOSE,
        SERVAL_PKT_MIG,
        SERVAL_PKT_RSYN,
        SERVAL_PKT_MIGDATA,
        __SERVAL_PKT_MAX = SERVAL_PKT_MIGDATA, 
};

struct serval_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	res1:3,
                ack:1,
		type:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	type:4,
  		ack:1,
                res1:3;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
        __u8    protocol;
        __sum16 check;
        __be16  length;       
        struct flow_id src_flowid;
        struct flow_id dst_flowid;
};

/* Generic extension header */
struct serval_ext {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	flags:4,
		type:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	type:4,
                flags:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
        __u8 length;
};
/*
  These defines can be used for convenient access to the fields in the
  base extension in extensions below. */
#define sv_ext_type exthdr.type
#define sv_ext_flags exthdr.flags
#define sv_ext_length exthdr.length

#define SERVAL_CONNECTION_EXT 1

struct serval_connection_ext {
        struct serval_ext exthdr;
        __be32 seqno;
        __be32 ackno;
        __u8 nonce[8];
        struct service_id srvid;
};

#define SERVAL_CONTROL_EXT 2

#define SERVAL_NONCE_SIZE 8

struct serval_control_ext {
        struct serval_ext exthdr;
        __be32 seqno;
        __be32 ackno;
        __u8 nonce[8];
};

#define SERVAL_SERVICE_EXT 3

struct serval_service_ext {
        struct serval_ext exthdr;
        struct service_id src_srvid;
        struct service_id dst_srvid;
};

#define SERVAL_DESCRIPTION_EXT 4

struct serval_description_ext {
        struct serval_ext exthdr;
        struct net_addr addrs[0];
};

#define SERVAL_SOURCE_EXT 5

struct serval_source_ext {
        struct serval_ext exthdr;
        __u8 source[0];
};

#endif /* _SERVAL_H */
