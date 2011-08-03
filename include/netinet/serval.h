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

/* Setup byte order defines according to the Linux kernel */
#if __BYTE_ORDER == __BIG_ENDIAN
#ifdef __LITTLE_ENDIAN
#undef __LITTLE_ENDIAN
#endif
#define __BIG_ENDIAN_BITFIELD
#undef  __LITTLE_ENDIAN_BITFIELD
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#ifdef __BIG_ENDIAN
#undef __BIG_ENDIAN
#endif
#define __LITTLE_ENDIAN_BITFIELD
#undef __BIG_ENDIAN_BITFIELD
#else
#error "Could not figure out the byte order of this platform!"
#endif

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
                        uint8_t un_ss[4];
                        uint8_t un_local[4];
                        uint8_t un_group[4];
                        uint8_t un_selfcert[20];
                };
                uint8_t	 un_id8[32];
                uint16_t un_id16[16];
                uint32_t un_id32[8];
        } srv_un;
#define s_ss srv_un.un_ss;
#define s_local srv_un.un_local;
#define s_group srv_un.un_group;
#define s_sfc srv_un.un_selfcert;
#define s_sid srv_un.un_id8
#define s_sid16 srv_un.un_id16
#define s_sid32 srv_un.un_id32
};

#define SERVICE_ID_DEFAULT_PREFIX (sizeof(struct service_id)<<3)

enum sv_service_flags {
        /* bottom 2 bits reserved for scope - resolution and
         * registration */
        SVSF_HOST_SCOPE = 0,
        SVSF_LOCAL_SCOPE = 1,
        SVSF_DOMAIN_SCOPE = 2,
        SVSF_GLOBAL_SCOPE = 3,
        SVSF_STRICT_SCOPE = 1 << 4, /* interpret scope strictly, by
                                     * default, scopes are
                                     * inclusive */
        SVSF_ANYCAST = 1 << 5, /* service instance can be anycasted, 0
                                * = backup or strict match */
        SVSF_MULTICAST = 1 << 6, /* service instance can be
                                  * multicasted */
        SVSF_INVALID = 0xFF
};

struct sockaddr_sv {
        sa_family_t sv_family;
        uint8_t sv_flags;
        uint8_t sv_prefix_bits;
        struct service_id sv_srvid;
};

struct flow_id {
        union {
                uint8_t  un_id8[4];
                uint16_t un_id16[2];
                uint32_t un_id32;
        } fl_un;
#define s_id8  fl_un.un_id8
#define s_id16 fl_un.un_id16
#define s_id32 fl_un.un_id32
};

struct net_addr {
        union {
                /* IPv6 address too big to fit in serval_skb_cb
                   together with 256-bit service_id atm. */
                /* struct in6_addr net_ip6; */
                struct in_addr un_ip;
                uint8_t un_raw[4];
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
        static char str[82*2];
        static int i = 0;
        i = (i + 1) % 2;
        return __hexdump(srvid, sizeof(*srvid), &str[i*sizeof(str)/2], 82);  
}

static inline const char *flow_id_to_str(const struct flow_id *flowid)
{
        static char str[22];
        static int i = 0;
        i = (i + 1) % 2;
        snprintf(&str[i*sizeof(str)/2], 11, 
                 "%u", ntohl(flowid->s_id32));
        return &str[i*sizeof(str)/2];
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
	uint8_t	res1:3,
                ack:1,
		type:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	uint8_t	type:4,
  		ack:1,
                res1:3;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
        uint8_t  protocol;
        uint16_t check;
        uint16_t length;  
        uint16_t res2;       
        struct flow_id src_flowid;
        struct flow_id dst_flowid;
};

/* Generic extension header */
struct serval_ext {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t	flags:4,
		type:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	uint8_t	type:4,
                flags:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
        uint8_t length;
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
        uint32_t seqno;
        uint32_t ackno;
        uint8_t  nonce[8];
        struct service_id srvid;
};

#define SERVAL_CONTROL_EXT 2

#define SERVAL_NONCE_SIZE 8

struct serval_control_ext {
        struct serval_ext exthdr;
        uint32_t seqno;
        uint32_t ackno;
        uint8_t  nonce[8];
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
        uint8_t source[0];
};

#endif /* _SERVAL_H */
