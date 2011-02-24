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
                        uint8_t un_ss[4];
                        uint8_t un_local[4];
                        uint8_t un_group[4];
                        uint8_t un_selfcert[20];
                };
                uint8_t	un_id8[32];
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

struct sockaddr_sv {
        sa_family_t sv_family;
        uint8_t sv_flags;
        uint8_t sv_prefix_bits;
        struct service_id sv_srvid;
};

struct flow_id {
        uint32_t s_id;
};

struct net_addr {
        union {
                /* IPv6 address too big to fit in serval_skb_cb
                   together with 256-bit service_id atm. */
                /* struct in6_addr net_ip6; */
                struct in_addr un_ip;
                unsigned char un_raw[4];
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

struct serval_hdr {
        uint16_t length;  
        uint8_t flags;
#define SVH_FIN	        0x01
#define SVH_SYN	        0x02
#define SVH_RST	        0x04
#define SVH_MIG	        0x08
#define SVH_ACK	        0x10
#define SVH_RSYN	0x20
        uint8_t protocol;
        struct flow_id src_flowid;
        struct flow_id dst_flowid;
};

/* Generic extension header */
struct serval_ext {
        uint8_t type;
        uint8_t flags;
        uint16_t length;
};

#define SERVAL_CONNECTION_EXT 1

struct serval_connection_ext {
        uint8_t type;
        uint8_t flags;
        uint16_t length;
        uint32_t seqno;
        uint32_t ackno;
        uint8_t nonce[8];
        struct service_id srvid;
};

#define SERVAL_CONTROL_EXT 2

#define SERVAL_NONCE_SIZE 8

struct serval_control_ext {
        uint8_t type;
        uint8_t flags;
        uint16_t length;
        uint32_t seqno;
        uint32_t ackno;
        uint8_t nonce[SERVAL_NONCE_SIZE];
};

#define SERVAL_SERVICE_EXT 3

struct serval_service_ext {
        uint8_t type;
        uint8_t flags;
        uint16_t length;
        struct service_id src_srvid;
        struct service_id dst_srvid;
};

#define SERVAL_DESCRIPTION_EXT 4

struct serval_description_ext {
        uint8_t type;
        uint8_t flags;
        uint16_t length;
        struct net_addr addrs[0];
};


#endif /* _SERVAL_H */
