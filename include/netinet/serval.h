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
#define HAS_SOCKADDR_LEN 1
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

#define SERVAL_ASSERT(predicate) __ASSERT(predicate, __LINE__)

#define __PASTE(a,b) a##b
#define __ASSERT(predicate,line)                                 \
        typedef char __PASTE(assertion_failed_,line)[2*!!(predicate)-1];

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

SERVAL_ASSERT(sizeof(struct service_id) == 32)

#define SERVICE_ID_MAX_PREFIX_BITS ((unsigned)(sizeof(struct service_id)<<3))

enum sv_service_flags {
        /* bottom 2 bits reserved for scope - resolution and
         * registration */
        SVSF_HOST_SCOPE = 0,
        SVSF_LOCAL_SCOPE = 1,
        SVSF_DOMAIN_SCOPE = 2,
        SVSF_GLOBAL_SCOPE = 3,
        SVSF_STRICT_SCOPE = 1 << 3, /* interpret scope strictly, by
                                     * default, scopes are
                                     * inclusive */
        SVSF_ANYCAST = 1 << 4, /* service instance can be anycasted, 0
                                * = backup or strict match */
        SVSF_MULTICAST = 1 << 5, /* service instance can be
                                  * multicasted */
        SVSF_INVALID = 0xFF
};

struct sockaddr_sv {
#if defined(HAS_SOCKADDR_LEN)
        uint8_t sv_len;
#endif
        sa_family_t sv_family;
        uint8_t sv_flags;
        uint8_t sv_prefix_bits;
        struct service_id sv_srvid;
};

SERVAL_ASSERT(sizeof(struct sockaddr_sv) == 36)

#define SERVAL_ADDRSTRLEN 80

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

SERVAL_ASSERT(sizeof(struct flow_id) == 4)

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

/**
 * Convert an ASCII character (char) to a byte integer. Returns -1 on
 * error.
 */
static inline int hextobyte(const char c)
{
        int value = -1;
        
        if (c >= '0' && c <= '9') {
                value = (c - '0');
        } else {
                char d = c | 0x20;
                
                if (d >= 'a' && d <= 'f')
                        value = d - 'a' + 10;
        }
        return value;
}

/**
 * Convert a hexadecimal string to a byte array. Returns 1 on success,
 * and 0 if the source string is not a valid hexadecimal string.
 */
static inline int serval_hexton(const char *src,
                                size_t src_len,
                                void *dst,
                                size_t dst_len)
{
        unsigned char *ptr = (unsigned char *)dst;

        while (*src != '\0' && dst_len-- && src_len--) {
                int value = hextobyte(*src++);

                if (value == -1)
                        return 0;
                
                value *= 16;
                        
                if (*src != '\0' && src_len--) {
                        int ret = hextobyte(*src++);

                        if (ret == -1)
                                return 0;
                        
                        value += ret;
                }
                *ptr++ = value;
        }
        
        return 1;
}

/*
 * Convert a byte array to a hexadecimal string. Will always
 * null-terminate.
 */
static inline char *serval_ntohex(const void *src,
                                  size_t src_len,
                                  char *dst,
                                  size_t dst_len)
{
        static const char hex[] = "0123456789abcdef";
        char *dst_ptr = (char *)dst;
        const unsigned char *src_ptr = (const unsigned char *)src;

        while (src_len && dst_len > 1) {
                *dst_ptr++ = hex[*src_ptr >> 4];

                if (--dst_len > 1) {
                        *dst_ptr++ = hex[*src_ptr++ & 0xf];
                        dst_len--;
                }
                src_len--;
        }
        
        if (dst_len)
                *dst_ptr = '\0';

        return dst;
}

static inline const char *service_id_to_str(const struct service_id *srvid)
{
        static char str[65*2];
        static int i = 0;
        i = (i + 1) % 2;
        return serval_ntohex(srvid, sizeof(*srvid),
                             &str[i*sizeof(str)/2], sizeof(str)/2);
}

static inline const char *flow_id_to_str(const struct flow_id *flowid)
{
        static char str[22];
        static int i = 0;
        i = (i + 1) % 2;
        snprintf(&str[i*sizeof(str)/2], sizeof(str)/2, 
                 "%u", ntohl(flowid->s_id32));
        return &str[i*sizeof(str)/2];
}

/**
 * Converts a binary service ID to string presentation
 * format. Equivalent to inet_ntop().
 */
static inline const char *serval_ntop(const void *src, char *dst, size_t len)
{
        return serval_ntohex(src, sizeof(struct service_id), dst, len);
}

/**
 * Converts a string in presentation format to a binary service
 * ID. Equivalent to inet_pton().
 */
static inline int serval_pton(const char *src, void *dst)
{
        return serval_hexton(src, 64, dst, sizeof(struct service_id));
}

struct serval_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t	res1:3,
                rsyn:1,
                fin:1,
                rst:1,
                ack:1,
		syn:1;
#elif defined (__BIG_ENDIAN_BITFIELD)
	uint8_t	syn:1,
  		ack:1,
                rst:1,
                fin:1,
                rsyn:1,
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
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct serval_hdr) == 16)

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
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct serval_ext) == 2)

/*
  These defines can be used for convenient access to the fields in the
  base extension in extensions below. */
#define sv_ext_type exthdr.type
#define sv_ext_flags exthdr.flags
#define sv_ext_length exthdr.length

#define SERVAL_EXT_FIRST(sh) \
        ((struct serval_ext *)((char *)sh + sizeof(struct serval_hdr)))

#define SERVAL_EXT_NEXT(ext) \
        ((struct serval_ext *)((char *)ext + ext->length))

enum serval_ext_type {
        SERVAL_CONNECTION_EXT = 1,
        SERVAL_CONTROL_EXT,
        SERVAL_SERVICE_EXT,
        SERVAL_DESCRIPTION_EXT,
        SERVAL_SOURCE_EXT,
        SERVAL_MIGRATE_EXT,
        __SERVAL_EXT_TYPE_MAX,
};

struct serval_connection_ext {
        struct serval_ext exthdr;
        uint32_t seqno;
        uint32_t ackno;
        uint8_t  nonce[8];
        struct service_id srvid;
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct serval_connection_ext) == 50)

#define SERVAL_NONCE_SIZE 8

struct serval_control_ext {
        struct serval_ext exthdr;
        uint32_t seqno;
        uint32_t ackno;
        uint8_t  nonce[8];
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct serval_control_ext) == 18)

struct serval_service_ext {
        struct serval_ext exthdr;
        struct service_id src_srvid;
        struct service_id dst_srvid;
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct serval_service_ext) == 66)

struct serval_description_ext {
        struct serval_ext exthdr;
        struct net_addr addrs[0];
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct serval_description_ext) == 2)

struct serval_source_ext {
        struct serval_ext exthdr;
        uint8_t source[0];
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct serval_source_ext) == 2)

struct serval_migrate_ext {
        struct serval_ext exthdr;
        uint32_t seqno;
        uint32_t ackno;
        uint8_t nonce[8];
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct serval_migrate_ext) == 18)

#define __SERVAL_SOURCE_EXT_LEN(sz)             \
        (sz + sizeof(struct serval_source_ext))

#define SERVAL_SOURCE_EXT_LEN __SERVAL_SOURCE_EXT_LEN(4)

#define SERVAL_SOURCE_EXT_NUM_ADDRS(ext)                                \
        (((ext)->sv_ext_length - sizeof(struct serval_source_ext)) / 4) 

#define SERVAL_SOURCE_EXT_GET_ADDR(ext, n)      \
        (&(ext)->source[n*4])

#define SERVAL_SOURCE_EXT_GET_LAST_ADDR(ext)                            \
        (&(ext)->source[(SERVAL_SOURCE_EXT_NUM_ADDRS(ext)-1)*4])

#endif /* _SERVAL_H */
