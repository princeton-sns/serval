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

#define SERVAL_ASSERT(predicate) __ASSERT__(predicate, __LINE__)

#define __PASTE__(a,b) a##b
#define __ASSERT__(predicate,line)                                 \
        typedef char __PASTE__(assertion_failed_,line)[2*!!(predicate)-1];

#define AF_SERVAL 28
#define PF_SERVAL AF_SERVAL   /* include/linux/socket.h */

#define SERVAL_PROTO_TCP 6
#define SERVAL_PROTO_UDP 17

/* IP Protocol number */
#define IPPROTO_SERVAL 144

/* The serviceID is in the format of a reversed FQDN that allows for
   easy longest-prefix matching, for example: "com.mydomain.service".

   Although a domain name may be up to 253 characters long, we cannot
   support full length names due to the limited size of a sockaddr
   structure. We cannot exceed sizeof(struct sockaddr_storage), which
   is 128 bytes in the Linux kernel. In addition, we want to be able
   to optionally pass two sockaddrs in a socket call; a serviceID
   (sockaddr_sv) followed by an IP address (sockaddr_in) for service
   resolver hints. Thus these two must not exceed 128 bytes when
   concatenated, or socket calls will return an error.
 */
#define SERVICE_ID_MIN_LEN (2)
#define SERVICE_ID_MAX_LEN (105)

struct service_id {
        char s_sid[SERVICE_ID_MAX_LEN+1];
};

#define SERVICE_ID_BITS(s) (strlen((s)->s_sid) << 3)

SERVAL_ASSERT(sizeof(struct service_id) == 106)

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
        struct service_id sv_srvid;
};

SERVAL_ASSERT(sizeof(struct sockaddr_sv) == 108)

#define SERVAL_ADDRSTRLEN SERVICE_ID_MAX_LEN

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

static inline int service_id_cmp(const struct service_id *id1,
                                 const struct service_id *id2)
{
        return strcmp(id1->s_sid, id2->s_sid);
}

static inline struct service_id *service_id_copy(struct service_id *s1,
                                                 struct service_id *s2)
{
        size_t i;
        
        for (i = 0; i < SERVICE_ID_MAX_LEN && s2->s_sid[i] != '\0'; i++)
                s1->s_sid[i] = s2->s_sid[i];
        
        s1->s_sid[i] = '\0';
        
        return s1;
}

static inline char *strrev(char *str, size_t n)
{
        size_t i;
    
        for (i = 0; i < n/2; i++) {
                str[i] ^= str[n-1-i];
                str[n-1-i] ^= str[i];
                str[i] ^= str[n-1-i];
        }
    
        return str;
}

static inline char *strrev_delim(char delim, char *str, size_t n)
{
        size_t i, j;
    
        for (i = 0, j = 0; i <= n; i++) {
                if (str[i] == delim || i == n) {
                        strrev(&str[j], i-j);
                        j = i + 1;
                }
        }
        return str;
}

static inline int fqdn_valid_char(char c)
{
        if ((c >= '0' && c <= '9') || 
            (c >= 'A' && c <= 'Z') || 
            (c >= 'a' && c <= 'z') ||
            c == '.' || 
            c == '-')
                return 1;
        return 0;
}

enum wildcard_pos {
        WP_NONE,
        WP_BEGINNING,
        WP_END,
};

/**
 * Copy an FQDN and verify its format at the same time. Optionally
 * allow a wildcard char ('*') at the beginning (1) or end of the
 * string (2), as indicated by the wildcard_pos argument.
 *
 * @dst the destination buffer.
 * @fqdn the source buffer.
 * @n the size of the destination buffer.
 * @wildcard_pos the position of the wildcard, where:
 * WP_NONE = do not accept a wildcard.
 * WP_BEGINNING = accept wildcard at beginning.
 * WP_END = accept wildcard at the end.
 *
 * @Returns: 0 if string has bad format, or number of characters
 * copied.
 */
static inline int fqdn_copy(char *dst, const char *fqdn, 
                            size_t n, enum wildcard_pos wp)
{
        int i;
        
        for (i = 0; (size_t)i < n && fqdn[i] != '\0'; i++) {
                /* Check for valid char, but also accept wildcard */
                
                if (fqdn[i] == '*') {
                        if (wp == WP_NONE || 
                            (wp == WP_BEGINNING && i != 0 && fqdn[1] != '.') ||
                            (wp == WP_END && fqdn[i+1] != '\0'))
                                return 0;
                } else if (!fqdn_valid_char(fqdn[i]))
                        return 0;
                dst[i] = fqdn[i];
        }
        
        if ((size_t)i < n)
                dst[i] = '\0';

        return i;
}

/**
 * Verify that a string contains only valid FQDN characters.
 * @Returns: The index of the first invalid character (this would be
 * the index of the string termination character, '\0', in case the
 * whole string is valid).
 *
 * @len is and optional argument that may return the length of the
 * string (including invalid characters).
 */
static inline size_t fqdn_verify_length(const char *fqdn, size_t *len)
{
        long i = -1;
        size_t l = 0;
                
        while (fqdn[l] != '\0') {
                if (!fqdn_valid_char(fqdn[l]) && i == -1)
                        i = l;
                l++;
        }

        if (i == -1)
                i = l;
        
        if (len)
                *len = l;

        return i;
}

/**
 * Verify that a string contains only valid FQDN characters.
 */
static inline int fqdn_verify(const char *fqdn)
{
        size_t len = 0;
        return (fqdn_verify_length(fqdn, &len) == len);
}

/**
 * Verify that a string contains only valid FQDN characters, but also
 * accept a wildcard char (*) at the beginning, e.g., as such:
 * "*.example.com"
 */
static inline int fqdn_verify_wildcard(const char *fqdn)
{
        size_t len = 0, i = 0;
        
        if (!fqdn)
                return -1;

        if (fqdn[0] == '*' && fqdn[1] == '.')
                fqdn++;
        
        i = fqdn_verify_length(fqdn, &len);
        
        if (i == len)
                return 1;

        return 0;
}

/**
 * Reverse a fully qualified domain name string (we do not require the
 * FQDN to end with a dot).
 */
 static inline int fqdn_reverse(const char *fqdn, char *out, 
                                enum wildcard_pos wp)
{
        int len = fqdn_copy(out, fqdn, SERVICE_ID_MAX_LEN, wp);
        
        if (len <= 0)
                return len;
        
        if (strrev_delim('.', strrev(out, len), len))
                return 1;
        
        return -1;
}

/**
 * Verify that a serviceID has valid format.
 */
static inline int service_id_verify(const struct service_id *srvid)
{
        size_t len = 0, i;

        if (!srvid)
                return -1;

        i = fqdn_verify_length(srvid->s_sid, &len);
        
        return (i == len && len > 0 && len <= SERVICE_ID_MAX_LEN);
}

/**
 * Verify that a serviceID has valid format, but also accept a
 * wildcard (*) at the end, e.g., as such: "com.example.*".
 */
static inline int service_id_verify_wildcard(const struct service_id *srvid)
{
        size_t len = 0, i;
        
        if (!srvid)
                return -1;
        
        /* A serviceID is a reverse FQDN, so there may be a wildcard
           at the end of the string. */
        i = fqdn_verify_length(srvid->s_sid, &len);

        /* Accept wildcard at the end */
        if ((i + 1) == len && srvid->s_sid[i] == '*')
                i++;

        return (i == len && len > 0 && len <= SERVICE_ID_MAX_LEN);
}

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
        return srvid->s_sid;
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
 * Converts a serviceID to string presentation format. Equivalent to
 * inet_ntop().
 */
static inline const char *serval_ntop(const void *src, char *dst, size_t len)
{
        if (fqdn_reverse((char *)src, dst, WP_END) == 1)
                return dst;
        return NULL;
}

/**
 * Converts a string in presentation format to a serviceID. Equivalent
 * to inet_pton().
 */
static inline int serval_pton(const char *src, void *dst)
{
        if (strlen(src) > SERVICE_ID_MAX_LEN)
                return -1;
        
        memset(dst, 0, sizeof(struct service_id));

        return fqdn_reverse(src, (char *)dst, WP_BEGINNING);
}

struct sal_hdr {
        struct flow_id src_flowid;
        struct flow_id dst_flowid;
        uint8_t  shl; /* SAL Header Length (in number of 32-bit words) */
        uint8_t  protocol;
        uint16_t check;
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct sal_hdr) == 12)

#define SAL_HEADER_LEN                          \
        sizeof(struct sal_hdr)

/* Generic extension header */
struct sal_ext {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t	res:4,
		type:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	uint8_t	type:4,
                res:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
        uint8_t length;
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct sal_ext) == 2)

/*
  These defines can be used for convenient access to the fields in the
  base extension in extensions below. */
#define ext_type exthdr.type
#define ext_length exthdr.length

#define SAL_EXT_FIRST(sh) \
        ((struct sal_ext *)((char *)sh + SAL_HEADER_LEN))

#define SAL_EXT_NEXT(ext)                                               \
        ((struct sal_ext *)((ext->type == SAL_PAD_EXT ?                 \
                             (char *)ext + 1 :                          \
                             (char *)ext + ext->length)))

#define SAL_EXT_LEN(ext)                                \
        (ext->type == SAL_PAD_EXT ?                     \
         sizeof(struct sal_pad_ext) : ext->length)

enum sal_ext_type {
        SAL_PAD_EXT = 0,
        SAL_CONTROL_EXT = 1,
        SAL_SERVICE_EXT,
        SAL_ADDRESS_EXT,
        SAL_SOURCE_EXT,
        __SAL_EXT_TYPE_MAX,
};

struct sal_pad_ext {
        uint8_t pad[1];
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct sal_pad_ext) == 1);

#define SAL_NONCE_SIZE 8

struct sal_control_ext {
        struct sal_ext exthdr;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t	res1:2,
                fin:1,
                rst:1,
                nack:1,
                ack:1,
                rsyn:1,
		syn:1;
#elif defined (__BIG_ENDIAN_BITFIELD)
	uint8_t	syn:1,
                rsyn:1,
  		ack:1,
                nack:1,
                rst:1,
                fin:1,
                res1:2;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
        uint8_t  res2;
        uint32_t verno;
        uint32_t ackno;
        uint8_t  nonce[SAL_NONCE_SIZE];
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct sal_control_ext) == 20)

#define SAL_CONTROL_EXT_LEN                     \
        sizeof(struct sal_control_ext)

struct sal_service_ext {
        struct sal_ext exthdr;
        struct service_id srvid;
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct sal_service_ext) == 108)

#define SAL_SERVICE_EXT_LEN(sid)             \
        (sizeof(struct sal_ext) +            \
         strlen((sid)->s_sid) + 1)

#define SAL_SERVICE_EXT_MIN_LEN                 \
        (sizeof(struct sal_ext) + 3)

#define SAL_SERVICE_EXT_MAX_LEN                 \
        sizeof(struct sal_service_ext)

struct sal_address_ext {
        struct sal_ext exthdr;
        uint16_t res;
        uint32_t verno;
        uint32_t ackno;
        struct net_addr addrs[0];
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct sal_address_ext) == 12)

#define SAL_ADDRESS_EXT_LEN                     \
        sizeof(struct sal_address_ext)

struct sal_source_ext {
        struct sal_ext exthdr;
        uint16_t res;
        uint8_t source[0];
} __attribute__((packed));

SERVAL_ASSERT(sizeof(struct sal_source_ext) == 4)

#define SAL_SOURCE_EXT_MIN_LEN                  \
        (sizeof(struct sal_source_ext) + 4)

#define SAL_SOURCE_EXT_MAX_LEN                          \
        (sizeof(struct sal_source_ext) + (20 * 4))

#define __SAL_SOURCE_EXT_LEN(sz)             \
        (sz + sizeof(struct sal_source_ext))

#define SAL_SOURCE_EXT_LEN __SAL_SOURCE_EXT_LEN(4)

#define SAL_SOURCE_EXT_NUM_ADDRS(ext)                                \
        (((ext)->ext_length - sizeof(struct sal_source_ext)) / 4) 

#define SAL_SOURCE_EXT_GET_ADDR(ext, n)      \
        (&(ext)->source[n*4])

#define SAL_SOURCE_EXT_GET_LAST_ADDR(ext)                            \
        (&(ext)->source[(SAL_SOURCE_EXT_NUM_ADDRS(ext)-1)*4])

#endif /* _SERVAL_H */
