/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _PLATFORM_H
#define _PLATFORM_H

#if defined(__KERNEL__)
#include <linux/kernel.h>
#include <linux/version.h>
#include <net/sock.h>
#define MALLOC(sz, prio) kmalloc(sz, prio)
#define FREE(m) kfree(m)

typedef uint32_t socklen_t;

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
static inline wait_queue_head_t *sk_sleep(struct sock *sk)
{
        return sk->sk_sleep;
}

static inline struct net *sock_net(struct sock *sk)
{
        return sk->sk_net;
}

#endif /* LINUX_VERSION_CODE */

#else /* User-level */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <libio.h>

#define LINUX_VERSION_CODE 132643 /* corresponds to 2.6.35 */
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))

typedef unsigned char gfp_t;
#define GFP_KERNEL 0
#define GFP_ATOMIC 1
#define MALLOC(sz, prio) malloc(sz)
#define FREE(m) free(m)

#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)

#define __init
#define __exit

#define panic(name) { int *foo = NULL; *foo = 1; } /* Cause a sefault */

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

int memcpy_toiovec(struct iovec *iov, unsigned char *kdata, int len);
int memcpy_fromiovec(unsigned char *kdata, struct iovec *iov, int len);

#endif /* __KERNEL__ */

const char *mac_ntop(const void *src, char *dst, socklen_t size);
int mac_pton(const char *src, void *dst);
const char *get_strtime(void);

#include "debug.h"

#endif /* _PLATFORM_H */
