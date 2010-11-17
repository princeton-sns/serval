/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _PLATFORM_H
#define _PLATFORM_H

#include "thread.h"
#include "lock.h"

#if defined(__KERNEL__)
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/time.h>
#include <net/sock.h>
#define MALLOC(sz, prio) kmalloc(sz, prio)
#define FREE(m) kfree(m)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
static inline wait_queue_head_t *sk_sleep(struct sock *sk)
{
        return sk->sk_sleep;
}

static inline struct net *sock_net(struct sock *sk)
{
        return sk->sk_net;
}

#endif

#else /* User-level */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
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

#endif /* __KERNEL__ */

static inline const char *get_strtime(void)
{
    static char buf[512];
#if defined(__KERNEL__)
    struct timeval now;

    do_gettimeofday(&now);
    sprintf(buf, "%ld.%03ld", now.tv_sec, now.tv_usec / 1000);
#else
    time_t now = time(0);
    struct tm p;
    localtime_r(&now, &p);
    strftime(buf, 512, "%b %e %T", &p);
#endif
    return buf;
}

#include "debug.h"

#endif /* _PLATFORM_H */
