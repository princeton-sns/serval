/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _PLATFORM_H
#define _PLATFORM_H

/* Detect platform */
#if defined(__unix__)
#define OS_UNIX 1
#if !defined(__KERNEL__)
#define OS_USER 1
#endif
#endif

#if defined(__linux__)
#define OS_LINUX 1
#if defined(__KERNEL__)
#define OS_KERNEL 1
#define OS_LINUX_KERNEL 1
#else
#define OS_USER 1
#endif
#endif /* OS_LINUX */

#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__APPLE__)
#define OS_BSD 1
#define OS_USER 1
#endif

#if defined(__APPLE__)
#define OS_MACOSX 1
#define OS_USER 1
#endif

/* TODO: Detect these in configure */
#define HAVE_LIBIO 1
#define HAVE_PPOLL 1
#define HAVE_PSELECT 1

#if defined(OS_ANDROID)
#undef OS_KERNEL
#undef HAVE_LIBIO
#undef HAVE_PPOLL
#undef HAVE_PSELECT
#define HAVE_OFFSETOF 1
#endif

#if defined(OS_LINUX_KERNEL)
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
#endif /* OS_LINUX_KERNEL */

#if defined(OS_USER)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#if defined(OS_LINUX)
#include <endian.h>
#elif defined(OS_BSD)
#include <sys/endian.h>
#endif
#if HAVE_LIBIO
#include <libio.h>
#endif

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

#if !HAVE_OFFSETOF
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

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

#if !defined(HAVE_PPOLL)
#include <poll.h>
#include <sys/select.h>
#include <signal.h>

int ppoll(struct pollfd fds[], nfds_t nfds, struct timespec *timeout, sigset_t *set);

#endif /* OS_ANDROID */

#endif /* OS_USER */

const char *mac_ntop(const void *src, char *dst, size_t size);
int mac_pton(const char *src, void *dst);
const char *get_strtime(void);

#include "debug.h"

#endif /* _PLATFORM_H */
