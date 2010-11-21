/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _NET_H_
#define _NET_H_

#include <scaffold/platform.h>

#if defined(OS_LINUX_KERNEL)
#include <linux/net.h>
#else
#include <linux/socket.h>
#include <linux/net.h>
#include "wait.h"

struct sock;
struct net;

struct socket_wq {
	wait_queue_head_t	wait;
};

struct socket {
        unsigned long           flags;
        socket_state            state;
        struct socket_wq        *wq;
        short                   type;
        struct sock             *sk;
        const struct proto_ops  *ops;
};

/* Dummy module struct for kernel compatibility */
#define THIS_MODULE (NULL)

struct module {
        char name[1];
};

#define __user 

struct kiocb;
struct sockaddr;
struct msghdr;
struct file;
struct poll_table_struct;

struct proto_ops {
	int		family;
        struct module   *owner;
	int		(*release)   (struct socket *sock);
	int		(*bind)	     (struct socket *sock,
				      struct sockaddr *myaddr,
				      int sockaddr_len);
	int		(*connect)   (struct socket *sock,
				      struct sockaddr *vaddr,
				      int sockaddr_len, int flags);
	int		(*accept)    (struct socket *sock,
				      struct socket *newsock, int flags);
	int		(*getname)   (struct socket *sock,
				      struct sockaddr *addr,
				      int *sockaddr_len, int peer);
	unsigned int	(*poll)	     (struct file *file, struct socket *sock,
				      struct poll_table_struct *wait);
	int		(*ioctl)     (struct socket *sock, unsigned int cmd,
				      unsigned long arg);
	int		(*listen)    (struct socket *sock, int len);
	int		(*shutdown)  (struct socket *sock, int flags);
	int		(*setsockopt)(struct socket *sock, int level,
				      int optname, char __user *optval, unsigned int optlen);
	int		(*getsockopt)(struct socket *sock, int level,
				      int optname, char __user *optval, int __user *optlen);
	int		(*sendmsg)   (struct kiocb *iocb, struct socket *sock,
				      struct msghdr *m, size_t total_len);
	int		(*recvmsg)   (struct kiocb *iocb, struct socket *sock,
				      struct msghdr *m, size_t total_len,
				      int flags);
};

struct net_proto_family {
	int		family;
        struct module   *owner;
	int		(*create)(struct net *net, struct socket *sock,
				  int protocol, int kern);
};

int sock_register(const struct net_proto_family *fam);
void sock_unregister(int family);
int sock_create(int family, int type, int proto,
                struct socket **res);
void sock_release(struct socket *sock);

/* 
   The struct net implements network namespaces in the kernel. We just
   use a dummy net here for compatibility with the kernel API.
 */
struct net {
	char dummy;
};

extern struct net init_net;

#endif /* OS_LINUX_KERNEL */

#endif /* _NET_H_ */
