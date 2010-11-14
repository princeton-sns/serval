/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SOCK_H_
#define _SOCK_H_

#if defined(__KERNEL__)
#include <net/sock.h>
#else
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <scaffold/atomic.h>
#include <scaffold/lock.h>
#include <scaffold/list.h>
#include "skbuff.h"
#include "net.h"

struct sk_buff;
struct proto;

struct sock {
	unsigned short          sk_family;
        struct hlist_node	sk_node;
	atomic_t		sk_refcnt;
	//int			skc_tx_queue_mapping;
        unsigned int	        sk_hash;
        unsigned char	        sk_state;
	int			sk_rcvbuf;
        spinlock_t              sk_lock;
        struct net              *sk_net;
        struct proto            *sk_prot;
	atomic_t		sk_rmem_alloc;
	atomic_t		sk_wmem_alloc;
	atomic_t		sk_omem_alloc;
	atomic_t		sk_drops;
	int			sk_sndbuf;
	struct sk_buff_head	sk_receive_queue;
	struct sk_buff_head	sk_write_queue;
	int			sk_write_pending;
	unsigned long 		sk_flags;
	unsigned long	        sk_lingertime;
	long			sk_rcvtimeo;
	long			sk_sndtimeo;
	//struct timer_list	sk_timer;
	struct sk_buff		*sk_send_head;

        void (*sk_destruct)(struct sock *sk);
	void (*sk_state_change)(struct sock *sk);
	void (*sk_data_ready)(struct sock *sk, int bytes);
	void (*sk_write_space)(struct sock *sk);
	/* void (*sk_error_report)(struct sock *sk); */
  	int (*sk_backlog_rcv)(struct sock *sk,
                              struct sk_buff *skb);  
};

struct kiocb;
#define __user 

struct proto {
	void			(*close)(struct sock *sk, 
					long timeout);
	int			(*connect)(struct sock *sk,
				        struct sockaddr *uaddr, 
					int addr_len);
	int			(*disconnect)(struct sock *sk, int flags);

	struct sock *		(*accept) (struct sock *sk, int flags, int *err);

	int			(*ioctl)(struct sock *sk, int cmd,
					 unsigned long arg);
	int			(*init)(struct sock *sk);
	void			(*destroy)(struct sock *sk);
	void			(*shutdown)(struct sock *sk, int how);
	int			(*setsockopt)(struct sock *sk, int level, 
					int optname, char __user *optval,
					unsigned int optlen);
	int			(*getsockopt)(struct sock *sk, int level, 
					int optname, char __user *optval, 
					int __user *option);  	 
	int			(*sendmsg)(struct kiocb *iocb, struct sock *sk,
					   struct msghdr *msg, size_t len);
	int			(*recvmsg)(struct kiocb *iocb, struct sock *sk,
					   struct msghdr *msg,
					size_t len, int noblock, int flags, 
					int *addr_len);
	int			(*bind)(struct sock *sk, 
					struct sockaddr *uaddr, int addr_len);

	int			(*backlog_rcv) (struct sock *sk, 
						struct sk_buff *skb);

	/* Keeping track of sk's, looking them up, and port selection methods. */
	void			(*hash)(struct sock *sk);
	void			(*unhash)(struct sock *sk);
	int			(*get_port)(struct sock *sk, unsigned short snum);

	unsigned int		obj_size;
	char			name[32];

	struct list_head	node;
};

extern int proto_register(struct proto *prot, int *);
extern void proto_unregister(struct proto *prot);

enum sock_flags {
	SOCK_DEAD,
	SOCK_DONE,
	SOCK_URGINLINE,
	SOCK_KEEPOPEN,
	SOCK_LINGER,
	SOCK_DESTROY,
	SOCK_BROADCAST,
	SOCK_TIMESTAMP,
	SOCK_ZAPPED,
	SOCK_USE_WRITE_QUEUE, /* whether to call sk->sk_write_space in sock_wfree */
};

#define sock_net(s) ((s)->sk_net)

struct sock *sk_alloc(struct net *net, int family, gfp_t priority,
		      struct proto *prot);

static inline void sk_free(struct sock *sk)
{
        if (sk->sk_destruct)
                sk->sk_destruct(sk);
        free(sk);
}

static inline void sock_hold(struct sock *sk)
{
        atomic_inc(&sk->sk_refcnt);
}

static inline void sock_put(struct sock *sk)
{
        if (atomic_dec_and_test(&sk->sk_refcnt))
                sk_free(sk);
}

static inline void lock_sock(struct sock *sk)
{
        spin_lock(&sk->sk_lock);
}

static inline void release_sock(struct sock *sk)
{
        spin_unlock(&sk->sk_lock);
}

static inline void sock_set_flag(struct sock *sk, enum sock_flags flag)
{
        sk->sk_flags |= (0x1 << flag);
}

static inline void sock_reset_flag(struct sock *sk, enum sock_flags flag)
{
        sk->sk_flags &= (flag ^ -1UL);
}

static inline int sock_flag(struct sock *sk, enum sock_flags flag)
{
	return sk->sk_flags & (0x1 << flag);
}

#endif /* __KERNEL__ */

#endif /* _SOCK_H_ */
