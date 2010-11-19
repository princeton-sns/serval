/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SOCK_H_
#define _SOCK_H_

#if defined(__KERNEL__)
#include <net/sock.h>
#else
#include <scaffold/platform.h>
#include <scaffold/atomic.h>
#include <scaffold/lock.h>
#include <scaffold/list.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include "skbuff.h"
#include "net.h"
#include "wait.h"
#include "timer.h"

struct sk_buff;
struct proto;

#define SHUTDOWN_MASK	3
#define RCV_SHUTDOWN	1
#define SEND_SHUTDOWN	2

struct sock {
	unsigned short          sk_family;
        struct hlist_node	sk_node;
	atomic_t		sk_refcnt;
        unsigned int		sk_shutdown  : 2,
				sk_no_check  : 2,
				sk_userlocks : 4,
				sk_protocol  : 8,
				sk_type      : 16;
        unsigned int	        sk_hash;
	struct socket_wq  	*sk_wq;
        unsigned char	        sk_state;
	int			sk_rcvbuf;
	int			sk_tx_queue_mapping;
        spinlock_t              sk_lock;
        struct net              *sk_net;
        struct proto            *sk_prot;
	atomic_t		sk_rmem_alloc;
	atomic_t		sk_wmem_alloc;
	atomic_t		sk_omem_alloc;
	atomic_t		sk_drops;
	unsigned short		sk_ack_backlog;
	unsigned short		sk_max_ack_backlog;
	int			sk_sndbuf;
	struct sk_buff_head	sk_receive_queue;
	struct sk_buff_head	sk_write_queue;
	int			sk_write_pending;
	unsigned long 		sk_flags;
	unsigned long	        sk_lingertime;
	rwlock_t		sk_callback_lock;
	long			sk_rcvtimeo;
	long			sk_sndtimeo;
	struct timer_list	sk_timer;
	struct socket		*sk_socket;
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
        struct module           *owner;
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

static inline int sock_no_getsockopt(struct socket *s, int a, 
                                     int b, char __user *c, int __user *d)
{
        return -1;
}

static inline int sock_no_setsockopt(struct socket *s, int a, int b, 
                                     char __user *c, unsigned int d)
{
        return -1;
}

extern int proto_register(struct proto *prot, int);
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

static inline void sk_tx_queue_set(struct sock *sk, int tx_queue)
{
	sk->sk_tx_queue_mapping = tx_queue;
}

static inline void sk_tx_queue_clear(struct sock *sk)
{
	sk->sk_tx_queue_mapping = -1;
}

static inline int sk_tx_queue_get(const struct sock *sk)
{
	return sk ? sk->sk_tx_queue_mapping : -1;
}

static inline void sk_set_socket(struct sock *sk, struct socket *sock)
{
	sk_tx_queue_clear(sk);
	sk->sk_socket = sock;
}

int sk_wait_data(struct sock *sk, long *timeo);

static inline int sock_writeable(const struct sock *sk) 
{
	return atomic_read(&sk->sk_wmem_alloc) < (sk->sk_sndbuf >> 1);
}

static inline long sock_rcvtimeo(const struct sock *sk, int noblock)
{
	return noblock ? 0 : sk->sk_rcvtimeo;
}

static inline long sock_sndtimeo(const struct sock *sk, int noblock)
{
	return noblock ? 0 : sk->sk_sndtimeo;
}


void sk_reset_timer(struct sock *sk, struct timer_list* timer,
                    unsigned long expires);
void sk_stop_timer(struct sock *sk, struct timer_list* timer);
int sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb);
int sock_queue_err_skb(struct sock *sk, struct sk_buff *skb);

static inline void sk_eat_skb(struct sock *sk, struct sk_buff *skb, int copied_early)
{
	__skb_unlink(skb, &sk->sk_receive_queue);
	__free_skb(skb);
}

static inline int sock_error(struct sock *sk)
{
        return 0;
}

static inline int sock_intr_errno(long timeo)
{
	return timeo == MAX_SCHEDULE_TIMEOUT ? -ERESTARTSYS : -EINTR;
}

void sock_wfree(struct sk_buff *skb);
void sock_rfree(struct sk_buff *skb);

static inline void skb_set_owner_w(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = sock_wfree;
	/*
	 * We used to take a refcount on sk, but following operation
	 * is enough to guarantee sk_free() wont free this sock until
	 * all in-flight packets are completed
	 */
	atomic_add(skb->truesize, &sk->sk_wmem_alloc);
}

static inline void skb_set_owner_r(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = sock_rfree;
	atomic_add(skb->truesize, &sk->sk_rmem_alloc);
	/* sk_mem_charge(sk, skb->truesize); */
}

void sock_init_data(struct socket *sock, struct sock *sk);

struct sock *sk_alloc(struct net *net, int family, gfp_t priority,
		      struct proto *prot);
void sk_free(struct sock *sk);

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

static inline wait_queue_head_t *sk_sleep(struct sock *sk)
{
        return sk->sk_wq ? &sk->sk_wq->wait : NULL;
}

static inline void sock_orphan(struct sock *sk)
{
	write_lock(&sk->sk_callback_lock);
	sock_set_flag(sk, SOCK_DEAD);
	sk_set_socket(sk, NULL);
	sk->sk_wq  = NULL;
	write_unlock(&sk->sk_callback_lock);
}

static inline void sock_graft(struct sock *sk, struct socket *parent)
{
	write_lock(&sk->sk_callback_lock);
	parent->sk = sk;
	sk_set_socket(sk, parent);
	write_unlock(&sk->sk_callback_lock);
}

void sk_common_release(struct sock *sk);

#endif /* __KERNEL__ */

#endif /* _SOCK_H_ */
