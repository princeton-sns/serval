/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/debug.h>
#include <serval/lock.h>
#include <serval/timer.h>
#include <serval/sock.h>
#include <serval/skbuff.h>
#include <serval/wait.h>
#include <serval/net.h>
#include <serval/bitops.h>
#include <serval/netdevice.h>
#include <pthread.h>
#include <serval_sock.h>
#include "client.h"

#define _SK_MEM_PACKETS		256
#define _SK_MEM_OVERHEAD	(sizeof(struct sk_buff) + 256)
#define SK_WMEM_MAX		(_SK_MEM_OVERHEAD * _SK_MEM_PACKETS)
#define SK_RMEM_MAX		(_SK_MEM_OVERHEAD * _SK_MEM_PACKETS)

/* Run time adjustable parameters. */
__u32 sysctl_wmem_max __read_mostly = SK_WMEM_MAX;
__u32 sysctl_rmem_max __read_mostly = SK_RMEM_MAX;
__u32 sysctl_wmem_default __read_mostly = SK_WMEM_MAX;
__u32 sysctl_rmem_default __read_mostly = SK_RMEM_MAX;

#if defined(OS_BSD)
#define UIO_MAXIOV 1024
#endif

/* Maximal space eaten by iovec or ancilliary data plus some space */
int sysctl_optmem_max __read_mostly = sizeof(unsigned long)*(2*UIO_MAXIOV+512);

struct list_head proto_list = { &proto_list, &proto_list };
DEFINE_RWLOCK(proto_list_lock);

static void sock_def_destruct(struct sock *sk)
{

}

static void sock_def_wakeup(struct sock *sk)
{
        struct socket_wq *wq = sk->sk_wq;
        read_lock(&sk->sk_callback_lock);
        if (wq_has_sleeper(wq)) {
                wake_up_interruptible_all(&wq->wait);
        }
        read_unlock(&sk->sk_callback_lock);
}

static void sock_def_error_report(struct sock *sk)
{
        struct socket_wq *wq = sk->sk_wq;

        read_lock(&sk->sk_callback_lock);
        if (wq_has_sleeper(wq))
                wake_up_interruptible_poll(&wq->wait, POLLERR);
        sk_wake_async(sk, SOCK_WAKE_IO, POLL_ERR);
        read_unlock(&sk->sk_callback_lock);
}

static void sock_def_readable(struct sock *sk, int bytes)
{
        /* TODO should differentiate between write and read sleepers
         * in the wait queue */
        struct socket_wq *wq = sk->sk_wq;

        read_lock(&sk->sk_callback_lock);
        if (wq_has_sleeper(wq))
                wake_up_interruptible_sync_poll(&wq->wait, POLLIN |
                                                POLLRDNORM | POLLRDBAND);

        sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_IN);

        if (skb_queue_len(&sk->sk_receive_queue) && 
            !client_has_data(sk->sk_socket->client))
                client_signal_raise(sk->sk_socket->client, CLIENT_SIG_READ);
        
        read_unlock(&sk->sk_callback_lock);
}

static void sock_def_write_space(struct sock *sk)
{        
        struct socket_wq *wq = sk->sk_wq;
        
        read_lock(&sk->sk_callback_lock);
        if ((atomic_read(&sk->sk_wmem_alloc) << 1) <= sk->sk_sndbuf) {
                if (wq_has_sleeper(sk->sk_wq))
                        wake_up_interruptible_sync_poll(&wq->wait, POLLOUT |
                                                        POLLWRNORM | POLLWRBAND);

                /* Should agree with poll, otherwise some programs break */
                if (sock_writeable(sk))
                        sk_wake_async(sk, SOCK_WAKE_SPACE, POLL_OUT);
        }
        read_unlock(&sk->sk_callback_lock);
}

static int sock_def_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

static inline void sock_lock_init(struct sock *sk)
{
	spin_lock_init(&(sk)->sk_lock.slock);
        sk->sk_lock.owned = 0;
}

void sock_init_data(struct socket *sock, struct sock *sk)
{
	skb_queue_head_init(&sk->sk_receive_queue);
	skb_queue_head_init(&sk->sk_write_queue);
        skb_queue_head_init(&sk->sk_error_queue);

	sk->sk_send_head	=	NULL;
	init_timer(&sk->sk_timer);
	sk->sk_net              =       &init_net;
	sk->sk_rcvbuf		=	SK_RMEM_MAX;
	sk->sk_sndbuf		=       SK_WMEM_MAX;
	sk->sk_state		=	0;
	sk_set_socket(sk, sock);
	sock_set_flag(sk, SOCK_ZAPPED);
        
        if (sock) {
		sk->sk_type	=	sock->type;
		sk->sk_wq	=	sock->wq;
		sock->sk	=	sk;
	} else
		sk->sk_wq	=	NULL;

	sk->sk_state_change	=	sock_def_wakeup;
	sk->sk_data_ready	=	sock_def_readable;
	sk->sk_write_space	=	sock_def_write_space;
	sk->sk_error_report	=	sock_def_error_report;
	sk->sk_destruct		=	sock_def_destruct;
	sk->sk_backlog_rcv	=	sock_def_backlog_rcv;
	sk->sk_write_pending	=	0;
	sk->sk_rcvtimeo		=	MAX_SCHEDULE_TIMEOUT;
	sk->sk_sndtimeo		=	MAX_SCHEDULE_TIMEOUT;
        sk->sk_bound_dev_if     =       0;

        spin_lock_init(&sk->sk_dst_lock);
        rwlock_init(&sk->sk_callback_lock);
#if defined(OS_LINUX_KERNEL)
	/*
	 * Before updating sk_refcnt, we must commit prior changes to memory
	 * (Documentation/RCU/rculist_nulls.txt for details)
	 */
	smp_wmb();
#endif
	atomic_set(&sk->sk_refcnt, 1);
	atomic_set(&sk->sk_drops, 0);
}

/*
 * Copy all fields from osk to nsk but nsk->sk_refcnt must not change yet,
 * even temporarly, because of RCU lookups. sk_node should also be left as is.
 */
static void sock_copy(struct sock *nsk, const struct sock *osk)
{
        memcpy(&nsk->sk_copy_start, &osk->sk_copy_start,
               osk->sk_prot->obj_size - offsetof(struct sock, sk_copy_start));
}

static struct sock *sk_prot_alloc(struct proto *prot, gfp_t priority, int family)
{
	struct sock *sk;

	sk = (struct sock *)malloc(prot->obj_size);

	if (sk) {
                memset(sk, 0, prot->obj_size);
	}

	return sk;
}

#define get_net(n) n

static void sock_net_set(struct sock *sk, struct net *net)
{
	/* TODO: make sure this is ok. Should be since we have no
	   network namespaces anyway. */
	sk->sk_net = net;
}

void sk_setup_caps(struct sock *sk, struct dst_entry *dst)
{
        /*
	__sk_dst_set(sk, dst);
	sk->sk_route_caps = dst->dev->features;
	if (sk->sk_route_caps & NETIF_F_GSO)
		sk->sk_route_caps |= NETIF_F_GSO_SOFTWARE;
	sk->sk_route_caps &= ~sk->sk_route_nocaps;
	if (sk_can_gso(sk)) {
		if (dst->header_len) {
			sk->sk_route_caps &= ~NETIF_F_GSO_MASK;
		} else {
			sk->sk_route_caps |= NETIF_F_SG | NETIF_F_HW_CSUM;
			sk->sk_gso_max_size = dst->dev->gso_max_size;
		}
	}
        */
}

struct sock *sk_alloc(struct net *net, int family, gfp_t priority,
		      struct proto *prot)
{
	struct sock *sk = NULL;

	sk = sk_prot_alloc(prot, priority, family);

	if (sk) {
		sk->sk_family = family;
		/*
		 * See comment in struct sock definition to understand
		 * why we need sk_prot_creator -acme
		 */
		sk->sk_prot = prot;
		sock_lock_init(sk);
		sock_net_set(sk, get_net(net));
		atomic_set(&sk->sk_wmem_alloc, 1);
	}

	return sk;
}

struct dst_entry *__sk_dst_check(struct sock *sk, u32 cookie)
{
	struct dst_entry *dst = __sk_dst_get(sk);
        
        /*
	if (dst && dst->obsolete && dst->ops->check(dst, cookie) == NULL) {
		sk_tx_queue_clear(sk);
		rcu_assign_pointer(sk->sk_dst_cache, NULL);
		dst_release(dst);
		return NULL;
	}
        */
	return dst;
}

struct dst_entry *sk_dst_check(struct sock *sk, u32 cookie)
{
	struct dst_entry *dst = sk_dst_get(sk);
        /*
	if (dst && dst->obsolete && dst->ops->check(dst, cookie) == NULL) {
		sk_dst_reset(sk);
		dst_release(dst);
		return NULL;
	}
        */
	return dst;
}

struct sock *sk_clone(const struct sock *sk, const gfp_t priority)
{
        struct sock *newsk;
        
        newsk = sk_prot_alloc(sk->sk_prot, priority, sk->sk_family);

        LOG_DBG("socket clone %p\n", newsk);

        if (newsk != NULL) {
                
                sock_copy(newsk, sk);

                /* SANITY */
                //get_net(sock_net(newsk));
                sk_node_init(&newsk->sk_node);
                sock_lock_init(newsk);
                bh_lock_sock(newsk);
                newsk->sk_backlog.head = newsk->sk_backlog.tail = NULL;
                newsk->sk_backlog.len = 0;

                atomic_set(&newsk->sk_rmem_alloc, 0);
                /*
                 * sk_wmem_alloc set to one (see sk_free() and sock_wfree())
                 */
                atomic_set(&newsk->sk_wmem_alloc, 1);
                atomic_set(&newsk->sk_omem_alloc, 0);
                skb_queue_head_init(&newsk->sk_receive_queue);
                skb_queue_head_init(&newsk->sk_error_queue);
                skb_queue_head_init(&newsk->sk_write_queue);
                
                spin_lock_init(&newsk->sk_dst_lock);
                rwlock_init(&newsk->sk_callback_lock);
                /*
                  lockdep_set_class_and_name(&newsk->sk_callback_lock,
                                           af_callback_keys + newsk->sk_family,
                                           af_family_clock_key_strings[newsk->sk_family]);
                */
                //newsk->sk_dst_cache= NULL;
                newsk->sk_wmem_queued= 0;
                //newsk->sk_forward_alloc = 0;
                newsk->sk_send_head = NULL;
                //newsk->sk_userlocks = sk->sk_userlocks & ~SOCK_BINDPORT_LOCK;

                sock_reset_flag(newsk, SOCK_DONE);
                
                newsk->sk_err   = 0;
                newsk->sk_priority = 0;
      
                atomic_set(&newsk->sk_refcnt, 2);

                /*
                 * Increment the counter in the same struct proto as the master
                 * sock (sk_refcnt_debug_inc uses newsk->sk_prot->socks, that
                 * is the same as sk->sk_prot->socks, as this field was copied
                 * with memcpy).
                 *
                 * This _changes_ the previous behaviour, where
                 * tcp_create_openreq_child always was incrementing the
                 * equivalent to tcp_prot->socks (inet_sock_nr), so this have
                 * to be taken into account in all callers. -acme
                 */
                //sk_refcnt_debug_inc(newsk);
                sk_set_socket(newsk, NULL);
                newsk->sk_wq = NULL;
                
                /*
                if (newsk->sk_prot->sockets_allocated)
                        percpu_counter_inc(newsk->sk_prot->sockets_allocated);
                */
                /*
                if (sock_flag(newsk, SOCK_TIMESTAMP) ||
                    sock_flag(newsk, SOCK_TIMESTAMPING_RX_SOFTWARE))
                        net_enable_timestamp();
                */
        }
//out:
        return newsk;
}

static void __sk_free(struct sock *sk)
{
	if (sk->sk_destruct)
		sk->sk_destruct(sk);
        
        free(sk);
}

void sk_free(struct sock *sk)

{        
        /*
	 * We substract one from sk_wmem_alloc and can know if
	 * some packets are still in some tx queue.
	 * If not null, sock_wfree() will call __sk_free(sk) later
	 */
	if (atomic_dec_and_test(&sk->sk_wmem_alloc))
		__sk_free(sk);
}

void sock_wfree(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	unsigned int len = skb->truesize;

	if (!sock_flag(sk, SOCK_USE_WRITE_QUEUE)) {
		/*
		 * Keep a reference on sk_wmem_alloc, this will be released
		 * after sk_write_space() call
		 */
		atomic_sub(len - 1, &sk->sk_wmem_alloc);
		sk->sk_write_space(sk);
		len = 1;
	}
	/*
	 * if sk_wmem_alloc reaches 0, we must finish what sk_free()
	 * could not do because of in-flight packets
	 */
	if (atomic_sub_and_test(len, &sk->sk_wmem_alloc))
		__sk_free(sk);
}

/*
 * Read buffer destructor automatically called from kfree_skb.
 */
void sock_rfree(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;

	atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
	/* sk_mem_uncharge(skb->sk, skb->truesize); */
}

void sk_common_release(struct sock *sk)
{
	if (sk->sk_prot->destroy)
		sk->sk_prot->destroy(sk);

	sk->sk_prot->unhash(sk);

	sock_orphan(sk);
	sock_put(sk);
}

int proto_register(struct proto *prot, int ignore)
{
	write_lock(&proto_list_lock);
	list_add(&prot->node, &proto_list);
	/* assign_proto_idx(prot); */
	write_unlock(&proto_list_lock);

	return 0;
}

void proto_unregister(struct proto *prot)
{
        write_lock(&proto_list_lock);
	/* release_proto_idx(prot); */
	list_del(&prot->node);
	write_unlock(&proto_list_lock);
}

/*
 *	Get a socket option on an socket.
 *
 *	FIX: POSIX 1003.1g is very ambiguous here. It states that
 *	asynchronous errors should be reported by getsockopt. We assume
 *	this means if you specify SO_ERROR (otherwise whats the point of it).
 */
int sock_common_getsockopt(struct socket *sock, int level, int optname,
			   char __user *optval, int __user *optlen)
{
	return 0;
}

/*
 *	Set socket options on an inet socket.
 */
int sock_common_setsockopt(struct socket *sock, int level, int optname,
			   char __user *optval, unsigned int optlen)
{
	return 0;
}

/* 
   Wait for data in receive queue, return 1 if data exists, else 0.
 */
int sk_wait_data(struct sock *sk, long *timeo)
{
        int rc;
        DEFINE_WAIT(wait);

        prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
        set_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);
        rc = sk_wait_event(sk, timeo, !skb_queue_empty(&sk->sk_receive_queue));
        clear_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);
        finish_wait(sk_sleep(sk), &wait);
        return rc;
}

/**
 *	__sk_mem_schedule - increase sk_forward_alloc and memory_allocated
 *	@sk: socket
 *	@size: memory size to allocate
 *	@kind: allocation type
 *
 *	If kind is SK_MEM_SEND, it means wmem allocation. Otherwise it means
 *	rmem allocation. This function assumes that protocols which have
 *	memory_pressure use sk_wmem_queued as write buffer accounting.
 */
int __sk_mem_schedule(struct sock *sk, int size, int kind)
{
	struct proto *prot = sk->sk_prot;
	int amt = sk_mem_pages(size);
	int allocated;

	sk->sk_forward_alloc += amt * SK_MEM_QUANTUM;
	allocated = atomic_add_return(amt, prot->memory_allocated);

	/* Under limit. */
	if (allocated <= prot->sysctl_mem[0]) {
		if (prot->memory_pressure && *prot->memory_pressure)
			*prot->memory_pressure = 0;
		return 1;
	}

	/* Under pressure. */
	if (allocated > prot->sysctl_mem[1])
		if (prot->enter_memory_pressure)
			prot->enter_memory_pressure(sk);

	/* Over hard limit. */
	if (allocated > prot->sysctl_mem[2])
		goto suppress_allocation;

	/* guarantee minimum buffer size under pressure */
	if (kind == SK_MEM_RECV) {
		if (atomic_read(&sk->sk_rmem_alloc) < prot->sysctl_rmem[0])
			return 1;
	} else { /* SK_MEM_SEND */
		if (sk->sk_type == SOCK_STREAM) {
			if (sk->sk_wmem_queued < prot->sysctl_wmem[0])
				return 1;
		} else if (atomic_read(&sk->sk_wmem_alloc) <
			   prot->sysctl_wmem[0])
				return 1;
	}

#if defined(OS_LINUX_KERNEL)
        /* TODO: Implement this for user level */
	if (prot->memory_pressure) {
		int alloc;

		if (!*prot->memory_pressure)
			return 1;
		alloc = percpu_counter_read_positive(prot->sockets_allocated);
		if (prot->sysctl_mem[2] > alloc *
		    sk_mem_pages(sk->sk_wmem_queued +
				 atomic_read(&sk->sk_rmem_alloc) +
				 sk->sk_forward_alloc))
			return 1;
	}
#endif

suppress_allocation:

	if (kind == SK_MEM_SEND && sk->sk_type == SOCK_STREAM) {
		sk_stream_moderate_sndbuf(sk);

		/* Fail only if socket is _under_ its sndbuf.
		 * In this case we cannot block, so that we have to fail.
		 */
		if (sk->sk_wmem_queued + size >= sk->sk_sndbuf)
			return 1;
	}

	/* Alas. Undo changes. */
	sk->sk_forward_alloc -= amt * SK_MEM_QUANTUM;
	atomic_sub(amt, prot->memory_allocated);
	return 0;
}

/**
 *	__sk_reclaim - reclaim memory_allocated
 *	@sk: socket
 */
void __sk_mem_reclaim(struct sock *sk)
{
	struct proto *prot = sk->sk_prot;

	atomic_sub(sk->sk_forward_alloc >> SK_MEM_QUANTUM_SHIFT,
		   prot->memory_allocated);
	sk->sk_forward_alloc &= SK_MEM_QUANTUM - 1;

	if (prot->memory_pressure && *prot->memory_pressure &&
	    (atomic_read(prot->memory_allocated) < prot->sysctl_mem[0]))
		*prot->memory_pressure = 0;
}


void sk_reset_timer(struct sock *sk, struct timer_list* timer,
                    unsigned long expires)
{
        if (!mod_timer(timer, expires))
                sock_hold(sk);
}

void sk_stop_timer(struct sock *sk, struct timer_list* timer)
{
        if (timer_pending(timer) && del_timer(timer))
		__sock_put(sk);
}

int sk_receive_skb(struct sock *sk, struct sk_buff *skb, const int nested)
{
	int rc = NET_RX_SUCCESS;

        /*
          if (sk_filter(sk, skb))
		goto discard_and_relse;
        */
	skb->dev = NULL;

	if (sk_rcvqueues_full(sk, skb)) {
		atomic_inc(&sk->sk_drops);
		goto discard_and_relse;
	}
	if (nested)
		bh_lock_sock_nested(sk);
	else
		bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		/*
		 * trylock + unlock semantics:
		 */
		//mutex_acquire(&sk->sk_lock.dep_map, 0, 1, _RET_IP_);

		rc = sk_backlog_rcv(sk, skb);

		//mutex_release(&sk->sk_lock.dep_map, 1, _RET_IP_);
	} else if (sk_add_backlog(sk, skb)) {
		bh_unlock_sock(sk);
		atomic_inc(&sk->sk_drops);
		goto discard_and_relse;
	}

	bh_unlock_sock(sk);
out:
	sock_put(sk);
	return rc;
discard_and_relse:
	kfree_skb(skb);
	goto out;
}

int sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	int skb_len;
	struct sk_buff_head *list = &sk->sk_receive_queue;

	/* Cast sk->rcvbuf to unsigned... It's pointless, but reduces
	   number of warnings when compiling with -W --ANK
	 */
	if (atomic_read(&sk->sk_rmem_alloc) + skb->truesize >=
	    (unsigned)sk->sk_rcvbuf) {
		atomic_inc(&sk->sk_drops);
		return -ENOMEM;
	}

        /*
	err = sk_filter(sk, skb);
	if (err)
		return err;
        
        */
        if (!sk_rmem_schedule(sk, skb->truesize)) {
		atomic_inc(&sk->sk_drops);
		return -ENOBUFS;
	}

	LOG_DBG("Queuing in socket for receive\n");
	skb->dev = NULL;
	skb_set_owner_r(skb, sk);

	/* Cache the SKB length before we tack it onto the receive
	 * queue.  Once it is added it no longer belongs to us and
	 * may be freed by other threads of control pulling packets
	 * from the queue.
	 */
	skb_len = skb->len;

	/* we escape from rcu protected region, make sure we dont leak
	 * a norefcounted dst
	 */
	/* skb_dst_force(skb); */

	skb->dropcount = atomic_read(&sk->sk_drops);
	__skb_queue_tail(list, skb);

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_data_ready(sk, skb_len);

	return 0;
}

int sock_queue_err_skb(struct sock *sk, struct sk_buff *skb)
{
        return 0;
}

void sk_reset_txq(struct sock *sk)
{
	sk_tx_queue_clear(sk);
}

/*
 * Allocate a memory block from the socket's option memory buffer.
 */
void *sock_kmalloc(struct sock *sk, int size, gfp_t priority)
{
	if (1 /*(unsigned)size <= sysctl_optmem_max &&
                atomic_read(&sk->sk_omem_alloc) + size < sysctl_optmem_max */) {
		void *mem;
		/* First do the add, to avoid the race if kmalloc
		 * might sleep.
		 */
		atomic_add(size, &sk->sk_omem_alloc);
		mem = malloc(size);
		if (mem)
			return mem;
		atomic_sub(size, &sk->sk_omem_alloc);
	}
	return NULL;
}

void sock_kfree_s(struct sock *sk, void *mem, int size)
{
	free(mem);
	atomic_sub(size, &sk->sk_omem_alloc);
}

/* It is almost wait_for_tcp_memory minus release_sock/lock_sock.
   I think, these locks should be removed for datagram sockets.
 */
static long sock_wait_for_wmem(struct sock *sk, long timeo)
{
	DEFINE_WAIT(wait);

	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);
	for (;;) {
		if (!timeo)
			break;
		if (signal_pending(current))
			break;
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
		if (atomic_read(&sk->sk_wmem_alloc) < sk->sk_sndbuf)
			break;
		if (sk->sk_shutdown & SEND_SHUTDOWN)
			break;
		if (sk->sk_err)
			break;
		timeo = schedule_timeout(timeo);
	}
	finish_wait(sk_sleep(sk), &wait);
	return timeo;
}

struct sk_buff *sock_alloc_send_pskb(struct sock *sk,
                                     unsigned long header_len,
                                     unsigned long data_len,
                                     int noblock,
                                     int *errcode)
{
        struct sk_buff *skb;
	long timeo;
	int err;

	timeo = sock_sndtimeo(sk, noblock);

	while (1) {
		err = sock_error(sk);
		if (err != 0)
			goto failure;

		err = -EPIPE;
		if (sk->sk_shutdown & SEND_SHUTDOWN)
			goto failure;

		if (atomic_read(&sk->sk_wmem_alloc) < sk->sk_sndbuf) {
			skb = alloc_skb(header_len, 0);
			if (skb) {
				/* Full success... */
				break;
			}
			err = -ENOBUFS;
			goto failure;
		}
		set_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		err = -EAGAIN;
		if (!timeo)
			goto failure;
		if (signal_pending(current))
			goto interrupted;
		timeo = sock_wait_for_wmem(sk, timeo);
	}

	skb_set_owner_w(skb, sk);
	return skb;

interrupted:
	err = sock_intr_errno(timeo);
failure:
	*errcode = err;
	return NULL;
}

struct sk_buff *sock_alloc_send_skb(struct sock *sk, unsigned long size,
				    int noblock, int *errcode)
{
	return sock_alloc_send_pskb(sk, size, 0, noblock, errcode);
}

void lock_sock(struct sock *sk)
{
        spin_lock(&sk->sk_lock.slock);
        sk->sk_lock.owned = 1;
}

/* process backlog of received packets when socket lock is
 * released. */ 
void __release_sock(struct sock *sk)
{
        struct sk_buff *skb = sk->sk_backlog.head;

        do {
                sk->sk_backlog.head = sk->sk_backlog.tail = NULL;
                bh_unlock_sock(sk);

                do {
                        struct sk_buff *next = skb->next;

                        skb->next = NULL;
                        sk_backlog_rcv(sk, skb);

                        /*
                         * We are in process context here with softirqs
                         * disabled, use cond_resched_softirq() to preempt.
                         * This is safe to do because we've taken the backlog
                         * queue private:
                         */
                        //cond_resched_softirq();

                        skb = next;
                } while (skb != NULL);

                bh_lock_sock(sk);
        } while ((skb = sk->sk_backlog.head) != NULL);

        /*
         * Doing the zeroing here guarantee we can not loop forever
         * while a wild producer attempts to flood us.
         */
        sk->sk_backlog.len = 0;
}

void release_sock(struct sock *sk)
{
        
        sk->sk_lock.owned = 0;
        spin_unlock(&sk->sk_lock.slock);
}

