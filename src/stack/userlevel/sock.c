/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/debug.h>
#include <serval/lock.h>
#include <serval/timer.h>
#include <serval/sock.h>
#include <serval/skbuff.h>
#include <serval/wait.h>
#include <serval/net.h>
#include <serval/bitops.h>
#include <pthread.h>

#define RCV_BUF_DEFAULT 1000
#define SND_BUF_DEFAULT 1000

LIST_HEAD(proto_list);
DEFINE_RWLOCK(proto_list_lock);

/* From linux asm-generic/poll.h. Seems to be non-standardized */
#ifndef POLLRDNORM 
#define POLLRDNORM      0x0040
#endif
#ifndef POLLRDBAND
#define POLLRDBAND      0x0080
#endif
#ifndef POLLWRNORM
#define POLLWRNORM      0x0100
#endif
#ifndef POLLWRBAND
#define POLLWRBAND      0x0200
#endif
#ifndef POLLMSG
#define POLLMSG         0x0400
#endif
#ifndef POLLREMOVE
#define POLLREMOVE      0x1000
#endif
#ifndef POLLRDHUP
#define POLLRDHUP       0x2000
#endif

static void sock_def_destruct(struct sock *sk)
{

}

static void sock_def_wakeup(struct sock *sk)
{
        struct socket_wq *wq = sk->sk_wq;

        read_lock(&sk->sk_callback_lock);
        if (wq_has_sleeper(wq))
                wake_up_interruptible_all(&wq->wait);
        read_unlock(&sk->sk_callback_lock);
}
/*
static void sock_def_error_report(struct sock *sk)
{
        struct socket_wq *wq = sk->sk_wq;

        read_lock(&sk->sk_callback_lock);
        if (wq_has_sleeper(wq))
                wake_up_interruptible_poll(&wq->wait, POLLERR);
        sk_wake_async(sk, SOCK_WAKE_IO, POLL_ERR);
        read_unlock(&sk->sk_callback_lock);
}
*/
static void sock_def_readable(struct sock *sk, int bytes)
{
        struct socket_wq *wq = sk->sk_wq;

        read_lock(&sk->sk_callback_lock);
        if (wq_has_sleeper(wq))
                wake_up_interruptible_sync_poll(&wq->wait, POLLIN |
                                                POLLRDNORM | POLLRDBAND);
        sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_IN);
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
	sk->sk_rcvbuf		=	RCV_BUF_DEFAULT;
	sk->sk_sndbuf		=       SND_BUF_DEFAULT;
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
	sk->sk_destruct		=	sock_def_destruct;
	sk->sk_backlog_rcv	=	sock_def_backlog_rcv;
	sk->sk_write_pending	=	0;
	sk->sk_rcvtimeo		=	MAX_SCHEDULE_TIMEOUT;
	sk->sk_sndtimeo		=	MAX_SCHEDULE_TIMEOUT;

        rwlock_init(&sk->sk_callback_lock);
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
                
                //spin_lock_init(&newsk->sk_dst_lock);
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

int sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
        return 0;
}

int sock_queue_err_skb(struct sock *sk, struct sk_buff *skb)
{
        return 0;
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
	gfp_t gfp_mask;
	long timeo;
	int err;

	gfp_mask = sk->sk_allocation;

	timeo = sock_sndtimeo(sk, noblock);

	while (1) {
		err = sock_error(sk);
		if (err != 0)
			goto failure;

		err = -EPIPE;
		if (sk->sk_shutdown & SEND_SHUTDOWN)
			goto failure;

		if (atomic_read(&sk->sk_wmem_alloc) < sk->sk_sndbuf) {
			skb = alloc_skb(header_len);
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
