/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <serval/platform.h>
#include <serval/list.h>
#include <serval/lock.h>
#include <serval/debug.h>
#include <serval/net.h>
#include <serval/wait.h>
#include <serval/bitops.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#if defined(OS_LINUX)
#include <linux/net.h>
#define SOCK_MAX (SOCK_PACKET + 1)
#elif defined(OS_BSD)
#define SOCK_MAX (SOCK_SEQPACKET + 1)
#else
#error "OS not supported!"
#endif
#include "client.h"

/* Setting NPROTO to AF_MAX is overkill here, since we effectively
 * only register Serval protocols. Anyhow, the net_families is just
 * an array of pointers, so the waste is not such a big deal. */
#ifndef NPROTO
#define NPROTO AF_MAX 
#endif

static DEFINE_SPINLOCK(net_family_lock);
static const struct net_proto_family *net_families[NPROTO] = { 0 };

int sock_register(const struct net_proto_family *ops)
{
	int err = 0;
	
	if (ops->family >= AF_MAX) {
		LOG_ERR("Trying to register invalid protocol %d\n", ops->family);
		return -ENOBUFS;
	}
	
	spin_lock(&net_family_lock);
	
	if (net_families[ops->family]) {
		LOG_ERR("Family %d already registered\n", ops->family);
		err = -EEXIST;
	} else {
		net_families[ops->family] = ops;
	}
	
	spin_unlock(&net_family_lock);
	
	LOG_INF("NET: Registered protocol family %d\n", ops->family);

	return err;
}

void sock_unregister(int family)
{
	if (family < 0 || family > NPROTO) {
		LOG_ERR("NET: invalid protocol family\n");
		return;
	}

	spin_lock(&net_family_lock);
	net_families[family] = NULL;
	spin_unlock(&net_family_lock);

	LOG_INF("NET: Unregistered protocol family %d\n", family);
}

static struct socket *sock_alloc(void)
{
	struct socket *sock;

	sock = (struct socket *)malloc(sizeof(struct socket));

	if (!sock)
		return NULL;
	
	memset(sock, 0, sizeof(*sock));

	sock->state = SS_UNCONNECTED;
	sock->flags = 0;
	sock->ops = NULL;
	sock->wq = (struct socket_wq *)malloc(sizeof(struct socket_wq));

	if (!sock->wq) {
		free(sock);
		return NULL;
	}
	
	init_waitqueue_head(&sock->wq->wait);

	return sock;
}

static void sock_free(struct socket *sock)
{
	if (sock->wq) {
		destroy_waitqueue_head(&sock->wq->wait);
		free(sock->wq);
	}	
	free(sock);
}

/*
 *	Update the socket async list
 *
 *	Fasync_list locking strategy.
 *
 *	1. fasync_list is modified only under process context socket lock
 *	   i.e. under semaphore.
 *	2. fasync_list is used under read_lock(&sk->sk_callback_lock)
 *	   or under socket lock
 */
/*
static int sock_fasync(int fd, struct file *filp, int on)
{
	struct socket *sock = filp->private_data;
	struct sock *sk = sock->sk;

	if (sk == NULL)
		return -EINVAL;

	lock_sock(sk);

	fasync_helper(fd, filp, on, &sock->wq->fasync_list);

	if (!sock->wq->fasync_list)
		sock_reset_flag(sk, SOCK_FASYNC);
	else
		sock_set_flag(sk, SOCK_FASYNC);

	release_sock(sk);
	return 0;
}
*/

int sock_wake_async(struct socket *sock, int how, int band)
{
        struct socket_wq *wq;

        if (!sock)
                return -1;
        
        wq = sock->wq;
        
        if (!wq || !wq->fasync_list) {
                return -1;
        }

        switch (how) {
        case SOCK_WAKE_WAITD:
                if (test_bit(SOCK_ASYNC_WAITDATA, &sock->flags))
                        goto call_kill;
        case SOCK_WAKE_SPACE:
                if (!test_and_clear_bit(SOCK_ASYNC_NOSPACE, &sock->flags))
                        break;
                /* fall through */
        case SOCK_WAKE_IO:
        call_kill:
                //kill_fasync(&wq->fasync_list, SIGIO, band);
                break;
        case SOCK_WAKE_URG:
                //kill_fasync(&wq->fasync_list, SIGURG, band);
                LOG_ERR("ASYNC IO not implemented!\n");
        }

       return 0;
}

int sock_create(int family, int type, int protocol,
                struct socket **res)
{	
	int err = 0;
	struct socket *sock;
	const struct net_proto_family *pf;

	if (family < 0 || family >= NPROTO)
		return -EAFNOSUPPORT;
	if (type < 0 || type >= SOCK_MAX)
		return -EINVAL;

	spin_lock(&net_family_lock);
	
	pf = net_families[family];
	
	if (!pf) {		
		err = -EAFNOSUPPORT;
		goto out_unlock;
	}

	sock = sock_alloc();

	if (!sock) {
		/* return -ENFILE; */
		err = -ENOMEM;
		goto out_unlock;
	}

	sock->type = type;

	err = pf->create(&init_net, sock, protocol, 0);
	
	*res = sock;
out_unlock:
	spin_unlock(&net_family_lock);

	return err;
}

void sock_release(struct socket *sock)
{
	LOG_DBG("socket of type=%d released\n", sock->type);

	if (sock->ops) {
		sock->ops->release(sock);
		sock->ops = NULL;
	}
	sock_free(sock);
}

