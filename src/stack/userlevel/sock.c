#include <scaffold/debug.h>
#include "sock.h"

static void sk_def_destruct(struct sock *sk)
{

}

static void sk_def_state_change(struct sock *sk)
{

}

static void sk_def_data_ready(struct sock *sk, int bytes)
{

}

static void sk_def_write_space(struct sock *sk)
{

}

static int sk_def_backlog_rcv(struct sock *sk)
{

}

struct sock *sk_alloc(void)
{
	struct sock *sk = NULL;

	/* Allocate sock */

	
	sk->sk_destruct = &sk_def_destruct;
	sk->sk_state_change = &sk_def_state_change;
	sk->sk_data_ready = &sk_def_data_ready;
	sk->sk_write_space = &sk_def_write_space;
	sk->sk_backlog_rcv = &sk_def_backlog_rcv;

	return NULL;
}
