/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SERVAL_SOCK_H
#define _SERVAL_SOCK_H

#include <netinet/serval.h>
#include <serval/list.h>
#include <serval/lock.h>
#include <serval/sock.h>
#include <serval/net.h>
#include <serval/timer.h>
#if defined(OS_USER)
#include <string.h>
#endif

struct serval_request_sock;

enum serval_sock_state {
        SERVAL_CLOSED = 1, 
        SERVAL_REQUEST,
        SERVAL_RESPOND,
        SERVAL_CONNECTED,
        SERVAL_CLOSING,
        SERVAL_TIMEWAIT,
        SERVAL_MIGRATE,
        SERVAL_RECONNECT,
        SERVAL_RRESPOND,
        SERVAL_LISTEN,
        SERVAL_CLOSEWAIT,
        /* TCP only */
        TCP_FINWAIT1,
        TCP_FINWAIT2,
        TCP_LASTACK,
        TCP_SIMCLOSE,
};

#define SERVAL_SOCK_STATE_MIN (1)
#define SERVAL_SOCK_STATE_MAX (TCP_SIMCLOSE)

enum serval_sock_flags {
        SSK_FLAG_BOUND = 0,
};

struct serval_sock_af_ops {
	int	    (*queue_xmit)(struct sk_buff *skb);
	int	    (*receive)(struct sock *sk, struct sk_buff *skb);
	void	    (*send_check)(struct sock *sk, struct sk_buff *skb);
	int	    (*rebuild_header)(struct sock *sk);
	int	    (*conn_request)(struct sock *sk, struct sk_buff *skb);
	struct sock *(*conn_child_sock)(struct sock *sk, struct sk_buff *skb,
                                        struct serval_request_sock *req,
                                        struct dst_entry *dst);
};

/* The AF_SERVAL socket */
struct serval_sock {
	/* NOTE: sk has to be the first member */
	struct sock		sk;
#if defined(OS_USER)
        struct client           *client;
#endif
        struct net_device       *dev; /* TX device for connected flows */
        unsigned char           flags;
        void                    *hash_key;
        unsigned int            hash_key_len;
        struct serval_sock_af_ops *af_ops;
        struct sk_buff_head     tx_queue;
 	struct timer_list	retransmit_timer;
        struct flow_id          local_flowid;
        struct flow_id          peer_flowid;
        struct service_id       local_srvid;
        struct service_id       peer_srvid;
        struct net_addr          dst_flowid;
        struct net_addr          src_flowid;
        struct list_head        syn_queue;
        struct list_head        accept_queue;
        unsigned long           tot_bytes_sent;
        unsigned long           tot_pkts_recv;
        unsigned long           tot_pkts_sent;
};

#define serval_sk(__sk) ((struct serval_sock *)__sk)

#define SERVAL_HTABLE_SIZE_MIN 256

struct serval_hslot {
	struct hlist_head head;
	int               count;
	spinlock_t        lock;
};

struct serval_table {
	struct serval_hslot *hash;
	unsigned int mask;
};

int serval_sock_get_flowid(struct flow_id *sid);

static inline unsigned int serval_hashfn(struct net *net, 
                                           void *key,
                                           size_t keylen,
                                           unsigned int mask)
{
        unsigned int num = 0;
        memcpy(&num, key, keylen < sizeof(num) ? keylen : sizeof(num));
	return num & mask;
}

extern struct serval_table serval_table;

static inline struct serval_hslot *serval_hashslot(struct serval_table *table,
						       struct net *net, 
                                                       void *key,
                                                       size_t keylen)
{
	return &table->hash[serval_hashfn(net, key, keylen, table->mask)];
}

struct sock *serval_sock_lookup_serviceid(struct service_id *);
struct sock *serval_sock_lookup_flowid(struct flow_id *);

void serval_sock_hash(struct sock *sk);
void serval_sock_unhash(struct sock *sk);

static inline void serval_sock_set_flag(struct serval_sock *ssk, 
                                          enum serval_sock_flags flag)
{
        ssk->flags |= (0x1 << flag);
}

static inline void serval_sock_reset_flag(struct serval_sock *ssk, 
                                            enum serval_sock_flags flag)
{
        ssk->flags &= (flag ^ -1UL);
}

static inline int serval_sock_flag(struct serval_sock *ssk, 
                                     enum serval_sock_flags flag)
{
	return ssk->flags & (0x1 << flag);
}


int __serval_assign_flowid(struct sock *sk);
struct sock *serval_sk_alloc(struct net *net, struct socket *sock, 
                               gfp_t priority, int protocol, 
                               struct proto *prot);
void serval_sock_init(struct sock *sk);
void serval_sock_destruct(struct sock *sk);
int serval_sock_set_state(struct sock *sk, int state);
void serval_sock_rexmit_timeout(unsigned long data);

int __init serval_sock_tables_init(void);
void __exit serval_sock_tables_fini(void);


#endif /* _SERVAL_SOCK_H */
