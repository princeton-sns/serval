/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SCAFFOLD_SOCK_H
#define _SCAFFOLD_SOCK_H

#include <netinet/scaffold.h>
#include <scaffold/list.h>
#include <scaffold/lock.h>
#include <scaffold/sock.h>
#include <scaffold/net.h>
#include <scaffold/timer.h>
#if defined(OS_USER)
#include <string.h>
#endif

struct scaffold_request_sock;

enum scaffold_sock_state {
        SCAFFOLD_CLOSED = 1, 
        SCAFFOLD_REQUEST,
        SCAFFOLD_RESPOND,
        SCAFFOLD_CONNECTED,
        SCAFFOLD_CLOSING,
        SCAFFOLD_TIMEWAIT,
        SCAFFOLD_MIGRATE,
        SCAFFOLD_RECONNECT,
        SCAFFOLD_RRESPOND,
        SCAFFOLD_LISTEN,
        /* TCP only */
        TCP_FINWAIT1,
        TCP_FINWAIT2,
        TCP_CLOSEWAIT,
        TCP_LASTACK,
        TCP_SIMCLOSE,
};

#define SCAFFOLD_SOCK_STATE_MIN (1)
#define SCAFFOLD_SOCK_STATE_MAX (TCP_SIMCLOSE)

enum scaffold_sock_flags {
        SSK_FLAG_BOUND = 0,
};

struct scaffold_sock_af_ops {
	int	    (*queue_xmit)(struct sk_buff *skb);
	void	    (*send_check)(struct sock *sk, struct sk_buff *skb);
	int	    (*rebuild_header)(struct sock *sk);
	int	    (*conn_request)(struct sock *sk, struct sk_buff *skb);
	struct sock *(*conn_child_sock)(struct sock *sk, struct sk_buff *skb,
                                        struct scaffold_request_sock *req,
                                        struct dst_entry *dst);
};

/* The AF_SCAFFOLD socket */
struct scaffold_sock {
	/* NOTE: sk has to be the first member */
	struct sock		sk;
#if defined(OS_USER)
        struct client           *client;
#endif
        struct net_device       *dev; /* TX device for connected flows */
        unsigned char           flags;
        void                    *hash_key;
        unsigned int            hash_key_len;
        struct scaffold_sock_af_ops *af_ops;
        struct sk_buff_head     tx_queue;
 	struct timer_list	retransmit_timer;
        struct sock_id          local_sockid;
        struct sock_id          peer_sockid;
        struct service_id       local_srvid;
        struct service_id       peer_srvid;
        struct flow_id          src_flowid;
        struct flow_id          dst_flowid;
        struct list_head        syn_queue;
        struct list_head        accept_queue;
        unsigned long           tot_bytes_sent;
        unsigned long           tot_pkts_recv;
        unsigned long           tot_pkts_sent;
};

#define scaffold_sk(__sk) ((struct scaffold_sock *)__sk)

#define SCAFFOLD_HTABLE_SIZE_MIN 256

struct scaffold_hslot {
	struct hlist_head head;
	int               count;
	spinlock_t        lock;
};

struct scaffold_table {
	struct scaffold_hslot *hash;
	unsigned int mask;
};

int scaffold_sock_get_sockid(struct sock_id *sid);

static inline unsigned int scaffold_hashfn(struct net *net, 
                                           void *key,
                                           size_t keylen,
                                           unsigned int mask)
{
        unsigned int num = 0;
        memcpy(&num, key, keylen < sizeof(num) ? keylen : sizeof(num));
	return num & mask;
}

extern struct scaffold_table scaffold_table;

static inline struct scaffold_hslot *scaffold_hashslot(struct scaffold_table *table,
						       struct net *net, 
                                                       void *key,
                                                       size_t keylen)
{
	return &table->hash[scaffold_hashfn(net, key, keylen, table->mask)];
}

struct sock *scaffold_sock_lookup_serviceid(struct service_id *);
struct sock *scaffold_sock_lookup_sockid(struct sock_id *);
struct sock *scaffold_sock_lookup_skb(struct sk_buff *);

void scaffold_sock_hash(struct sock *sk);
void scaffold_sock_unhash(struct sock *sk);

static inline void scaffold_sock_set_flag(struct scaffold_sock *ssk, 
                                          enum scaffold_sock_flags flag)
{
        ssk->flags |= (0x1 << flag);
}

static inline void scaffold_sock_reset_flag(struct scaffold_sock *ssk, 
                                            enum scaffold_sock_flags flag)
{
        ssk->flags &= (flag ^ -1UL);
}

static inline int scaffold_sock_flag(struct scaffold_sock *ssk, 
                                     enum scaffold_sock_flags flag)
{
	return ssk->flags & (0x1 << flag);
}

int scaffold_sock_set_state(struct sock *sk, int state);

int __init scaffold_sock_tables_init(void);
void __exit scaffold_sock_tables_fini(void);
void scaffold_sock_init(struct sock *sk);
void scaffold_srv_rexmit_timeout(unsigned long data);

#endif /* _SCAFFOLD_SOCK_H */
