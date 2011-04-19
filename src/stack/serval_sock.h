/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SERVAL_SOCK_H
#define _SERVAL_SOCK_H

#include <netinet/serval.h>
#include <serval/list.h>
#include <serval/lock.h>
#include <serval/hash.h>
#include <serval/sock.h>
#include <serval/inet_sock.h>
#include <serval/net.h>
#include <serval/timer.h>
#include <serval/request_sock.h>
#if defined(OS_USER)
#include <string.h>
#endif
#if defined(OS_LINUX_KERNEL)
#include <net/tcp_states.h>
#endif

enum serval_packet_type { 
        SERVAL_PKT_DATA = 1,
        SERVAL_PKT_CONN_SYN,
        SERVAL_PKT_CONN_SYNACK,
        SERVAL_PKT_CONN_ACK,
        SERVAL_PKT_ACK,
        SERVAL_PKT_RESET,
        SERVAL_PKT_CLOSE,
        SERVAL_PKT_CLOSEACK,
        SERVAL_PKT_MIG,
        SERVAL_PKT_RSYN,
        SERVAL_PKT_MIGDATA,
        SERVAL_PKT_RSYNACK
};

/*
  TCP states from net/tcp_states.h, should be as compatible as
  possible.
  
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT,
	TCP_SYN_RECV,
	TCP_FIN_WAIT1,
	TCP_FIN_WAIT2,
	TCP_TIME_WAIT,
	TCP_CLOSE,
	TCP_CLOSE_WAIT,
	TCP_LAST_ACK,
	TCP_LISTEN,
	TCP_CLOSING,
	TCP_MAX_STATES	
 */
enum {
        SERVAL_MIN_STATE = 0,
        SERVAL_INIT = SERVAL_MIN_STATE,
        SERVAL_CONNECTED,
        SERVAL_REQUEST,
        SERVAL_RESPOND,
        SERVAL_FINWAIT1,
        SERVAL_FINWAIT2,
        SERVAL_TIMEWAIT,
        SERVAL_CLOSED,
        SERVAL_CLOSEWAIT,
        SERVAL_LASTACK,
        SERVAL_LISTEN,
        SERVAL_CLOSING,
        SERVAL_MIGRATE,
        SERVAL_RECONNECT,
        SERVAL_RRESPOND,
        SERVAL_MAX_STATE
};

enum {
        SERVALF_CONNECTED = (1 << 1),
        SERVALF_REQUEST   = (1 << 2),
        SERVALF_RESPOND   = (1 << 3),
        SERVALF_FINWAIT1  = (1 << 4),
        SERVALF_FINWAIT2  = (1 << 5),
        SERVALF_TIMEWAIT  = (1 << 6),
        SERVALF_CLOSED    = (1 << 7), 
        SERVALF_CLOSEWAIT = (1 << 8),
        SERVALF_LASTACK   = (1 << 9),
        SERVALF_LISTEN    = (1 << 10),
        SERVALF_CLOSING   = (1 << 11),
        SERVALF_MIGRATE   = (1 << 12),
        SERVALF_RECONNECT = (1 << 13),
        SERVALF_RRESPOND  = (1 << 14)
};

enum serval_sock_flags {
        SSK_FLAG_BOUND = 0,
        SSK_FLAG_AUTOBOUND,
};

struct serval_sock_af_ops {
	int	        (*queue_xmit)(struct sk_buff *skb);
	int	        (*receive)(struct sock *sk, struct sk_buff *skb);
	void	        (*send_check)(struct sock *sk, struct sk_buff *skb);
	int	        (*rebuild_header)(struct sock *sk);
	int	        (*conn_request)(struct sock *sk, struct sk_buff *skb);
        void            (*conn_child_sock)(struct sock *sk, 
                                           struct sk_buff *skb,
                                           struct request_sock *rsk,
                                           struct sock *child,
                                           struct dst_entry *dst);
        int             (*close_request)(struct sock *sk, struct sk_buff *skb);
        int             (*close_ack)(struct sock *sk, struct sk_buff *skb);
};

/* The AF_SERVAL socket */
struct serval_sock {
	/* NOTE: sk has to be the first member */
        struct inet_sock        sk;
#if defined(OS_USER)
        struct client           *client;
#endif
        struct net_device       *dev; /* TX device for connected flows */
        unsigned char           flags;
        void                    *hash_key;
        unsigned int            hash_key_len;  /* Keylen in bytes */
        unsigned short          srvid_prefix_bits;
        struct serval_sock_af_ops *af_ops;
        struct sk_buff_head     tx_queue;
 	struct timer_list	retransmit_timer;        
	struct timer_list	tw_timer;
        struct flow_id          local_flowid;
        struct flow_id          peer_flowid;
        struct service_id       local_srvid;
        struct service_id       peer_srvid;
        struct list_head        syn_queue;
        struct list_head        accept_queue;
	struct sk_buff_head	ctrl_queue;
	struct sk_buff		*ctrl_send_head;
        uint8_t                 local_nonce[SERVAL_NONCE_SIZE];
        uint8_t                 peer_nonce[SERVAL_NONCE_SIZE];
        struct {
                uint32_t        una;
                uint32_t        nxt;
                uint32_t        wnd;
                uint32_t        iss;
        } snd_seq;
        struct {
                uint32_t        nxt;
                uint32_t        wnd;
                uint32_t        iss;
        } rcv_seq;
        unsigned short          retransmits;
        unsigned long           rto;
        unsigned long           srtt;
        unsigned long           tot_bytes_sent;
        unsigned long           tot_pkts_recv;
        unsigned long           tot_pkts_sent;
};

#define SERVAL_INITIAL_RTO (3000)

#define serval_sk(__sk) ((struct serval_sock *)__sk)

#define SERVAL_HTABLE_SIZE_MIN 256

struct serval_hslot {
	struct hlist_head head;
	int               count;
	spinlock_t        lock;
};

struct serval_table {
	struct serval_hslot *hash;
        unsigned int (*hashfn)(struct serval_table *tbl, struct sock *sk);
        struct serval_hslot *(*hashslot)(struct serval_table *tbl,
                                         struct net *net,
                                         void *key,
                                         size_t keylen);
	unsigned int mask;
};

static inline int serval_sock_is_master(struct sock *sk)
{
        return 1;
}

int serval_sock_get_flowid(struct flow_id *sid);

static inline unsigned int serval_hashfn(struct net *net, 
                                         void *key,
                                         size_t keylen,
                                         unsigned int mask)
{
	return *((unsigned int *)key) & mask;
}

static inline unsigned int serval_hashfn_listen(struct net *net, 
                                                void *key,
                                                size_t keylen,
                                                unsigned int mask)
{
        return full_bitstring_hash(key, keylen) & mask;
}

extern struct serval_table serval_table;

static inline 
struct serval_hslot *serval_hashslot(struct serval_table *table,
                                     struct net *net, 
                                     void *key,
                                     size_t keylen)
{
	return &table->hash[serval_hashfn(net, key, keylen, table->mask)];
}

static inline 
struct serval_hslot *serval_hashslot_listen(struct serval_table *table,
                                            struct net *net, 
                                            void *key,
                                            size_t keylen)
{
	return &table->hash[serval_hashfn_listen(net, key, keylen*8, table->mask)];
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
void serval_sock_destroy(struct sock *sk);
void serval_sock_done(struct sock *sk);

void serval_sock_set_dev(struct sock *sk, struct net_device *dev);
const char *serval_sock_state_str(struct sock *sk);
const char *serval_state_str(unsigned int state);
int serval_sock_set_state(struct sock *sk, unsigned int state);
void serval_sock_rexmit_timeout(unsigned long data);

int __init serval_sock_tables_init(void);
void __exit serval_sock_tables_fini(void);

void serval_sock_wfree(struct sk_buff *skb);
void serval_sock_rfree(struct sk_buff *skb);

static inline void skb_serval_set_owner_w(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = serval_sock_wfree;
        /* Guarantees the socket is not free'd for in-flight packets */
        sock_hold(sk);
}

static inline void skb_serval_set_owner_r(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = serval_sock_rfree;
}


#endif /* _SERVAL_SOCK_H */
