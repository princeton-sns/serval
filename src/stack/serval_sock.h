/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SERVAL_SOCK_H
#define _SERVAL_SOCK_H

#include <netinet/serval.h>
#include <serval/list.h>
#include <serval/lock.h>
#include <serval/hash.h>
#include <serval/sock.h>
#include <serval/dst.h>
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
        __SERVAL_MIN_STATE = 0,
        SERVAL_INIT = __SERVAL_MIN_STATE,
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
        __SERVAL_MAX_STATE
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
        SERVALF_CLOSING   = (1 << 11)
};

/**
   Service Access Layer (SAL) socket states used for, e.g., migration.
 */
enum {
        SAL_INITIAL = 0,
        SAL_RSYN_SENT,
        SAL_RSYN_RECV,
        SAL_RSYN_SENT_RECV, /* Receive RSYN after having sent RSYN */
        __SAL_MAX_STATE,
};

enum serval_sock_flags {
        SSK_FLAG_BOUND = 0,
        SSK_FLAG_AUTOBOUND,
        SSK_FLAG_HASHED,
        SSK_FLAG_CHILD,
        SSK_FLAG_FIN_SENT,
};

struct serval_sock_af_ops {
	int	        (*queue_xmit)(struct sk_buff *skb);
	int	        (*encap_queue_xmit)(struct sk_buff *skb);
	int	        (*receive)(struct sock *sk, struct sk_buff *skb);
	void	        (*send_check)(struct sock *sk, struct sk_buff *skb);
	int	        (*rebuild_header)(struct sock *sk);
        int             (*conn_build_syn)(struct sock *sk, struct sk_buff *skb);
        int             (*conn_build_synack)(struct sock *sk,
                                             struct dst_entry *dst,
                                             struct request_sock *rsk,
                                             struct sk_buff *skb);
        int             (*conn_build_ack)(struct sock *sk, struct sk_buff *skb);        
	int	        (*conn_request)(struct sock *sk, 
                                        struct request_sock *rsk, 
                                        struct sk_buff *skb);
	int	        (*conn_close)(struct sock *sk);
	int	        (*request_state_process)(struct sock *sk, 
                                                 struct sk_buff *skb);
	int	        (*respond_state_process)(struct sock *sk, 
                                                 struct sk_buff *skb);
        int             (*conn_child_sock)(struct sock *sk, 
                                           struct sk_buff *skb,
                                           struct request_sock *rsk,
                                           struct sock *child,
                                           struct dst_entry *dst);
	u16	        net_header_len;
	u16	        sockaddr_len;
        int             (*migration_completed)(struct sock *sk);
        int             (*freeze_flow)(struct sock *sk);
        int             (*send_shutdown)(struct sock *sk);
        int             (*recv_shutdown)(struct sock *sk);
        int             (*close_ack)(struct sock *sk, struct sk_buff *skb);
        void            (*done)(struct sock *sk);
};

/* The AF_SERVAL socket */
struct serval_sock {
	/* NOTE: sk has to be the first member */
        struct inet_sock        sk;
#if defined(OS_USER)
        struct client           *client;
#endif
        /* SAL state, used for, e.g., migration */
        u8                      sal_state;
        u8                      flags;
        int                     mig_dev_if;
        u32                     mig_daddr;
        void                    *hash_key;
        u32                     hash_key_len;  /* Keylen in bytes */
        u16                     srvid_prefix_bits;
        u16                     srvid_flags;
        struct list_head        sock_node;
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
        u8                      local_nonce[SERVAL_NONCE_SIZE];
        u8                      peer_nonce[SERVAL_NONCE_SIZE];
        u16                     ext_hdr_len;
        u16                     udp_encap_sport;
        u16                     udp_encap_dport;
        u16                     udp_encap_migration_dport;
        struct {
                u32        una;
                u32        nxt;
                u32        wnd;
                u32        iss;
        } snd_seq;
        struct {
                u32        nxt;
                u32        wnd;
                u32        iss;
        } rcv_seq;
        u8                      retransmits;
        u8                      backoff;
        u8                      pending;
        u32                     rto;
        u32                     srtt;
	u32                     mdev;  /* medium deviation */
	u32                     mdev_max; /* maximal mdev for the last rtt period */
	u32                     rttvar;	/* smoothed mdev_max */
	u32                     rtt_seq; /* sequence number to update rttvar */
        unsigned long           timeout;
        unsigned long           tot_bytes_sent;
        unsigned long           tot_pkts_recv;
        unsigned long           tot_pkts_sent;
};

#define SAL_RTO_MAX	((unsigned)(120*HZ))
#define SAL_RTO_MIN	((unsigned)(HZ/5))
#define SAL_TIMEOUT_INIT ((unsigned)(3*HZ))

#define serval_sk(__sk) ((struct serval_sock *)__sk)

/* Should be power of two */
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
	return &table->hash[serval_hashfn(net, key, keylen*8, table->mask)];
}

void serval_sock_migrate_iface(struct net_device *old_if, 
                               struct net_device *new_if);
void serval_sock_migrate_flow(struct flow_id *old_f,
                              struct net_device *new_if);
void serval_sock_migrate_service(struct service_id *old_s,
                                 struct net_device *new_if);
void serval_sock_freeze_flows(struct net_device *dev);
struct sock *serval_sock_lookup_service(struct service_id *, int protocol);
struct sock *serval_sock_lookup_flow(struct flow_id *);

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

static inline void serval_sock_clear_xmit_timer(struct sock *sk)
{
	struct serval_sock *ssk = serval_sk(sk);
        ssk->pending = 0;
        ssk->retransmits = 0;
        ssk->backoff = 0;
        sk_stop_timer(sk, &ssk->retransmit_timer);
}

static inline void serval_sock_reset_xmit_timer(struct sock *sk, 
                                                unsigned long when,
                                                const unsigned long max_when)
{
        struct serval_sock *ssk = serval_sk(sk);

	if (when > max_when) {
		when = max_when;
	}
        ssk->pending = 1;
        ssk->timeout = jiffies + when;
        sk_reset_timer(sk, &ssk->retransmit_timer, ssk->timeout);
}

int __serval_assign_flowid(struct sock *sk);
struct sock *serval_sk_alloc(struct net *net, struct socket *sock, 
                             gfp_t priority, int protocol, 
                             struct proto *prot);
void serval_sock_init(struct sock *sk);
void serval_sock_destroy(struct sock *sk);
void serval_sock_done(struct sock *sk);

void serval_sock_set_dev(struct sock *sk, struct net_device *dev);
void serval_sock_set_mig_dev(struct sock *sk, struct net_device *dev);
const char *serval_sock_print_state(struct sock *sk, char *buf, size_t buflen);
const char *serval_sock_state_str(struct sock *sk);
const char *serval_state_str(unsigned int state);
int serval_sock_set_state(struct sock *sk, unsigned int state);

const char *serval_sock_sal_state_str(struct sock *sk);
const char *serval_sal_state_str(unsigned int state);
int serval_sock_set_sal_state(struct sock *sk, unsigned int new_state);
void serval_sock_rexmit_timeout(unsigned long data);

int __init serval_sock_tables_init(void);
void __exit serval_sock_tables_fini(void);

void serval_sock_wfree(struct sk_buff *skb);
void serval_sock_rfree(struct sk_buff *skb);

static inline void skb_serval_set_owner_w(struct sk_buff *skb, 
                                          struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = serval_sock_wfree;
        /* Guarantees the socket is not free'd for in-flight packets */
        sock_hold(sk);
}

static inline void skb_serval_set_owner_r(struct sk_buff *skb, 
                                          struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = serval_sock_rfree;
}

struct dst_entry *serval_sock_route_req(struct sock *sk,
                                        struct request_sock *req);

int serval_sock_rebuild_header(struct sock *sk);

void flow_table_read_lock(void);
void flow_table_read_unlock(void);
int __flow_table_print(char *buf, int buflen);
int flow_table_print(char *buf, int buflen);

#endif /* _SERVAL_SOCK_H */
