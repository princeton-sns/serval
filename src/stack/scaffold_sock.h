/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SCAFFOLD_SOCK_H
#define _SCAFFOLD_SOCK_H

#include <netinet/scaffold.h>
#include <scaffold/list.h>
#include <scaffold/lock.h>
#include <userlevel/sock.h>
#include <userlevel/net.h>

#if !defined(__KERNEL__)
#include <string.h>
#endif

/* The AF_SCAFFOLD socket */
struct scaffold_sock {
	/* NOTE: sk has to be the first member */
	struct sock		sk;
#if !defined(__KERNEL__)
        struct client           *client;
#endif
        struct sock_id          sockid;
        struct service_id       local_sid;
        struct service_id       peer_sid;
        unsigned long           tot_bytes_sent;
        struct hlist_node       node;
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
	int mask;
};

static inline int scaffold_hashfn(struct net *net, struct sock_id *sid, unsigned mask)
{
        unsigned int num = 0;
        memcpy(&num, sid, sizeof(num));
	return num & mask;
}

extern struct scaffold_table scaffold_table;
extern int scaffold_table_init(struct scaffold_table *, const char *);

static inline struct scaffold_hslot *scaffold_hashslot(struct scaffold_table *table,
						       struct net *net, 
                                                       struct sock_id *sid)
{
	return &table->hash[scaffold_hashfn(net, sid, table->mask)];
}

#endif /* _SCAFFOLD_SOCK_H */
