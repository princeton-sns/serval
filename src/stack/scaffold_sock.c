/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/platform.h>
#include <scaffold/skbuff.h>
#include <scaffold/list.h>
#include <scaffold/debug.h>
#include <netinet/scaffold.h>
#include "scaffold_sock.h"
#if defined(OS_LINUX_KERNEL)
#include <linux/ip.h>
#else
#include <netinet/ip.h>
#endif

static atomic_t scaffold_sock_id = ATOMIC_INIT(1);
static struct scaffold_table established_table;
static struct scaffold_table listen_table;

static const char *sock_state_str[] = {
        "UNDEFINED",
        "CLOSED",
        "REQUEST",
        "RESPOND",
        "CONNECTED",
        "CLOSING",
        "TIMEWAIT",
        "MIGRATE",
        "RECONNECT",
        "RRESPOND",
        "LISTEN",
        /* TCP only */
        "FINWAIT1",
        "FINWAIT2",
        "CLOSEWAIT",
        "LASTACK",
        "SIMCLOSE"  
};

int scaffold_sock_get_sockid(struct sock_id *sid)
{
        sid->s_id = htons(atomic_inc_return(&scaffold_sock_id));

        return 0;
}

int __init scaffold_table_init(struct scaffold_table *table, const char *name)
{
	unsigned int i;

	table->hash = MALLOC(SCAFFOLD_HTABLE_SIZE_MIN *
			      2 * sizeof(struct scaffold_hslot), GFP_KERNEL);
	if (!table->hash) {
		/* panic(name); */
		return -1;
	}

	table->mask = SCAFFOLD_HTABLE_SIZE_MIN - 1;

	for (i = 0; i <= table->mask; i++) {
		INIT_HLIST_HEAD(&table->hash[i].head);
		table->hash[i].count = 0;
		spin_lock_init(&table->hash[i].lock);
	}

	return 0;
}

void __exit scaffold_table_fini(struct scaffold_table *table)
{
        unsigned int i;

        for (i = 0; i <= table->mask; i++) {
                spin_lock_bh(&table->hash[i].lock);
                        
                while (!hlist_empty(&table->hash[i].head)) {
                        struct sock *sk;

                        sk = hlist_entry(table->hash[i].head.first, 
                                          struct sock, sk_node);
                        
                        hlist_del(&sk->sk_node);
                        table->hash[i].count--;
                        sock_put(sk);
                }
                spin_unlock_bh(&table->hash[i].lock);           
	}

        FREE(table->hash);
}

static struct sock *scaffold_sock_lookup(struct scaffold_table *table,
                                         struct net *net, void *key, 
                                         size_t keylen)
{
        struct scaffold_hslot *slot;
        struct hlist_node *walk;
        struct sock *sk = NULL;

        if (!key)
                return NULL;

        slot = scaffold_hashslot(table, net, key, keylen);

        if (!slot)
                return NULL;

        spin_lock_bh(&slot->lock);
        
        hlist_for_each_entry(sk, walk, &slot->head, sk_node) {
                struct scaffold_sock *ssk = scaffold_sk(sk);
                if (memcmp(key, ssk->hash_key, keylen) == 0) {
                        sock_hold(sk);
                        goto out;
                }
        }
        sk = NULL;
 out:
        spin_unlock_bh(&slot->lock);
        
        return sk;
}

struct sock *scaffold_sock_lookup_sockid(struct sock_id *sockid)
{
        return scaffold_sock_lookup(&established_table, &init_net, 
                                    sockid, sizeof(*sockid));
}

struct sock *scaffold_sock_lookup_serviceid(struct service_id *srvid)
{
        return scaffold_sock_lookup(&listen_table, &init_net, 
                                    srvid, sizeof(*srvid));
}

struct sock *scaffold_sock_lookup_skb(struct sk_buff *skb)
{
 	struct sock *sk = NULL;
        /*
	const struct iphdr *iph = ip_hdr(skb);
        struct sock_id sockid;
        switch (iph->protocol) {
	case IPPROTO_TCP:
        {
                struct tcphdr *tcp = tcp_hdr(skb);
                memcpy(&sockid, &tcp->dest, sizeof(sockid));
                sk = scaffold_sock_lookup(&scaffold_table, &init_net, &sockid);
                break;
        }
	case IPPROTO_UDP:
        {
                struct udphdr *udp = udp_hdr(skb);
                memcpy(&sockid, &udp->dest, sizeof(sockid));
                sk = scaffold_sock_lookup(&scaffold_table, &init_net, &sockid);
                break;
        }
        default:
                break;
        }
        */

        return sk;
}

static inline unsigned int scaffold_ehash(struct sock *sk)
{
        return scaffold_hashfn(sock_net(sk), 
                               &scaffold_sk(sk)->local_sockid,
                               sizeof(struct sock_id),
                               established_table.mask);
}

static inline unsigned int scaffold_lhash(struct sock *sk)
{
        return scaffold_hashfn(sock_net(sk), 
                               &scaffold_sk(sk)->local_srvid, 
                               sizeof(struct service_id),
                               listen_table.mask);
}

static void __scaffold_table_hash(struct scaffold_table *table, struct sock *sk)
{
        struct scaffold_sock *ssk = scaffold_sk(sk);
        struct scaffold_hslot *slot;

        sk->sk_hash = scaffold_hashfn(sock_net(sk), 
                                      ssk->hash_key,
                                      ssk->hash_key_len,
                                      table->mask);

        slot = &table->hash[sk->sk_hash];

        spin_lock(&slot->lock);
        slot->count++;
        hlist_add_head(&sk->sk_node, &slot->head);
#if defined(OS_LINUX_KERNEL)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
#else
        sock_prot_inc_use(sk->sk_prot);
#endif
#endif
        spin_unlock(&slot->lock);     
}

static void __scaffold_sock_hash(struct sock *sk)
{
        if (!hlist_unhashed(&sk->sk_node)) {
                LOG_ERR("socket already hashed\n");
        }
        
        LOG_DBG("hashing socket %p\n", sk);

        if (sk->sk_state == SCAFFOLD_LISTEN) {
                LOG_DBG("Hashing socket based on service id %s\n",
                        service_id_to_str(&scaffold_sk(sk)->local_srvid));
                scaffold_sk(sk)->hash_key = &scaffold_sk(sk)->local_srvid;
                scaffold_sk(sk)->hash_key_len = sizeof(scaffold_sk(sk)->local_srvid);
                __scaffold_table_hash(&listen_table, sk);

        } else { 
                LOG_DBG("Hashing socket based on socket id %s\n",
                        socket_id_to_str(&scaffold_sk(sk)->local_sockid));
                scaffold_sk(sk)->hash_key = &scaffold_sk(sk)->local_sockid;
                scaffold_sk(sk)->hash_key_len = sizeof(scaffold_sk(sk)->local_sockid);
                __scaffold_table_hash(&established_table, sk);
        }
}

void scaffold_sock_hash(struct sock *sk)
{
        if (sk->sk_state != SCAFFOLD_CLOSED) {
		local_bh_disable();
		__scaffold_sock_hash(sk);
		local_bh_enable();
	}
}

void scaffold_sock_unhash(struct sock *sk)
{
        struct net *net = sock_net(sk);
        spinlock_t *lock;

        LOG_DBG("unhashing socket %p\n", sk);

        /* grab correct lock */
        if (sk->sk_state == SCAFFOLD_LISTEN) {
                lock = &scaffold_hashslot(&listen_table, net, 
                                          &scaffold_sk(sk)->local_srvid, 
                                          sizeof(struct service_id))->lock;
        } else {
                lock = &scaffold_hashslot(&established_table,
                                          net, &scaffold_sk(sk)->local_sockid, 
                                          sizeof(struct sock_id))->lock;
        }

	spin_lock_bh(lock);

        if (!hlist_unhashed(&sk->sk_node)) {
                hlist_del_init(&sk->sk_node);
#if defined(OS_LINUX_KERNEL)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
                sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
#else
                sock_prot_dec_use(sk->sk_prot);
#endif
#endif
        }
	spin_unlock_bh(lock);
}

int scaffold_sock_set_state(struct sock *sk, int new_state)
{
        /* TODO: state transition checks */
        
        if (new_state < SCAFFOLD_SOCK_STATE_MIN ||
            new_state > SCAFFOLD_SOCK_STATE_MAX) {
                LOG_ERR("invalid state\n");
                return -1;
        }

        LOG_DBG("%s -> %s\n",
                sock_state_str[sk->sk_state],
                sock_state_str[new_state]);

        sk->sk_state = new_state;

        return new_state;
}

int __init scaffold_sock_init(void)
{
        int ret;

        ret = scaffold_table_init(&listen_table, "LISTEN");

        if (ret < 0)
                goto fail_table;
        
        ret = scaffold_table_init(&established_table, "ESTABLISHED");

fail_table:
        return ret;
}

void __exit scaffold_sock_fini(void)
{
        scaffold_table_fini(&listen_table);
        scaffold_table_fini(&established_table);
        if (sock_state_str[0]) {} /* Avoid compiler warning when
                                   * compiling with debug off */
}
