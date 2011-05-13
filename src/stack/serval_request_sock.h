/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SERVAL_REQUEST_SOCK_H_
#define _SERVAL_REQUEST_SOCK_H_

#include <serval/platform.h>
#include <serval/list.h>
#include <serval/sock.h>
#include <netinet/serval.h>
#if defined(OS_USER)
#include <string.h>
#endif
#include "serval_sock.h"

struct serval_request_sock {
        struct sock *sk;
        struct service_id peer_srvid;
        struct flow_id local_flowid;
        struct flow_id peer_flowid;
        struct net_addr dst_addr;
        uint32_t rcv_seq;
        uint32_t iss_seq;
        uint8_t local_nonce[SERVAL_NONCE_SIZE];
        uint8_t peer_nonce[SERVAL_NONCE_SIZE];
        unsigned char flags;
        struct list_head lh;
};

static inline struct serval_request_sock *serval_rsk_alloc(int alloc)
{
        struct serval_request_sock *rsk;

        rsk = ZALLOC(sizeof(*rsk), alloc);

        if (!rsk)
                return NULL;

        INIT_LIST_HEAD(&rsk->lh);
        
        serval_sock_get_flowid(&rsk->local_flowid);

#if defined(OS_LINUX_KERNEL)
        get_random_bytes(rsk->local_nonce, SERVAL_NONCE_SIZE);
        get_random_bytes(&rsk->iss_seq, sizeof(rsk->iss_seq));
#else
        {
                unsigned int i;
                unsigned char *seqno = (unsigned char *)&rsk->iss_seq;
                for (i = 0; i < SERVAL_NONCE_SIZE; i++) {
                        rsk->local_nonce[i] = random() & 0xff;
                }
                for (i = 0; i < sizeof(rsk->iss_seq); i++) {
                        seqno[i] = random() & 0xff;
                }
        }       
#endif
        return rsk;
}

static inline void serval_rsk_free(struct serval_request_sock *rsk)
{
        FREE(rsk);
}

#endif /* _SERVAL_REQUEST_SOCK_H_ */
