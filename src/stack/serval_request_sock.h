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
        uint32_t seqno;
        uint8_t nonce[8];
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

        return rsk;
}

static inline void serval_rsk_free(struct serval_request_sock *rsk)
{
        FREE(rsk);
}

#endif /* _SERVAL_REQUEST_SOCK_H_ */
