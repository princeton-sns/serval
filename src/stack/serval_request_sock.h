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
        struct sock_id local_sockid;
        struct sock_id peer_sockid;
        struct flow_id dst_flowid;
        uint32_t seqno;
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
        
        serval_sock_get_sockid(&rsk->local_sockid);

        return rsk;
}

static inline void serval_rsk_free(struct serval_request_sock *rsk)
{
        FREE(rsk);
}

#endif /* _SERVAL_REQUEST_SOCK_H_ */
