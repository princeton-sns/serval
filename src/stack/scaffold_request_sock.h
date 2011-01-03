/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _SCAFFOLD_REQUEST_SOCK_H_
#define _SCAFFOLD_REQUEST_SOCK_H_

#include <scaffold/platform.h>
#include <scaffold/list.h>
#include <scaffold/sock.h>
#include <netinet/scaffold.h>
#if defined(OS_USER)
#include <string.h>
#endif
#include "scaffold_sock.h"

struct scaffold_request_sock {
        struct sock *sk;
        int state;
        struct service_id peer_srvid;
        struct flow_id dst_flowid;
        struct sock_id sockid;
        uint32_t seqno;
        unsigned char flags;
        struct list_head lh;
};

static inline struct scaffold_request_sock *scaffold_rsk_alloc(int alloc)
{
        struct scaffold_request_sock *rsk;

        rsk = ZALLOC(sizeof(*rsk), alloc);

        if (!rsk)
                return NULL;

        INIT_LIST_HEAD(&rsk->lh);
        
        scaffold_sock_get_sockid(&rsk->sockid);

        return rsk;
}

static inline void scaffold_rsk_free(struct scaffold_request_sock *rsk)
{
        FREE(rsk);
}

#endif /* _SCAFFOLD_REQUEST_SOCK_H_ */
