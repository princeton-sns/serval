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

        rsk = MALLOC(sizeof(*rsk), alloc);

        if (!rsk)
                return NULL;

        memset(rsk, 0, sizeof(*rsk));
        INIT_LIST_HEAD(&rsk->lh);

        return rsk;
}

static inline void scaffold_rsk_free(struct scaffold_request_sock *rsk)
{
        FREE(rsk);
}

#endif /* _SCAFFOLD_REQUEST_SOCK_H_ */
