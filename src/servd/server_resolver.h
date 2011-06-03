/*
 * server_resolver.h
 *
 *  Created on: Mar 9, 2011
 *      Author: daveds
 */

#ifndef SERVER_RESOLVER_H_
#define SERVER_RESOLVER_H_

#include "service_types.h"
#include "resolver.h"
#include "resolver_base.h"
#include "resolver_messaging.h"
#include "libstack/resolver_protocol.h"
#include "task.h"
#include <glib.h>

/* Note how the rpc handler will maintain a separate
 * callback info per peer remote resolver to handle
 * incoming requests. The resolver_rpc here maintains
 * the incoming request/response cache, while the
 * dual/pair peer->resolver_rpc is responsible for
 * output request delivery/reliability. Maintaining
 * separate req/resp caches eliminates the possibility
 * of txn ID collision to allow for independent full
 * duplex req streams. Moreover, the underlying udp
 * message channel mechanism relies on remote-SID
 * dispatch to map packets to their appropriate handlers
 */
struct callback_info {
    /* cache reference - may be invalid - incref? */
    service_resolver* peer;
    /* request rate, etc? */
    resolver_rpc* rpc;
    struct server_rpc_handler* handler;
};

struct server_rpc_handler {
    service_resolver* resolver;

    /* TODO - this really needs to lock the dispatch table....*/
    /* should be removed on peer removal */
    task_mutex callback_mutex;
    /* GHashTable* callback_table; */
    GPtrArray* callback_list;

    /* default messaging for unknown peers */
    struct callback_info def_callback;
    resolver_message_callback callback;
    peer_status_callback status_callback;
};

struct server_rpc_handler* create_server_rpc_handler(service_resolver* res);
int init_server_rpc_handler(struct server_rpc_handler* handler, service_resolver* res);
int server_rpc_handler_initialize(struct server_rpc_handler* handler);
void server_rpc_handler_start(struct server_rpc_handler* handler);
void server_rpc_handler_stop(struct server_rpc_handler* handler);
int server_rpc_handler_finalize(struct server_rpc_handler* handler);

#endif /* SERVER_RESOLVER_H_ */
