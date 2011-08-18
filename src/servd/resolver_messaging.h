#ifndef RESOLVER_MESSAGING_H_
#define RESOLVER_MESSAGING_H_

#include "libstack/resolver_protocol.h"
#include "service_types.h"
#include <glib.h>
#include "message_channel.h"

#define SERVER_EXPIRE_TIMER 5
#define CLIENT_EXPIRE_TIMER 15

#define SERVER_REQUEST_TIMEOUT 5
#define CLIENT_REQUEST_TIMEOUT 5
#define RPC_MAX_RETRY 1

//the resolver messaging is responsible for
//cleaning up the message data at this point
//? should the data be refcounted?
//? should the data be scatter/gather instead of full blob?

struct sv_resolver_rpc;

//note that the last callback in the "chain" or list is responsible for consuming (freeing) the message
typedef struct sv_resolver_message_callback {
    void *target;
    void
     (*resolver_message_cb) (struct sv_resolver_message_callback * cb,
			     uint16_t type,
			     struct sv_control_header * message,
			     size_t len, struct sv_instance_addr * remote);
} resolver_message_callback;

//used by resolver implementations for RPC
//can be UDP (requires demux) or TCP


//void configure(const Configuration*);
//void install();
//static void getInstance(const container::Context*, scaffold::ControllerInterface*&);

/* client/server rpc */
//uint32_t (*get_outstanding_responses)(struct sv_resolver_messaging* resm);
//uint32_t (*get_rpc_expire_timeout)(struct sv_resolver_messaging* resm);
//void (*set_rpc_expire_timeout)(struct sv_resolver_messaging* resm, uint32_t timeout);
//int
//(*send_resolver_response)(struct sv_resolver_messaging* messenger, uint32_t xid,
//        sv_control_header* response, size_t len, resolver_message_callback* rm_cb);
//int (*start)(resolver_rpc* messenger);
//    int (*stop)(resolver_rpc* messenger);
struct sv_resolver_rpc_interface;
struct sv_resolver_rpc {
    enum component_state state;
    task_mutex req_mutex;
    //keyed by transactionID
    GHashTable *rpc_request_map;

    //typedef hash_map<uint16_t, TestStats> StatMap;
    //transaction id boundary?

    uint64_t last_remote_access;
    uint32_t outstanding_requests;

    uint16_t max_retry;
    uint16_t request_timeout;

    /* the message channel must be serval compatible
     * should be effectively shared between req/resp
     * */
    message_channel *channel;
    /* only needed for incoming requests */
    resolver_message_callback callback;
};


typedef struct {
    struct sv_resolver_rpc resolver;
    struct sv_resolver_rpc_interface *interface;
} resolver_rpc;

struct sv_resolver_rpc_interface {
    /*component interface */
    int (*initialize) (resolver_rpc * messenger);
    void (*start) (resolver_rpc * messenger);
    void (*stop) (resolver_rpc * messenger);
    int (*finalize) (resolver_rpc * messenger);

    void (*set_local_address) (resolver_rpc * messenger,
			       struct sockaddr * saddr, size_t len);

    void (*set_callback) (resolver_rpc * messenger,
			  resolver_message_callback * callback);
    /*attribute accessor/mutators */
     uint32_t(*get_outstanding_requests) (resolver_rpc * messenger);

     uint16_t(*get_max_retry) (resolver_rpc * messenger);
    void (*set_max_retry) (resolver_rpc * messenger, uint16_t retry);

     uint16_t(*get_request_timeout) (resolver_rpc * messenger);
    void (*set_request_timeout) (resolver_rpc * messenger, uint16_t timeout);

    /* resolver rpc */
    int (*send_resolver_message) (resolver_rpc * messenger, uint32_t xid,
				  struct sv_control_header * message,
				  size_t len,
				  resolver_message_callback * rm_cb);
};


void resolver_rpc_set_peer(resolver_rpc * messenger,
			   struct sv_instance_addr *peer_addr);
const struct sv_instance_addr *resolver_rpc_get_peer(resolver_rpc * messenger);
int resolver_rpc_get_max_message_size(resolver_rpc * messenger);
uint64_t resolver_rpc_get_last_remote_access(resolver_rpc * bm);

#endif				// -- RESOLVER_MESSAGING_H_
