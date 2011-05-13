#ifndef RESOLVER_MESSAGING_H_
#define RESOLVER_MESSAGING_H_

#include "libstack/resolver_protocol.h"
#include "service_types.h"

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
    void* target;
    void
    (*resolver_message_cb)(void* target, uint16_t type, struct sv_control_header* message, size_t len,
            struct sv_instance_addr* remote);
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
//int (*start)(void* messenger);
//    int (*stop)(void* messenger);

struct sv_resolver_rpc_interface {
    /*component interface */
    int (*initialize)(void* messenger);
    void (*start)(void* messenger);
    void (*stop)(void* messenger);
    int (*finalize)(void* messenger);

    /*attribute accessor/mutators */
    uint32_t (*get_outstanding_requests)(void* resm);

    uint16_t (*get_max_retry)(void* resm);
    void (*set_max_retry)(void* resm, uint16_t retry);

    uint16_t (*get_request_timeout)(void* resm);
    void (*set_request_timeout)(void* resm, uint16_t timeout);

    /* resolver rpc */
    int (*send_resolver_message)(void* messenger, uint32_t xid, struct sv_control_header* message,
            size_t len, resolver_message_callback* rm_cb);
};

typedef struct {
    void* target;
    struct sv_resolver_rpc_interface* interface;
} resolver_rpc;

void resolver_rpc_set_peer(struct sv_resolver_rpc* messenger, struct sv_instance_addr* peer_addr);
const struct sv_instance_addr* resolver_rpc_get_peer(struct sv_resolver_rpc* messenger);
int resolver_rpc_get_max_message_size(struct sv_resolver_rpc* messenger);
uint64_t resolver_rpc_get_last_remote_access(struct sv_resolver_rpc* bm);

#endif  // -- RESOLVER_MESSAGING_H_
