/*
 * service_types.h
 *
 *  Created on: Feb 13, 2011
 *      Author: daveds
 */

#ifndef SERVICE_TYPES_H_
#define SERVICE_TYPES_H_
#include "netinet/serval.h"
#include "serval/atomic.h"
#include "resolver.h"
#include "libstack/resolver_protocol.h"
#include "task.h"

#define DEFAULT_SERVICE_PRIORITY 5000;
#define DEFAULT_SERVICE_WEIGHT 1000;
struct sv_resolver;

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

enum component_state {
    COMP_CREATED = 0,
    COMP_INITIALIZED,
    COMP_STARTED,
    COMP_SUSPENDED
};

#define is_created(state) (state == COMP_CREATED)
#define is_initialized(state) (state >= COMP_INITIALIZED)
#define is_started(state) (state >= COMP_STARTED)
#define is_suspended(state) (state >= COMP_SUSPENDED)

struct sv_instance_addr {
    struct sockaddr_sv service;
    union {
        struct sockaddr sa;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
    } address;
};


//TODO what is the size of this thing, esp. with sockaddr_sv having 3 bytes before the serviceID
struct service_reference {
    /*top attributes correspond to service_info*/
    struct sv_instance_addr instance;
    //flags should include: backup, mcast, private/scope, etc
    uint64_t registered;
    uint32_t ttl;
    uint32_t capacity;

    uint32_t priority;
    uint32_t weight;
    uint32_t idle_timeout;
    uint32_t hard_timeout;

    /* these are really resolution path data */
    uint32_t packets_resolved;
    uint32_t bytes_resolved;
    uint32_t tokens_consumed;

    /* source resolver? */
    service_resolver* resolver;

    /* data from the actual instance/source SR */
    uint32_t peer_instance_count;
    //uint32_t duration_sec;
    //uint32_t duration_nsec;
    uint32_t peer_packets_resolved;
    uint32_t peer_packets_dropped;
    uint32_t peer_bytes_resolved;
    uint32_t peer_bytes_dropped;
    uint32_t peer_tokens_consumed;

};

struct sv_component_interface {
    /*component interface */
    int (*initialize)(void* target);
    int (*finalize)(void* target);
    int (*start)(void* target);
    int (*stop)(void* target);
};

typedef struct {
    void* target;
    struct sv_component_interface* interface;

} component;

struct message_barrier;

typedef void (*barrier_handler)(struct message_barrier* barrier, const void* message, size_t len);
typedef void (*callback_trigger)(struct message_barrier* barrier);

struct message_barrier {
    atomic_t message_count;
    uint16_t type;
    uint16_t status;
    int successes;
    int failures;

    void* callback;
    callback_trigger trigger;
    void* linger_data;
    void* private;

    task_mutex barrier_mutex;
    task_cond barrier_cond;

    barrier_handler success_handler;
    barrier_handler failure_handler;

};

void init_message_barrier(struct message_barrier* barrier,
        void* priv_data, uint16_t type, barrier_handler sh,
        barrier_handler fh, callback_trigger cbt);

static inline int get_stat_size(uint16_t type) {
    switch(type) {
        case SVS_INSTANCE_STATS:
            return sizeof(struct sv_instance_stats);
        case SVS_SERVICE_STATS:
            return sizeof(struct sv_service_stats);
        case SVS_TABLE_STATS:
            return sizeof(struct sv_table_stats);
        case SVS_ROUTER_STATS:
            return sizeof(struct sv_router_stats);
        default:
            return 0;
    }
}

void message_barrier_default_cb(struct message_barrier* barrier, uint16_t type, const void* message,
        size_t len);
void wait_for_message_barrier(struct message_barrier* barrier);
void message_barrier_handle_success_default(struct message_barrier* barrier, const void* message,
        size_t len);
void message_barrier_handle_failure_default(struct message_barrier* barrier, const void* message,
        size_t len);

void destroy_int_key(void* data);

#endif /* SERVICE_TYPES_H_ */
