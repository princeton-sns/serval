#ifndef _RESOLVER_PROTOCOL_H_
#define _RESOLVER_PROTOCOL_H_

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <netinet/serval.h>

/* #define CONTROLLER_OID 0xFFFE */
#define SERVICE_ROUTER_PREFIX 0xFFFFFFFF
#define SV_VERSION 0x10
#define ETH_ADDR_LEN 6
#define ANY_VALUE 0

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define NTOHLL(val) (((ntohl(val) & 0x00000000ffffffffULL) << 32) | (ntohl(val >> 32) & 0x00000000ffffffffULL))
#elif __BYTE_ORDER == __BIG_ENDIAN
#define NTOHLL(val) (val)
#else
#error " BYTE ORDERING not specified "
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define HTONLL(val) (((htonl(val) & 0x00000000ffffffffULL) << 32) | (htonl(val >> 32) & 0x00000000ffffffffULL))
#elif __BYTE_ORDER == __BIG_ENDIAN
#define HTONLL(val) (val)
#else
#error " BYTE ORDERING not specified "
#endif

#define get_service_count(message) (message->header.length - sizeof(message)) / sizeof(struct service_desc)
#define get_body_length(message) (message->header.length - sizeof(message))
#define get_stat_count(message, stattype) (message->header.length - sizeof(message)) / sizeof(stattype)

extern struct sockaddr_sv service_router_prefix;

//define the header format
enum sv_type {

    //service router bootstrap messages
    SV_DISCOVER_MESSAGE = 1,

    SV_DISAPPEAR_MESSAGE = 2,
    //basic service router "ping"
    SV_ECHO_REQUEST = 3,
    SV_ECHO_REPLY = 4,

    //service registration - authorization and authentication
    SV_REGISTER_REQUEST = 5,
    SV_UNREGISTER_REQUEST = 6,

    //service update (load and meta/stat info)
    SV_UPDATE_REQUEST = 7,
    SV_UPDATE_MESSAGE = 8,

    //service query
    SV_QUERY_REQUEST = 9,
    SV_QUERY_REPLY = 10,

    SV_RESOLUTION_REQUEST = 11,
    SV_RESOLUTION_REPLY = 12,

    SV_ACK = 253,
    SV_TIMEOUT = 254,
    SV_ERROR = 255
};

//Serval service router protocol primitive data types
typedef uint64_t uid;

//authentication credentials?
struct service_desc {
    uint16_t type; //unused - really it's padding, but may be useful later
    uint8_t flags;
    uint8_t prefix;
    struct service_id service;
};

//28 bytes
struct sv_control_header {
    uint8_t version;
    //message type: discover, leave, etc
    uint8_t type;
    //total length of control packet including scaffold header
    uint16_t length;
    //transaction id
    uint32_t xid;

    //these should actually correspond to the serviceID's - peer ID's?
    //uid source_id;
    //unique source dest ID - 0 for "ANY"
    //uid dest_id;

    //credentials: public auth key,principal id?
    //authentication digest?

    //    const std::string to_string() const {
    //        std::string str("<scaffold header: ");
    //        char val[64];
    //        sprintf(val, "%.2X:%u:%llX:%llX:%u:%u:%u", version, type, source_id, dest_id, dc_id, id,
    //                length);
    //        str += val;
    //        str += " >";
    //        return str;
    //    }
};
//pack the attributes? - not if we use padding

enum sv_prefix_flags {
    SVPF_STUB = 0, SVPF_TRANSIT = 1 << 0, SVPF_DELEGATE = 1 << 1, SVPF_AUTH = 1 << 2
};

//service router discovery:
//24 bytes + header
enum sv_discover_flags {
    DISCOVER_NOTIFY = 1 << 0, DISCOVERY_PROPAGATE = 1 << 1
/*high-order byte reserved for propagate counter*/

};

#define PROPAGATE_TTL(flags) (flags >> 8)
#define INC_PROPAGATE_TTL(flags, ttl) flags &= (0x00FF | (((flags >> 8) + (uint8_t) ttl) << 8))
#define DEC_PROPAGATE_TTL(flags, ttl) flags &= (0x00FF | (((flags >> 8) - (uint8_t) ttl) << 8))

struct sv_discover_message {
    struct sv_control_header header;
    uint16_t flags; /* notify me, or broadcast notifcation only, i.e. req or resp */
    char pad[2];
    struct service_desc resolver_id;
    struct net_addr resolver_addr;

    //uid sv_id; //may not be necessary if the src serviceID corresponds to a unique serviceID
    uint32_t uptime; //uptime in seconds - determines peer reboot
    uint32_t capabilities; //reference openflow? (transit, terminal, authoritative,specialized)
    uint32_t capacity; //(table size in K?, req/s, etc)
    //n_tables - resolution tables?

    // hierarchy (network position) - clustering and alignment
    // tier designation or traceroute signature (hash to group/tier)

    //authoritative or selective/delegate services
    struct service_desc service_prefixes[0];
};

enum sv_stats {
    SVS_INSTANCE_STATS = 1 << 0,
    SVS_SERVICE_STATS = 1 << 1,
    SVS_TABLE_STATS = 1 << 2,
    SVS_ROUTER_STATS = 1 << 3,

    SVS_HAS_MORE = 1 << 15
};

enum sv_capabilities {
    SVC_TRANSIT = 1 << 0, /*Can perform resolution/redireciton - if not set, then the SR is terminal for non-specified prefixes*/
    SVC_DELEGATE = 1 << 1, /*Can function as a delegate resolver for specific prefixes/SID's - not nec general transit*/
    SVC_AUTH = 1 << 2, /*Can act as an authoritative resolver for specified prefixes*/
    SVC_COORDINATOR = 1 << 3 /*Can function as a coordinator for other service routers, but does not resolve packets itself*/

};

#define is_stub(cap) cap == 0
#define is_transit(cap) cap & SVC_TRANSIT
#define is_delegate(cap) cap & SVC_DELEGATE
#define is_authoritative(cap) cap & SVC_AUTH

//x bytes + header
struct sv_disappear_message {
    struct sv_control_header header;
    uint16_t flags;
    char pad[2];
    struct service_desc resolver_id;
    struct net_addr resolver_addr;
};

struct sv_service_stats {
    struct service_desc service;
    uint32_t instance_count;
    uint32_t duration_sec;
    uint32_t duration_nsec;
    uint32_t packets_resolved;
    uint32_t packets_dropped;
    uint32_t bytes_resolved;
    uint32_t bytes_dropped;
    uint32_t tokens_consumed;
    //last idle - or average idle (inter-arrival) time
};

struct sv_instance_stats {
    struct service_desc service;
    struct net_addr address;
    uint16_t priority;
    uint16_t weight;
    uint16_t idle_timeout;
    uint16_t hard_timeout;
    uint32_t duration_sec;
    uint32_t duration_nsec;
    uint32_t packets_resolved;
    uint32_t bytes_resolved;
    uint32_t packets_dropped;
    uint32_t bytes_dropped;
    uint32_t tokens_consumed;
    //last idle - or average idle (inter-arrival) time
};

struct sv_table_stats {
    uint32_t max_entries;
    uint32_t service_count;
    uint32_t instance_count;
    uint32_t packets_resolved;
    uint32_t packets_dropped;
    uint32_t bytes_resolved;
    uint32_t bytes_dropped;
};

struct sv_router_stats {
    uint16_t tables;
    uint16_t peers;
    uint32_t service_count;
    uint32_t instance_count;
    uint32_t packets_resolved;
    uint32_t packets_dropped;
    uint32_t bytes_resolved;
    uint32_t bytes_dropped;
    //load? instantaneous, 1 min, 5 min, 10 min?
};

struct sv_update_request {
    struct sv_control_header header;
    uint16_t type;
    uint16_t flags;
    struct service_desc service_ids[0];
};

struct sv_update_message {
    struct sv_control_header header;
    uint16_t type;
    uint16_t flags; /*count in the stat_response header...*/
    uint8_t body[0]; //array of stats structs
};

/*service registration
 no explicitly defined reply messages
 all replies are either ACKs or ERRORs
 */

//12 bytes + x + header
struct sv_register_message {
    struct sv_control_header header;
    uint32_t ttl; //object ttl in seconds (ms?)
    struct net_addr address;
    //TODO - authorization certificates/tokens? or should these be configured at NOX
    struct service_desc service_ids[0];
};

#define NUM_SERVICES(message, len) (len - sizeof(*message)) / sizeof(struct service_desc)

struct sv_unregister_message {
    struct sv_control_header header;
    struct net_addr address;
    struct service_desc service_ids[0];
};

//liveness "ping" from controller to host or vice-versa
//4 bytes + x + header
struct sv_echo_message {
    struct sv_control_header header;
    uint32_t count;
    /* timestamp for rtt estimation - reflected
     * on echo reply
     */
    uint32_t timestamp;
};

struct sv_query_request {
    struct sv_control_header header;
    //other limits?
    struct service_desc service_ids[0];
};

struct sv_query_response {
    struct sv_control_header header;
    uint16_t flags;
    char pad[2];
    struct service_desc service_ids[0];
};

struct sv_resolution_request {
    struct sv_control_header header;
    struct service_desc service_id;
};

struct sv_resolution_response {
    struct sv_control_header header;
    struct service_desc service_id;
    struct net_addr address;
};

//only sent in response to a message/request
struct sv_error_reply {
    struct sv_control_header header;
    uint16_t error_type;
    uint16_t message_type;
    //ttl/lease request
    uint8_t body[0];
};

enum sv_error {
    SV_ERR_INVALID_VERSION = 1,
    SV_ERR_INVALID_TYPE = 2,
    SV_ERR_INVALID_ARG = 3,
    SV_ERR_UNAUTHORIZED = 4,
    SV_ERR_SERVICE_NOT_FOUND = 5,
    SV_ERR_PEER_DECLINED = 6,
    SV_ERR_PEER_UNKNOWN = 7,
    SV_ERR_INVALID_ECHO_COUNT = 8,
    SV_ERR_SYSTEM_ERROR = 1000
};

#endif /* _RESOLVER_PROTOCOL_H_ */
