/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef STATE_HH
#define STATE_HH

#include <netinet/serval.h>
#include "types.h"

const char *
oid_to_str(sf_oid_t oid);

#define CRC_LEN 4

class State {
    static const char *state_str[];
  public:
    // states similar to DCCP rfc4340
    static const unsigned int MAX_STATES = 20;
    enum Type {
        CLOSED = 1,
        REGISTER,
        UNBOUND,
        REQUEST,
        RESPOND,
        BOUND,
        CLOSING,  // bound dgram only
        TIMEWAIT, // bound dgram only
        UNREGISTER,
        FAILOVER_WAIT,
        RECONNECT,
        RRESPOND,
        LISTEN,
        // TCP only
        TCP_FINWAIT1,
        TCP_FINWAIT2,
        TCP_CLOSEWAIT,
        TCP_LASTACK,
        TCP_SIMCLOSE,
    };
    static const char *state_s(const State::Type &);
};

class PacketType {
    static const char *packettype_str[];
  public:
    enum Type { DATA = 0, SYN = 1, SYNACK = 2, ACK = 3, RESET = 4, CLOSE = 5,
                MIG = 6, RSYN = 7, MIGDATA = 8, RSYNACK = 9 }; // sko
    static const char *packettype_s(const PacketType::Type &);
};

/*
  Return values for packet handling functions.
  This value determines the fate of the packet.
*/
typedef enum {
    PACKET_ERROR = -1,
    PACKET_HANDLED,
    PACKET_STOLEN,
} PacketRetval_t;

class sf_err_t {
  public:
    sf_err_t(): v(0) { }
    sf_err_t(uint8_t err)
            : v(err) { }
    sf_err_t(const sf_err_t &e)
            : v(e.v) { }
    sf_err_t &operator=(const sf_err_t &u) { v = u.v; return *this; }

    uint8_t v;
};

inline bool
operator==(const sf_err_t &u, const sf_err_t &v)
{
    return u.v == v.v;
}

inline bool
operator!=(const sf_err_t &u, const sf_err_t &v)
{
    return !(u == v);
}

// sf_oid_t

inline bool
operator==(const sf_oid_t &u, const sf_oid_t &v)
{
    return memcmp(&u, &v, sizeof(u)) == 0;
}

inline bool
operator!=(const sf_oid_t &u, const sf_oid_t &v)
{
    return !(u == v);
}

// sf_host_t

inline bool
operator==(const sf_host_t &u, const sf_host_t &v)
{
    return memcmp(&u, &v, sizeof(u)) == 0;
}

inline bool
operator!=(const sf_host_t &u, const sf_host_t &v)
{
    return !(u == v);
}

// sf_proto_t

inline bool
operator==(const sf_proto_t &u, const sf_proto_t &v)
{
    return u.v == v.v;
}

inline bool
operator!=(const sf_proto_t &u, const sf_proto_t &v)
{
    return !(u == v);
}

inline bool
operator==(const sf_proto_t &u, int v)
{
    return u.v == v;
}

inline bool
operator!=(const sf_proto_t &u, int v)
{
    return !(u == v);
}


// sf_sock_t

inline bool
operator==(const sf_sock_t &u, const sf_sock_t &v)
{
    return memcmp(&u, &v, sizeof(u)) == 0;
}

inline bool
operator!=(const sf_sock_t &u, const sf_sock_t &v)
{
    return !(u == v);
}

inline size_t
hashcode(const sf_sock_t &v)
{
    return v.s_id;
}

inline size_t
hashcode(const sf_oid_t &v)
{
    return v.s_sid16;
}

inline size_t
hashcode(const sf_host_t &v)
{
    return v.s_addr;
}

inline sf_sock_t
ip_to_sock_id(uint32_t ip)
{
    sf_sock_t p;
    p.s_id = ip & 0xffff;
    return p;
}

inline sf_oid_t
port_to_obj_id(uint16_t port)
{
    sf_oid_t p;
    p.s_sid16 = port;
    return p;
}

#define STRERROR_UNIMPL_STR "strerror unimplemented in kernel"
inline char *
_strerror_sf_r(int errnum, char *buf, size_t buflen)
{
    switch (errnum) {
        case ESOCKIDNOTAVAIL: 
            snprintf(buf, buflen, "%s", 
                     "SERVAL socket IDs unavailable");
            break;
        case ESCAFDUNREACH:
            snprintf(buf, buflen, "%s", 
                     "local SERVAL daemon unreachable");
            break;
        case ESFINTERNAL:
            snprintf(buf, buflen, "%s", 
                     "internal error in SERVAL socket library");
            break;
        case ESOCKNOTBOUND: 
            snprintf(buf, buflen, "%s", 
                     "SERVAL sockets must bind using bind() "
                     "prior to send, sendto, recv, recvfrom");
            break;
        case EFRESYNCPROG:
            snprintf(buf, buflen, "%s", 
                     "Connection to new instance in progress after failover");
            break;
        case EFRESYNCFAIL:
            snprintf(buf, buflen, "%s", 
                     "Connection to new instance failed");
            break;
        case ENEWINSTANCE:
            snprintf(buf, buflen, "%s", 
                     "Connected to new instance. Needs recovery.");
            break;
        default: 
#if defined(_GNU_SOURCE)
            return strerror_r(errnum, buf, buflen);
#else

            if (strerror_r(errnum, buf, buflen) == -1)
                return NULL;
            return buf;
#endif
    }
    return buf;
}

static char st_buf[256];
inline char *
_strerror_sf(int errnum)
{
    return _strerror_sf_r(errnum, st_buf, 256);
}

#endif
