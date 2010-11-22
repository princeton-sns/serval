#ifndef _TYPES_H_
#define _TYPES_H_

#include <sys/types.h>
#include <netinet/scaffold.h>

typedef struct sock_id sf_sock_t;
typedef struct service_id sf_oid_t;
typedef struct host_addr sf_host_t;

#define s_oid s_sid16
#define sf_oid sf_srvid

typedef struct {
    uint8_t v;
} sf_proto_t;

#define SF_OK                  0
#define ESOCKIDNOTAVAIL      200   /* Exhausted socket ids for host */
#define ESCAFDUNREACH        201   /* Cannot reach Scafd daemon */
#define ESFINTERNAL          202   /* undiagnosed internal SF errors */
#define ESOCKNOTBOUND        203   /* all SF sockets must call bind()
                                      prior to send, sendto, recv, recvfrom */
#define ENOTRECONN           204
#define EFAILOVER            205   /* cannot do operation since 
                                      socket is in failover mode */

#define ENEWINSTANCE         206   /* connected to a new instance 
                                      do recovery if needed
                                   */
#define EFRESYNCPROG         207   /* resync after failover in progress */
#define EFRESYNCFAIL         208   /* resync after failover failed */

/* Reserved Object IDs */
#define CONTROLLER_OID 0xFFFE
#define SCAFFOLD_OID 0xFFFD
#define SCAFFOLD_NULL_OID 0xFFFF

#endif /* _TYPES_H_ */
