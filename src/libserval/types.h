/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _TYPES_H_
#define _TYPES_H_

#include <sys/types.h>
#include <netinet/serval.h>

/* These typedefs are for backwards compatibility with old defines in
 * libserval. The need for these should ideally go away in the
 * future. */
typedef struct flow_id sv_sock_t;
typedef struct service_id sv_srvid_t;
typedef struct host_addr sv_host_t;

#define s_srvid s_sid16

typedef struct {
	uint8_t v;
} sv_proto_t;

#define SERVAL_OK                  0
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

#endif /* _TYPES_H_ */
