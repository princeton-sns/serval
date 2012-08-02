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
	int v;
} sv_proto_t;

#define SERVAL_OK            0
#define ESOCKIDNOTAVAIL      200   /* Exhausted socket ids for host */
#define ESCAFDUNREACH        201   /* Cannot reach Scafd daemon */
#define ESVINTERNAL          202   /* undiagnosed internal Serval errors */
#define ESOCKNOTBOUND        203   /* all SF sockets must call bind()
                                      prior to send, sendto, recv, recvfrom */

#endif /* _TYPES_H_ */
