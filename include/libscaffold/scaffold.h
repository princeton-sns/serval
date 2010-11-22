#ifndef _LIBSCAFFOLD_H_
#define _LIBSCAFFOLD_H_

#include <netinet/scaffold.h>
#include <stdio.h>

/* Reserved Object IDs */
#define CONTROLLER_OID 0xFFFE
#define SCAFFOLD_OID 0xFFFD
#define SCAFFOLD_NULL_OID 0xFFFF

/* connect_sf() or listen_sf() flags
   typically SF_WANT_FAILOVER in connect_sf and
   SF_HAVE_FAILOVER in listen_sf */
#define SF_WANT_FAILOVER 0x01
#define SF_HAVE_FAILOVER 0x02

#if defined(SCAFFOLD_NATIVE_API)

#define socket_sf socket
#define bind_sf bind
#define connect_sf connect
#define listen_sf listen
#define accept_sf accept
#define send_sf send
#define recv_sf recv
#define close_sf close
#define sendto_sf sendto
#define recvfrom_sf recvfrom
#define strerror_sf_r strerror_r
#define strerror_sf strerror

static inline int migrate_sf(int socket) 
{
    return ioctl(socket, SIOCSFMIGRATE);
}

#else

#ifdef __cplusplus
extern "C"
#endif
int 
socket_sf(int domain, int type, int protocol);

#ifdef __cplusplus
extern "C"
#endif
int
bind_sf(int socket, const struct sockaddr *address, socklen_t address_len);

#ifdef __cplusplus
extern "C"
#endif
int 
connect_sf(int socket, const struct sockaddr *address, 
           socklen_t address_len);

#ifdef __cplusplus
extern "C"
#endif
int 
mlisten_sf(int socket, int backlog, 
           const struct sockaddr *addr, 
           socklen_t address_len);

/* top 16 bits of backlog reserved for flags (e.g., SF_HAVE_FAILOVER) */
#ifdef __cplusplus
extern "C"
#endif
int 
listen_sf(int socket, int backlog); 


#ifdef __cplusplus
extern "C"
#endif
int 
accept_sf(int socket, struct sockaddr *address, 
          socklen_t *addr_len);

#ifdef __cplusplus
extern "C"
#endif
ssize_t 
send_sf(int socket, const void *buffer, size_t length, int flags);

#ifdef __cplusplus
extern "C"
#endif
ssize_t 
recv_sf(int socket, void *buffer, size_t length, int flags);

#ifdef __cplusplus
extern "C"
#endif
int
close_sf(int filedes);

#ifdef __cplusplus
extern "C"
#endif
ssize_t 
sendto_sf(int socket, const void *buffer, size_t length, int flags,
          const struct sockaddr *dest_addr, socklen_t dest_len);

#ifdef __cplusplus
extern "C"
#endif
ssize_t 
recvfrom_sf(int socket, void *buffer, size_t length, int flags,
            struct sockaddr *address, socklen_t *address_len);

#ifdef __cplusplus
extern "C"
#endif
int
getsockopt_sf(int soc, int level, int option_name, 
              void *option_value, socklen_t *option_len);

#ifdef __cplusplus
extern "C"
#endif
char *
strerror_sf_r(int errnum, char *buf, size_t buflen);

#ifdef __cplusplus
extern "C"
#endif
char *
strerror_sf(int errnum);

/* sko begin */
#ifdef __cplusplus
extern "C"
#endif
int 
migrate_sf(int socket);
/* sko end */

/* Implemented in state.cc */
#ifdef __cplusplus
extern "C"
#endif
const char *
srvid_to_str(struct service_id srvid);

#endif /* SCAFFOLD_NATIVE_API */


#endif /* _LIBSCAFFOLD_H_ */
