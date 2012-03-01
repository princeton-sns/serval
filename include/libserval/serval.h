/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _LIBSERVAL_H_
#define _LIBSERVAL_H_

#include <netinet/serval.h>
#include <stdio.h>

/* Reserved ServiceIDs */
extern struct service_id _controller_srvid;
extern struct service_id _serval_srvid;
extern struct service_id _serval_null_srvid;
#define CONTROLLER_SID (&_controller_srvid)
#define SERVAL_SID (&_serval_srvid)
#define SERVAL_NULL_SID (&_serval_null_srvid)

#if defined(SERVAL_NATIVE)

#define socket_sv socket
#define bind_sv bind
#define connect_sv connect
#define listen_sv listen
#define accept_sv accept
#define send_sv send
#define sendmsg_sv sendmsg
#define recv_sv recv
#define recvmsg_sv recvmsg
#define close_sv close
#define sendto_sv sendto
#define recvfrom_sv recvfrom
#define strerror_sv_r strerror_r
#define strerror_sv strerror

#include <sys/ioctl.h>

#else

#ifdef __cplusplus
extern "C"
#endif
int socket_sv(int domain, int type, int protocol);

#ifdef __cplusplus
extern "C"
#endif
int bind_sv(int socket, const struct sockaddr *address, socklen_t address_len);

#ifdef __cplusplus
extern "C"
#endif
int connect_sv(int socket, const struct sockaddr *address, 
               socklen_t address_len);

#ifdef __cplusplus
extern "C"
#endif
int listen_sv(int socket, int backlog); 


#ifdef __cplusplus
extern "C"
#endif
int accept_sv(int socket, struct sockaddr *address, 
              socklen_t *addr_len);

#ifdef __cplusplus
extern "C"
#endif
ssize_t send_sv(int socket, const void *buffer, size_t length, int flags);

#ifdef __cplusplus
extern "C"
#endif
ssize_t recv_sv(int socket, void *buffer, size_t length, int flags);

#ifdef __cplusplus
extern "C"
#endif
ssize_t sendmsg_sv(int socket, const struct msghdr *message, int flags);

#ifdef __cplusplus
extern "C"
#endif
ssize_t recvmsg_sv(int socket, struct msghdr *message, int flags);

#ifdef __cplusplus
extern "C"
#endif
int
close_sv(int filedes);

#ifdef __cplusplus
extern "C"
#endif
ssize_t sendto_sv(int socket, const void *buffer, size_t length, int flags,
                  const struct sockaddr *dest_addr, socklen_t dest_len);

#ifdef __cplusplus
extern "C"
#endif
ssize_t recvfrom_sv(int socket, void *buffer, size_t length, int flags,
                    struct sockaddr *address, socklen_t *address_len);

#ifdef __cplusplus
extern "C"
#endif
int getsockopt_sv(int soc, int level, int option_name, 
                  void *option_value, socklen_t *option_len);

#ifdef __cplusplus
extern "C"
#endif
char *strerror_sv_r(int errnum, char *buf, size_t buflen);

#ifdef __cplusplus
extern "C"
#endif
char *strerror_sv(int errnum);

/* Implemented in state.cc */
#ifdef __cplusplus
extern "C"
#endif
const char *srvid_to_str(struct service_id srvid);

#endif /* SERVAL_NATIVE */

#endif /* _LIBSERVAL_H_ */
