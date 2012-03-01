/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
// Copyright (c) 2010 The Trustees of Princeton University (Trustees)

// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and/or hardware specification (the “Work”) to deal
// in the Work without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Work, and to permit persons to whom the Work is
// furnished to do so, subject to the following conditions: The above
// copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Work.

// THE WORK IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE WORK OR THE USE OR OTHER
// DEALINGS IN THE WORK.


#include <libserval/serval.h>
#include "socket.hh"

static SVSockLib sock;

int socket_sv(int domain, int type, int protocol)
{
    sv_err_t err;
  
    int s = sock.socket_sv(domain, type, protocol, err);
    if (s == SERVAL_SOCKET_ERROR) {
        errno = err.v;
        return -1;
    }
    return s;
}

int bind_sv(int soc, const struct sockaddr *address, socklen_t address_len)
{
    sv_err_t err;

    int n = sock.bind_sv(soc, address, address_len, err);
    if (n  == SERVAL_SOCKET_ERROR) {
        errno = err.v;
        return -1;
    }
    return n;
}

int connect_sv(int soc, const struct sockaddr *address, socklen_t address_len)
{ 
    sv_err_t err;

    if (address->sa_family != AF_SERVAL) {
        info("connecting with non-Serval socket.");
        return ::connect(soc, address, address_len);
    }
    int n = sock.connect_sv(soc, address, address_len, err);
    if (n == SERVAL_SOCKET_ERROR) {
        errno = err.v;
        return -1;
    }
    return n;
}

int listen_sv(int soc, int backlog)
{
    sv_err_t err;
    int n;
    n = sock.listen_sv(soc, backlog, err);
    if (n == SERVAL_SOCKET_ERROR) {
        errno = err.v;
        return -1;
    }
    return n;
}

int accept_sv(int soc, struct sockaddr *address, socklen_t *addr_len)
{
    sv_err_t err;

    int fd = sock.accept_sv(soc, address, addr_len, err);
    if (fd == SERVAL_SOCKET_ERROR) {
        errno = err.v;
        return -1;
    }
    return fd;
}

ssize_t send_sv(int soc, const void *buffer, size_t length, int flags)
{
    sv_err_t err;
    int n = sock.send_sv(soc, buffer, length, flags, err);

    if (n == SERVAL_SOCKET_ERROR) {
        errno = err.v;
        return -1;
    } 
    
    return n;
}

ssize_t recv_sv(int soc, void *buffer, size_t length, int flags)
{
    sv_err_t err;
    int n = sock.recv_sv(soc, buffer, length, flags, err);
    if (n == SERVAL_SOCKET_ERROR) {
        errno = err.v;
        return -1;
    }
    return n;
}

ssize_t sendmsg_sv(int soc, const struct msghdr *message, int flags)
{
    sv_err_t err;
    int n = sock.sendmsg_sv(soc, message, flags, err);

    if (n == SERVAL_SOCKET_ERROR) {
        errno = err.v;
        return -1;
    }

    return n;
}

ssize_t recvmsg_sv(int soc, struct msghdr *message, int flags)
{
    sv_err_t err;
    int n = sock.recvmsg_sv(soc, message, flags, err);
    if (n == SERVAL_SOCKET_ERROR) {
        errno = err.v;
        return -1;
    }
    return n;
}

ssize_t sendto_sv(int soc, const void *buffer, size_t length, int flags,
                  const struct sockaddr *dest_addr, socklen_t dest_len)
{
    sv_err_t err;
    int n = sock.sendto_sv(soc, buffer, length, flags, 
                           dest_addr, dest_len, err);
    if (n == SERVAL_SOCKET_ERROR) {
        errno = err.v;
        return -1;
    }
    return n;
}

ssize_t recvfrom_sv(int soc, void *buffer, size_t length, int flags,
                    struct sockaddr *address, socklen_t *address_len)
{
    sv_err_t err;
    int n = sock.recvfrom_sv(soc, buffer, length, flags, 
                             address, address_len, err);
    if (n == SERVAL_SOCKET_ERROR) {
        errno = err.v;
        return -1;
    }
    return n;
}

int getsockopt_sv(int soc, int level, int option_name, 
                  void *option_value, socklen_t *option_len)
{
    sv_err_t err;
    int n = sock.getsockopt_sv(soc, level, option_name, option_value, 
                               option_len, err);
    if (n == SERVAL_SOCKET_ERROR) {
        errno = err.v;
        return -1;
    }
    return n;
}

int close_sv(int fd)
{
    sv_err_t err;
    int n = sock.close_sv(fd, err);
    if (n == SERVAL_SOCKET_ERROR) {
        errno = err.v;
        return -1;
    }
    return n;
}

char *strerror_sv(int errnum)
{
    return _strerror_sv(errnum);
}
