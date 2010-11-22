/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef SOCKIO_HH
#define SOCKIO_HH

#if defined(__KERNEL__)
#include <linux/types.h>
#include <linux/socket.h>
#else
#include <sys/types.h>
#include <stdio.h>
#endif

class SockIO {
  public:
#if defined(__KERNEL__)
    typedef struct socket* io_sock_t;
#else
    typedef int io_sock_t;
#endif
    static int writen(io_sock_t fd, const void *vptr, int n);
    static int writev(io_sock_t fd, struct iovec *iov, int iovcnt);
    static int readn(io_sock_t fd, void *vptr, int n);
#ifdef DEBUG_MODE
    static void print(const char *, const unsigned char *, int);
#else
    static void print(const char *, const unsigned char *, int) { return; }
#endif
};

template<typename T> size_t
serial_read(T *obj, const unsigned char *buf)
{
    size_t u = sizeof(*obj);
    memcpy(obj, buf, u);
    return u;
}

template<typename T> size_t
serial_write(const T &obj, unsigned char *buf)
{
    size_t u = sizeof(obj);
    memcpy(buf, &obj, u);
    return u;
}

#endif
