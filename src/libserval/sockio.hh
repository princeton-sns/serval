/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef SOCKIO_HH
#define SOCKIO_HH

#include <sys/types.h>
#include <stdio.h>

class SockIO {
  public:
    typedef int io_sock_t;
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
serial_read(T *service, const unsigned char *buf)
{
    size_t u = sizeof(*service);
    memcpy(service, buf, u);
    return u;
}

template<typename T> size_t
serial_write(const T &service, unsigned char *buf)
{
    size_t u = sizeof(service);
    memcpy(buf, &service, u);
    return u;
}

#endif /* SOCKIO_HH */
