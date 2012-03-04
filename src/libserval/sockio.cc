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

#include "sockio.hh"

#include <sys/types.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "log.hh"

#ifdef DEBUG_MODE
#define MAX_DBG_STRLEN 512
void SockIO::print(const char *label, const unsigned char *buf, int buflen)
{
    return;
    char str[MAX_DBG_STRLEN + 1];
    size_t len = 0;

    for (int i = 0; i < buflen; i++)
        len += snprintf(str + len, MAX_DBG_STRLEN, "%d: ", (int)buf[i]);

    info("%s:%d bytes =  %s", label, buflen, str);
    return;
}
#endif
//
// SockIO, only blocking I/O
//
int SockIO::readn(io_sock_t fd, void *vptr, int n)
{
    size_t nleft;
    int nr;
    char *ptr;

    ptr = (char *)vptr;
    nleft = n;
    while (nleft > 0) {
        if ( (nr = ::read(fd, ptr, nleft)) < 0 &&
             errno != ECONNRESET) {
            if (errno == EINTR)
                //nr = 0;
                return -1;
            else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                //lerr("SockIO::readn only supports blocking IO (got %s)",
                //strerror(errno));
                return -1;
            } else {
                lerr("SockIO::readn error %s", strerror(errno));
                return -1;
            }
        } else if (nr == 0 && nleft > 0) {
            lerr("SockIO::readn EOF");
            return 0;
        } else if (errno == ECONNRESET) {
            lerr("SockIO::readn ECONNRESET");
            return 0;
        }
        nleft -= nr;
        ptr += nr;
        info("nleft = %d", nleft);
    }
    info("SockIO:readn read %d bytes", n - nleft);
    return (n - nleft);
}

int SockIO::writen(io_sock_t fd, const void *vptr, int n)
{
    int nleft;
    int nwritten;
    const char *ptr;

    ptr = (char *)vptr;
    nleft = n;
    while (nleft > 0) {
        if ( (nwritten = ::write(fd, ptr, nleft)) <= 0) {
            if (nwritten < 0 && errno == EINTR)
                nwritten = 0;
            else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                lerr("SockIO::writen only supports blocking IO (got %s)",
                     strerror(errno));
                return -1;
            } else if (errno == EPIPE) {
                lerr("SockIO::writen cLosed socket (%s)",
                     strerror(errno));
                return 0;
            } else {
                lerr("SockIO::writen error %s", strerror(errno));
                return -1;
            }
        }
        nleft -= nwritten;
        ptr += nwritten;
    }
    info("SockIO:writen wrote %d bytes", n);
    return n;
}

int SockIO::writev(io_sock_t fd, struct iovec *iov, int iovcnt)
{
    size_t nleft;
    ssize_t nwritten;
    struct iovec *fptr = iov;
    nleft = iovcnt;
    int nbytes = 0;
    while (nleft > 0) {
        if ( (nwritten = ::writev(fd, (const struct iovec *)iov, nleft)) <= 0) {
            if (nwritten < 0 && errno == EINTR)
                nwritten = 0;
            else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                lerr("SockIO::writev only supports blocking IO (got %s)",
                     strerror(errno));
                return -1;
            } else if (errno == EPIPE) {
                lerr("SockIO::writev closed socket (%s)",
                     strerror(errno));
                return 0;
            } else {
                lerr("SockIO::writev error %s", strerror(errno));
                return -1;
            }
        }
        size_t p = nwritten;
        nbytes += nwritten;
        while (p > 0) {
            if (p >= fptr->iov_len) {
                p -= fptr->iov_len;
                nleft--;
                fptr++;
            } else {
                fptr->iov_len -= p;
                unsigned char *x = static_cast<unsigned char *>(fptr->iov_base);
                x += p;
                fptr->iov_base = x;
                p = 0;
            }
        }
    }
    info("SockIO:writev wrote %d bytes %d chunks", nbytes, iovcnt);
    return nbytes;
}
