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

#include "message.hh"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/un.h>
#include <assert.h>

const char *Message::msg_str[] = {
    "MSG_UNKNOWN",
    "MSG_BIND_REQ", 
    "MSG_BIND_RSP",
    "MSG_CONNECT_REQ", 
    "MSG_CONNECT_RSP",
    "MSG_LISTEN_REQ", 
    "MSG_LISTEN_RSP",
    "MSG_ACCEPT_REQ", 
    "MSG_ACCEPT_RSP",
    "MSG_ACCEPT2_REQ", 
    "MSG_ACCEPT2_RSP",
    "MSG_SEND_REQ", 
    "MSG_SEND_RSP",
    "MSG_RECV_REQ", 
    "MSG_RECV_RSP",
    "MSG_CLOSE_REQ", 
    "MSG_CLOSE_RSP",
    "MSG_RECVMESG", 
    "MSG_CLEAR_DATA", 
    "MSG_HAVE_DATA",
    NULL
};

int Message::read_hdr(const unsigned char *buf)
{
    if (check_buf(buf, __FILE__, __LINE__) < 0) {
        lerr("check_buf failed");
        return -1;
    }

    const unsigned char *p = buf;
    p += serial_read(&_version, p);
    p += serial_read(&_type, p);
    p += serial_read(&_pld_len_v, p);

    if (check_hdr() < 0) {
        lerr("check header failed");
        return -1;
    }

    info("Message::read (hdr) version = %d, type = %d, len = %d",
         _version, _type, _pld_len_v);
    return p - buf;
}

int Message::write_hdr(unsigned char *buf) const
{
    if (check_buf(buf, __FILE__, __LINE__) < 0)
        return -1;
    unsigned char *p = buf;
    p += serial_write(_version, p);
    p += serial_write(_type, p);
    p += serial_write(_pld_len_v, p);
    info("Message::write (hdr) version = %d, type = %d, len = %d",
         _version, _type, _pld_len_v);
    return p - buf;
}

int Message::write_to_stream_soc(int soc)
{
    sv_err_t err;
    if (write_to_stream_soc(soc, err) < 0) {
        lerr("write_to_stream_soc failed with error %s", 
             _strerror_sv(err.v));
        return -1;
    }
    return 0;
}

int Message::write_to_stream_soc(int soc, sv_err_t &err) /*  const */
{
    int slen = serial_len();
    info("writing %d bytes to stream soc %d", slen, soc);
    unsigned char *buf = new unsigned char[slen];

    if (buf == NULL) {
        err = ENOMEM;
        return -1;
    }

    if (write_serial(buf) < 0) {
        delete[] buf;
        err = ESVINTERNAL;
        return -1;
    }

    int iovcnt = nonserial_pld_len() > 0 ? 2 : 1;
    struct iovec *vec = new struct iovec[iovcnt];
    vec[0].iov_base = buf;
    vec[0].iov_len = slen;
    if (iovcnt == 2) {
        vec[1].iov_base = nonserial_buf_mutable();
        vec[1].iov_len = nonserial_pld_len();
    }

    int n = 0;
    if ((n = SockIO::writev(soc, vec, iovcnt)) <= 0) {
        //(n += SockIO::writen(soc, nonserial_buf(), nonserial_pld_len())) < 0)) {
        delete[] buf;
        delete[] vec;
        if (n == 0)  // EOF
            return 0;
        err = ESVINTERNAL;
        return -1;
    }
    delete[] buf;
    delete[] vec;

    assert (n == serial_len() + nonserial_pld_len());
    info("Message::write_to_stream_soc "
         "wrote %d bytes total (serial:%d, nonserial:%d)", n,
         serial_len(), nonserial_pld_len());
    return n;
}

int Message::read_from_stream_soc(int soc, sv_err_t &err)
{
    int r1 = read_hdr_from_stream_soc(soc, err);
    if (r1 == 0) {
        lerr("Message::read_from_stream_soc EOF received");
        return 0;
    } else if (r1 < 0)
        return -1;

    int r2 = 0;
    if (pld_len()) {
        r2 = read_pld_from_stream_soc(soc, err);
        if (r2 == 0) {
            lerr("Message::read_from_stream_soc EOF received");
            return 0;
        } else if (r2 < 0)
            return -1;
    }
    assert (r1+r2 == total_len());
    return r1+r2;
}

int Message::read_hdr_from_stream_soc(int soc, sv_err_t &err)
{
    int len = hdr_len();
    unsigned char *buf = new unsigned char[len];

    int n = SockIO::readn(soc, buf, len);

    if (n == 0) {
        lerr("Message::read_hdr_from_stream_soc EOF received");
        delete [] buf;
        return 0;
    }

    if (n < 0 || read_hdr(buf) < 0) {
        delete[] buf;
        lerr("Message::read_hdr_from_stream_soc failed n=%d", n);
        err = errno;
        return -1;
    }

    SockIO::print("Message::read_hdr_from_stream_soc", buf, len);
    delete[] buf;
    return len;
}

int Message::read_pld_from_stream_soc(int soc, sv_err_t &err)
{
    if (!pld_len())
        return 0;

    int slen = serial_pld_len();
    if (slen) {
        unsigned char *buf = new unsigned char[slen];
        int n = SockIO::readn(soc, buf, slen);

        if (n == 0) {
            lerr("Message::read_pld_from_stream_soc EOF received");
            delete [] buf;
            return 0;
        }
        
        info("readn returned n=%d slen=%d", n, slen);

        if (n < 0 || read_serial_payload(buf) < 0) {
            delete[] buf;
            lerr("Message::read_pld_from_stream_soc failed");
            err = ESVINTERNAL;
            return -1;
        }
        SockIO::print("Message::read_pld_from_stream_soc", buf, slen);
        delete[] buf;
    }

    if (nonserial_pld_len()) {
        info("reading %d bytes non-serial payload", nonserial_pld_len());
        assert (nonserial_buf_mutable());  // user manages nonserial buf alloc
        int n = SockIO::readn(soc, nonserial_buf_mutable(), 
                              nonserial_pld_len());
        if (n == 0) {
            lerr("Message::read_from_stream_soc EOF "
                 "received during nonserial rd");
            return 0;
        }

        if (n < 0) {
            err = ESVINTERNAL;
            lerr("Message::read_from_stream_soc reading "
                 "non-serial payload failed");
            return -1;
        }
    }
    SockIO::print("Message::read_from_stream_soc", nonserial_buf_mutable(),
                  nonserial_pld_len());
    return pld_len();
}

int Message::write_serial(unsigned char *buf) const
{
    if (check_buf(buf, __FILE__, __LINE__) < 0)
        return -1;
    unsigned char *p = buf;
    int n;
    if ((n = write_hdr(p)) < 0) {
        lerr("Message::write header failed");
        return -1;
    }
    p += n;
    if ((n = write_serial_payload(p)) < 0) {
        lerr("Message::write payload failed");
        return -1;
    }
    p += n;
    SockIO::print("Message::write", buf, serial_len());
    return p - buf;
}
