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

#include "listen.hh"
#include <string.h>
//
// ListenReq
//

ListenReq::ListenReq()
        :Message(LISTEN_REQ), _use_first(true), _backlog(DEFAULT_BACKLOG)
{
    memset(&_local_service_id, 0xff, sizeof(_local_service_id));
    set_pld_len_v(serial_pld_len());
}

ListenReq::ListenReq(int backlog)
        :Message(LISTEN_REQ), _use_first(true), _backlog(backlog)
{
    memset(&_local_service_id, 0xff, sizeof(_local_service_id));
    set_pld_len_v(serial_pld_len());
}

ListenReq::ListenReq(sv_srvid_t service_id, int backlog)
        :Message(LISTEN_REQ), _use_first(false), _backlog(backlog)
{
    memcpy(&_local_service_id, &service_id, sizeof(service_id));
    set_pld_len_v(serial_pld_len());
}

uint16_t ListenReq::serial_pld_len() const
{
    return sizeof(_use_first) + sizeof(_local_service_id) + sizeof(_backlog);
}

int ListenReq::write_serial_payload(unsigned char *buf) const
{
    unsigned char *p = buf;
    p += serial_write(_use_first, p);
    p += serial_write(_local_service_id, p);
    p += serial_write(_backlog, p);
    return p - buf;
}

int ListenReq::read_serial_payload(const unsigned char *buf)
{
    const unsigned char *p = buf;
    p += serial_read(&_use_first, p);
    p += serial_read(&_local_service_id, p);
    p += serial_read(&_backlog, p);
    return p - buf;
}

void ListenReq::print(const char *label) const
{
    Message::print(label);
    info("%s: use_first=%s, local_service_id=%s, backlog=%d\n", label,
         (_use_first ? "t" : "f"), service_id_to_str(&_local_service_id), _backlog);
}

//
// ListenRsp
//

ListenRsp::ListenRsp()
        : Message(LISTEN_RSP), _err(SERVAL_OK)
{
    set_pld_len_v(serial_pld_len());
}

ListenRsp::ListenRsp(sv_err_t err)
        : Message(LISTEN_RSP), _err(err)
{
    set_pld_len_v(serial_pld_len());
}

uint16_t ListenRsp::serial_pld_len() const
{
    return sizeof(_err);
}

int ListenRsp::write_serial_payload(unsigned char *buf) const
{
    unsigned char *p = buf;
    p += serial_write(_err, p);
    return p - buf;
}

int ListenRsp::read_serial_payload(const unsigned char *buf)
{
    const unsigned char *p = buf;
    p += serial_read(&_err, p);
    return p - buf;
}

void ListenRsp::print(const char *label) const
{
    Message::print(label);
    info("%s: err=%d\n", label, _err.v);
}

