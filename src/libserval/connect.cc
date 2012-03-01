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

#include "connect.hh"
#include "log.hh"

//
// ConnectReq
//

ConnectReq::ConnectReq()
        :Message(CONNECT_REQ)
{

    memset(&_service_id, 0xff, sizeof(_service_id));
    _nb = false;
    _flags = 0;
    set_pld_len_v(serial_pld_len());
}


ConnectReq::ConnectReq(const sv_srvid_t& service_id, bool nb, uint16_t flags)
        :Message(CONNECT_REQ), _nb(nb), _flags(flags)
{
    memcpy(&_service_id, &service_id, sizeof(service_id));
    set_pld_len_v(serial_pld_len());
}

int
ConnectReq::check_type() const
{
    return _type == CONNECT_REQ;
}

uint16_t
ConnectReq::serial_pld_len() const
{
    return sizeof(_service_id) + sizeof(_nb) + sizeof(_flags);
}

int
ConnectReq::write_serial_payload(unsigned char *buf) const
{
    unsigned char *p = buf;
    p += serial_write(_service_id, p);
    p += serial_write(_nb, p);
    p += serial_write(_flags, p);
    return p - buf;
}

int
ConnectReq::read_serial_payload(const unsigned char *buf)
{
    const unsigned char *p = buf;
    p += serial_read(&_service_id, p);
    p += serial_read(&_nb, p);
    p += serial_read(&_flags, p);
    return p - buf;
}

void
ConnectReq::print(const char *label) const
{
    Message::print(label);
    info("%s: service_id=%s, nb = %s, flags = %d", 
         label, service_id_to_str(&_service_id), _nb ? "t" : "f", _flags);
}

//
// ConnectRsp
//
ConnectRsp::ConnectRsp()
        : Message(CONNECT_RSP), _err(0)
{
    memset(&_service_id, 0xff, sizeof(_service_id));
    set_pld_len_v(serial_pld_len());
}


ConnectRsp::ConnectRsp(const sv_srvid_t& service_id, sv_err_t err)
        : Message(CONNECT_RSP), _err(err)
{
    memcpy(&_service_id, &service_id, sizeof(service_id));
    set_pld_len_v(serial_pld_len());
}

int
ConnectRsp::check_type() const
{
    return _type == CONNECT_RSP;
}

uint16_t
ConnectRsp::serial_pld_len() const
{
    return sizeof(_service_id) + sizeof(_err);
}

int
ConnectRsp::write_serial_payload(unsigned char *buf) const
{
    unsigned char *p = buf;
    p += serial_write(_service_id, p);
    p += serial_write(_err, p);
    return p - buf;
}

int
ConnectRsp::read_serial_payload(const unsigned char *buf)
{
    const unsigned char *p = buf;
    p += serial_read(&_service_id, p);
    p += serial_read(&_err, p);
    return p - buf;
}

void
ConnectRsp::print(const char *label) const
{
    Message::print(label);
    info("%s: service_id=%s, err=%d", label, 
         service_id_to_str(&_service_id), _err.v);
}
