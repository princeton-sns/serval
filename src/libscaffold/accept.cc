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
#include "accept.hh"

//
// AcceptReq
//

AcceptReq::AcceptReq()
    :Message(ACCEPT_REQ),
     _nb(false)
{
    set_pld_len_v(serial_pld_len());
}

uint16_t
AcceptReq::serial_pld_len() const
{
    return sizeof(_nb);
}

int
AcceptReq::check_type() const
{
    return _type == ACCEPT_REQ;
}

int
AcceptReq::write_serial_payload(unsigned char *buf) const
{
    unsigned char *p = buf;
    p += serial_write(_nb, p);
    return p - buf;
}

int
AcceptReq::read_serial_payload(const unsigned char *buf)
{
    const unsigned char *p = buf;
    p += serial_read(&_nb, p);
    return p - buf;
}

void
AcceptReq::print(const char *label) const
{
    Message::print(label);
    info("%s", label);
}

//
// AcceptRsp
//
AcceptRsp::AcceptRsp()
        : Message(ACCEPT_RSP), _err(0)
{
    _local_obj_id.s_oid = htons(0xffff);
    _remote_obj_id.s_oid = htons(0xffff);
    _sock_id.s_id = 0xffff;
    set_pld_len_v(serial_pld_len());
}


AcceptRsp::AcceptRsp(sf_oid_t local_obj_id, sf_oid_t remote_obj_id,
                     sf_sock_t sock_id, sf_err_t err)
        : Message(ACCEPT_RSP),
          _sock_id(sock_id),
          _err(err)
{
    memcpy(&_local_obj_id, &local_obj_id, sizeof(local_obj_id));
    memcpy(&_remote_obj_id, &remote_obj_id, sizeof(remote_obj_id));
    set_pld_len_v(serial_pld_len());
}

uint16_t
AcceptRsp::serial_pld_len() const
{
    return sizeof(_local_obj_id)
            + sizeof(_remote_obj_id)
            + sizeof(_sock_id)
            + sizeof(_err);
}

int
AcceptRsp::check_type() const
{
    return _type == ACCEPT_RSP;
}

int
AcceptRsp::write_serial_payload(unsigned char *buf) const
{
    unsigned char *p = buf;
    p += serial_write(_local_obj_id, p);
    p += serial_write(_remote_obj_id, p);
    p += serial_write(_sock_id, p);
    p += serial_write(_err, p);
    return p - buf;
}

int
AcceptRsp::read_serial_payload(const unsigned char *buf)
{
    const unsigned char *p = buf;
    p += serial_read(&_local_obj_id, p);
    p += serial_read(&_remote_obj_id, p);
    p += serial_read(&_sock_id, p);
    p += serial_read(&_err, p);
    return p - buf;
}

void
AcceptRsp::print(const char *label) const
{
    Message::print(label);
    info("%s: local_obj_id=%s, remote_obj_id=%s, sock_id = %d, err=%s",
         label, oid_to_str(_local_obj_id), oid_to_str(_remote_obj_id),
         _sock_id.s_id, _err.v ? "t" : "f");
}

//
// AcceptReq2
//
AcceptReq2::AcceptReq2()
        : Message(ACCEPT_REQ2), _nb(false)
{
    _obj_id.s_oid = htons(0xffff);
    _sock_id.s_id = 0xffff;
    set_pld_len_v(serial_pld_len());
}


AcceptReq2::AcceptReq2(sf_oid_t obj_id, sf_sock_t sock_id, bool nb)
        : Message(ACCEPT_REQ2), _sock_id(sock_id), _nb(nb)
{
    memcpy(&_obj_id, &obj_id, sizeof(obj_id));
    set_pld_len_v(serial_pld_len());
}

uint16_t
AcceptReq2::serial_pld_len() const
{
    return sizeof(_obj_id) + sizeof(_sock_id) + sizeof(_nb);
}

int
AcceptReq2::check_type() const
{
    return _type == ACCEPT_REQ2;
}

int
AcceptReq2::write_serial_payload(unsigned char *buf) const
{
    unsigned char *p = buf;
    p += serial_write(_obj_id, p);
    p += serial_write(_sock_id, p);
    p += serial_write(_nb, p);
    return p - buf;
}

int
AcceptReq2::read_serial_payload(const unsigned char *buf)
{
    const unsigned char *p = buf;
    p += serial_read(&_obj_id, p);
    p += serial_read(&_sock_id, p);
    p += serial_read(&_nb, p);
    return p - buf;
}

void
AcceptReq2::print(const char *label) const
{
    Message::print(label);
    info("%s: obj_id=%s, sock_id = %d, nb = %s", 
         label, oid_to_str(_obj_id), _sock_id.s_id,
         _nb ? "t" : "f");
}

//
// AcceptRsp2
//
AcceptRsp2::AcceptRsp2()
        : Message(ACCEPT_RSP), _err(0)
{
    set_pld_len_v(serial_pld_len());
}


AcceptRsp2::AcceptRsp2(sf_err_t err)
        : Message(ACCEPT_RSP), _err(err)
{
    set_pld_len_v(serial_pld_len());
}

uint16_t
AcceptRsp2::serial_pld_len() const
{
    return sizeof(_err);
}

int
AcceptRsp2::check_type() const
{
    return ACCEPT_RSP2;
}

int
AcceptRsp2::write_serial_payload(unsigned char *buf) const
{
    unsigned char *p = buf;
    p += serial_write(_err, p);
    return p - buf;
}

int
AcceptRsp2::read_serial_payload(const unsigned char *buf)
{
    const unsigned char *p = buf;
    p += serial_read(&_err, p);
    return p - buf;
}

void
AcceptRsp2::print(const char *label) const
{
    Message::print(label);
    info("%s: err=%s", label, _err.v ? "t" : "f");
}
