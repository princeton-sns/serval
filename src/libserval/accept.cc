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

uint16_t AcceptReq::serial_pld_len() const
{
    return sizeof(_nb);
}

int AcceptReq::check_type() const
{
    return _type == ACCEPT_REQ;
}

int AcceptReq::write_serial_payload(unsigned char *buf) const
{
    unsigned char *p = buf;
    p += serial_write(_nb, p);
    return p - buf;
}

int AcceptReq::read_serial_payload(const unsigned char *buf)
{
    const unsigned char *p = buf;
    p += serial_read(&_nb, p);
    return p - buf;
}

void AcceptReq::print(const char *label) const
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
    memset(&_local_service_id, 0xff, sizeof(_local_service_id));
    memset(&_remote_service_id, 0xff, sizeof(_remote_service_id));
    memset(&_flow_id, 0xff, sizeof(_flow_id));
    set_pld_len_v(serial_pld_len());
}

AcceptRsp::AcceptRsp(const sv_srvid_t& local_service_id, 
                     const sv_srvid_t& remote_service_id,
                     sv_sock_t flow_id, sv_err_t err)
        : Message(ACCEPT_RSP),
          _flow_id(flow_id),
          _err(err)
{
    memcpy(&_local_service_id, &local_service_id, sizeof(local_service_id));
    memcpy(&_remote_service_id, &remote_service_id, sizeof(remote_service_id));
    set_pld_len_v(serial_pld_len());
}

uint16_t AcceptRsp::serial_pld_len() const
{
    return sizeof(_local_service_id)
            + sizeof(_remote_service_id)
            + sizeof(_flow_id)
            + sizeof(_err);
}

int AcceptRsp::check_type() const
{
    return _type == ACCEPT_RSP;
}

int AcceptRsp::write_serial_payload(unsigned char *buf) const
{
    unsigned char *p = buf;
    p += serial_write(_local_service_id, p);
    p += serial_write(_remote_service_id, p);
    p += serial_write(_flow_id, p);
    p += serial_write(_err, p);
    return p - buf;
}

int AcceptRsp::read_serial_payload(const unsigned char *buf)
{
    const unsigned char *p = buf;
    p += serial_read(&_local_service_id, p);
    p += serial_read(&_remote_service_id, p);
    p += serial_read(&_flow_id, p);
    p += serial_read(&_err, p);
    return p - buf;
}

void AcceptRsp::print(const char *label) const
{
    Message::print(label);
    info("%s: local_service_id=%s, remote_service_id=%s, flow_id = %s, err=%s",
         label, service_id_to_str(&_local_service_id), 
         service_id_to_str(&_remote_service_id),
         flow_id_to_str(&_flow_id), _err.v ? "t" : "f");
}

//
// AcceptReq2
//
AcceptReq2::AcceptReq2()
        : Message(ACCEPT_REQ2), _nb(false)
{

    memset(&_service_id, 0xff, sizeof(_service_id));
    memset(&_flow_id, 0xff, sizeof(_flow_id));
    set_pld_len_v(serial_pld_len());
}


AcceptReq2::AcceptReq2(const sv_srvid_t& service_id, sv_sock_t flow_id, bool nb)
        : Message(ACCEPT_REQ2), _flow_id(flow_id), _nb(nb)
{
    memcpy(&_service_id, &service_id, sizeof(service_id));
    set_pld_len_v(serial_pld_len());
}

uint16_t AcceptReq2::serial_pld_len() const
{
    return sizeof(_service_id) + sizeof(_flow_id) + sizeof(_nb);
}

int AcceptReq2::check_type() const
{
    return _type == ACCEPT_REQ2;
}

int AcceptReq2::write_serial_payload(unsigned char *buf) const
{
    unsigned char *p = buf;
    p += serial_write(_service_id, p);
    p += serial_write(_flow_id, p);
    p += serial_write(_nb, p);
    return p - buf;
}

int AcceptReq2::read_serial_payload(const unsigned char *buf)
{
    const unsigned char *p = buf;
    p += serial_read(&_service_id, p);
    p += serial_read(&_flow_id, p);
    p += serial_read(&_nb, p);
    return p - buf;
}

void AcceptReq2::print(const char *label) const
{
    Message::print(label);
    info("%s: service_id=%s, flow_id = %s, nb = %s", 
         label, service_id_to_str(&_service_id), flow_id_to_str(&_flow_id),
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


AcceptRsp2::AcceptRsp2(sv_err_t err)
        : Message(ACCEPT_RSP), _err(err)
{
    set_pld_len_v(serial_pld_len());
}

uint16_t AcceptRsp2::serial_pld_len() const
{
    return sizeof(_err);
}

int AcceptRsp2::check_type() const
{
    return ACCEPT_RSP2;
}

int AcceptRsp2::write_serial_payload(unsigned char *buf) const
{
    unsigned char *p = buf;
    p += serial_write(_err, p);
    return p - buf;
}

int AcceptRsp2::read_serial_payload(const unsigned char *buf)
{
    const unsigned char *p = buf;
    p += serial_read(&_err, p);
    return p - buf;
}

void AcceptRsp2::print(const char *label) const
{
    Message::print(label);
    info("%s: err=%s", label, _err.v ? "t" : "f");
}
