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

#include "send.hh"

//
// SendReq
//
SendReq::SendReq()
    :Message(SEND_REQ), _nb(false), _ipaddr(0),
     _nsbuf(0), _nonserial_len(0), _flags(0)
{
    memset(&_dst_service_id, 0xff, sizeof(_dst_service_id));
    set_pld_len_v(serial_pld_len() + nonserial_pld_len());
}

SendReq::SendReq(bool nb, 
                 unsigned char *buf, uint16_t buflen, int flags)
    :Message(SEND_REQ), _nb(nb), _ipaddr(0),
     _nsbuf(buf), _nonserial_len(buflen), _flags(flags)
{
    memset(&_dst_service_id, 0xff, sizeof(_dst_service_id));
    set_pld_len_v(serial_pld_len() + nonserial_pld_len());
}

SendReq::SendReq(sv_srvid_t dst_service_id,
                 unsigned char *buf, uint16_t buflen, int flags)
    :Message(SEND_REQ), _nb(false), _ipaddr(0),
     _nsbuf(buf), _nonserial_len(buflen), _flags(flags)
{
    memcpy(&_dst_service_id, &dst_service_id, sizeof(dst_service_id));
    set_pld_len_v(serial_pld_len() + nonserial_pld_len());
}

SendReq::SendReq(sv_srvid_t dst_service_id, uint32_t ipaddr,
                 unsigned char *buf, uint16_t buflen, int flags)
    :Message(SEND_REQ), _nb(false), _ipaddr(ipaddr),
     _nsbuf(buf), _nonserial_len(buflen), _flags(flags)
{
    memcpy(&_dst_service_id, &dst_service_id, sizeof(dst_service_id));
    set_pld_len_v(serial_pld_len() + nonserial_pld_len());
}

uint16_t SendReq::serial_pld_len() const
{
    return sizeof(_nb) + 
        sizeof(_dst_service_id) + sizeof(_ipaddr) + 
        sizeof(_nonserial_len) + sizeof(_flags);
}

int SendReq::check_type() const
{
    return _type == SEND_REQ;
}

int SendReq::write_serial_payload(unsigned char *buf) const
{
    unsigned char *p = buf;
    p += serial_write(_nb, p);
    p += serial_write(_dst_service_id, p);
    p += serial_write(_ipaddr, p);
    p += serial_write(_nonserial_len, p);
    p += serial_write(_flags, p);
    return p - buf;
}

int SendReq::read_serial_payload(const unsigned char *buf)
{
    const unsigned char *p = buf;
    p += serial_read(&_nb, p);
    p += serial_read(&_dst_service_id, p);
    p += serial_read(&_ipaddr, p);
    p += serial_read(&_nonserial_len, p);
    p += serial_read(&_flags, p);
    return p - buf;
}

void SendReq::print(const char *label) const
{
    Message::print(label);
    info("%s: dst_service_id = %s, ipaddr = %i, buflen=%d, flags=%d\n",
         label, service_id_to_str(&_dst_service_id), _ipaddr, _nonserial_len, _flags);
}

//
// SendRsp
//
SendRsp::SendRsp()
        : Message(SEND_RSP), _err(0)
{
    set_pld_len_v(serial_pld_len());
}


SendRsp::SendRsp(sv_err_t err)
        : Message(SEND_RSP), _err(err)
{
    set_pld_len_v(serial_pld_len());
}

uint16_t SendRsp::serial_pld_len() const
{
    return sizeof(_err);
}

int SendRsp::check_type() const
{
    return SEND_RSP;
}

int SendRsp::write_serial_payload(unsigned char *buf) const
{
    unsigned char *p = buf;
    p += serial_write(_err, p);
    return p - buf;
}

int SendRsp::read_serial_payload(const unsigned char *buf)
{
    const unsigned char *p = buf;
    p += serial_read(&_err, p);
    return p - buf;
}

void SendRsp::print(const char *label) const
{
    Message::print(label);
    info("%s: err=%s", label, _err.v ? "t" : "f");
}

