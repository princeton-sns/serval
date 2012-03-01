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

#include "recv.hh"

//
// RecvRsp
//
RecvRsp::RecvRsp(int err)
        :Message(RECV_RSP), _ipaddr(0), _nsbuf(0), 
         _nonserial_len(0), _flags(0), _err(err)
{
    memset(&_src_service_id, 0xff, sizeof(_src_service_id));
    set_pld_len_v(serial_pld_len() + nonserial_pld_len());
}

uint16_t RecvRsp::serial_pld_len() const
{
    return sizeof(_src_service_id) + sizeof(_ipaddr)
            + sizeof(_nonserial_len) 
            + sizeof(_flags) 
            + sizeof(_err);
}

int RecvRsp::check_type() const
{
    return _type == RECV_RSP;
}

RecvRsp::RecvRsp(unsigned char *buf, uint16_t buflen, int flags, int err)
        :Message(RECV_RSP), _ipaddr(0), _nsbuf(buf), 
         _nonserial_len(buflen), _flags(flags),
         _err(err)
{
    memset(&_src_service_id, 0xff, sizeof(_src_service_id));
    set_pld_len_v(serial_pld_len() + nonserial_pld_len());
}

RecvRsp::RecvRsp(const sv_srvid_t& src_service_id,
                 unsigned char *buf, uint16_t buflen, int flags)
        :Message(RECV_RSP), _ipaddr(0), _nsbuf(buf), 
         _nonserial_len(buflen), _flags(flags),
         _err(SERVAL_OK)
{
    memcpy(&_src_service_id, &src_service_id, sizeof(src_service_id));
    set_pld_len_v(serial_pld_len() + nonserial_pld_len());
}

int RecvRsp::write_serial_payload(unsigned char *buf) const
{
    unsigned char *p = buf;
    p += serial_write(_src_service_id, p);
    p += serial_write(_ipaddr, p);
    p += serial_write(_nonserial_len, p);
    p += serial_write(_flags, p);
    p += serial_write(_err, p);
    return p - buf;
}

int RecvRsp::read_serial_payload(const unsigned char *buf)
{
    const unsigned char *p = buf;
    p += serial_read(&_src_service_id, p);
    p += serial_read(&_ipaddr, p);
    p += serial_read(&_nonserial_len, p);
    p += serial_read(&_flags, p);
    p += serial_read(&_err, p);
    return p - buf;
}

void RecvRsp::print(const char *label) const
{
    Message::print(label);
    info("%s: src_service_id = %s, src_ipaddr = %u, buflen=%d, flags=%d, err=%d\n",
         label, service_id_to_str(&_src_service_id), _ipaddr, 
         _nonserial_len, _flags, _err.v);
}

//
// RecvReq
//


RecvReq::RecvReq(uint16_t len, int flags)
        :Message(RECV_REQ), _len(len), _flags(flags)
{
    set_pld_len_v(serial_pld_len());
}

int RecvReq::check_type() const
{
    return _type == RECV_REQ;
}

uint16_t RecvReq::serial_pld_len() const
{
    return sizeof(_len) + sizeof(_flags);
}

int RecvReq::write_serial_payload(unsigned char *buf) const
{
    unsigned char *p = buf;
    p += serial_write(_len, p);
    p += serial_write(_flags, p);
    return p - buf;
}

int RecvReq::read_serial_payload(const unsigned char *buf)
{
    const unsigned char *p = buf;
    p += serial_read(&_len, p);
    p += serial_read(&_flags, p);
    return p - buf;
}

void RecvReq::print(const char *label) const
{
    Message::print(label);
    info("%s: len=%d", label, _len);

}
