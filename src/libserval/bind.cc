/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
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

#include "bind.hh"
#include "log.hh"

//
// BindReq
//

BindReq::BindReq()
        :Message(BIND_REQ)
{
    _obj_id.s_srvid = htons(SERVAL_NULL_OID);
    set_pld_len_v(serial_pld_len());
}

BindReq::BindReq(sv_srvid_t obj_id)
        :Message(BIND_REQ)
{
    memcpy(&_obj_id, &obj_id, sizeof(obj_id));
    set_pld_len_v(serial_pld_len());
}

int
BindReq::check_type() const
{
    return _type == BIND_REQ;
}

uint16_t
BindReq::serial_pld_len() const
{
    return sizeof(_obj_id);
}

int
BindReq::write_serial_payload(unsigned char *buf) const
{
    unsigned char *p = buf;
    p += serial_write(_obj_id, p);
    return p - buf;
}

int
BindReq::read_serial_payload(const unsigned char *buf)
{
    const unsigned char *p = buf;
    p += serial_read(&_obj_id, p);
    return p - buf;
}

void
BindReq::print(const char *label) const
{
    Message::print(label);
    info("%s: obj_id=%s", label, oid_to_str(_obj_id));
}

//
// BindRsp
//

BindRsp::BindRsp()
        : Message(BIND_RSP), _err(0)
{
    _obj_id.s_srvid = htons(SERVAL_NULL_OID);
    set_pld_len_v(serial_pld_len());
}

BindRsp::BindRsp(sv_srvid_t obj_id, sv_err_t err)
        : Message(BIND_RSP), _err(err)
{
    memcpy(&_obj_id, &obj_id, sizeof(obj_id));
    set_pld_len_v(serial_pld_len());
}

int
BindRsp::check_type() const
{
    return _type == BIND_RSP;
}

uint16_t
BindRsp::serial_pld_len() const
{
    return sizeof(_obj_id) + sizeof(_err);
}

int
BindRsp::write_serial_payload(unsigned char *buf) const
{
    unsigned char *p = buf;
    p += serial_write(_obj_id, p);
    p += serial_write(_err, p);
    return p - buf;
}

int
BindRsp::read_serial_payload(const unsigned char *buf)
{
    const unsigned char *p = buf;
    p += serial_read(&_obj_id, p);
    p += serial_read(&_err, p);
    return p - buf;
}

void
BindRsp::print(const char *label) const
{
    Message::print(label);
    info("%s: obj_id=%s, err=%s", label, oid_to_str(_obj_id),
         _err.v ? "t" : "f");
}
