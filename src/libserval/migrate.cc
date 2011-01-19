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

#include "migrate.hh"
#include "log.hh"

//
// MigrateReq
//

MigrateReq::MigrateReq()
        :Message(MIG_REQ)
{
    set_pld_len_v(serial_pld_len());
}

int
MigrateReq::check_type() const
{
    return _type == MIG_REQ;
}

uint16_t
MigrateReq::serial_pld_len() const
{
    return 0;
}

int
MigrateReq::write_serial_payload(unsigned char *buf) const
{
    buf = NULL; // purge compilation warning
    return 0;
}

int
MigrateReq::read_serial_payload(const unsigned char *buf)
{
    buf = NULL; // purge compilation warning
    return 0;
}

void
MigrateReq::print(const char *label) const
{
    Message::print(label);
    info("%s: migrate req", label);
}

//
// MigrateRsp
//


MigrateRsp::MigrateRsp()
        : Message(MIG_RSP), _err(0)
{
    set_pld_len_v(serial_pld_len());
}


MigrateRsp::MigrateRsp(sv_err_t err)
        : Message(MIG_RSP), _err(err)
{
    set_pld_len_v(serial_pld_len());
}

int
MigrateRsp::check_type() const
{
    return _type == MIG_RSP;
}

uint16_t
MigrateRsp::serial_pld_len() const
{
    return sizeof(_err);
}

int
MigrateRsp::write_serial_payload(unsigned char *buf) const
{
    unsigned char *p = buf;
    p += serial_write(_err, p);
    return p - buf;
}

int
MigrateRsp::read_serial_payload(const unsigned char *buf)
{
    const unsigned char *p = buf;
    p += serial_read(&_err, p);
    return p - buf;
}

void
MigrateRsp::print(const char *label) const
{
    Message::print(label);
    info("%s: err=%d", label, _err.v);
}
