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
#ifndef BIND_HH
#define BIND_HH

#include "message.hh"

class BindReq : public Message {
  public:
    BindReq();
    BindReq(const sv_srvid_t& service_id, uint8_t flags, uint8_t prefix);

    int check_type() const;
    int write_serial_payload(unsigned char *buf) const;
    int read_serial_payload(const unsigned char *buf);
    uint16_t serial_pld_len() const;

    void print(const char *label) const;
    const sv_srvid_t& service_id() const { return _service_id; }
    uint8_t flags() {return _flags;}
    uint8_t prefix() {return _prefix;}

  private:
    uint8_t _flags;
	uint8_t _prefix;
	sv_srvid_t _service_id;
};

class BindRsp : public Message {
  public:
    BindRsp();
    BindRsp(const sv_srvid_t& service_id, sv_err_t err);

    int check_type() const;
    int write_serial_payload(unsigned char *buf) const;
    int read_serial_payload(const unsigned char *buf);
    uint16_t serial_pld_len() const;

    void print(const char *label) const;
    sv_err_t err() const { return _err; }

  private:
    sv_srvid_t _service_id;
    sv_err_t _err;
};

#endif
