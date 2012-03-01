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
#include "select.hh"

//
// HaveData
//

HaveData::HaveData()
        :Message(HAVE_DATA)
{
    set_pld_len_v(serial_pld_len());
}

uint16_t HaveData::serial_pld_len() const
{
    return 0;
}

int HaveData::check_type() const
{
    return _type == HAVE_DATA;
}

int HaveData::write_serial_payload(unsigned char *buf) const
{
    buf = NULL; // avoid compilation warning for unused variable.
    return 0;
}

int HaveData::read_serial_payload(const unsigned char *buf)
{
    buf = NULL; // avoid compilation warning for unused variable.
    return 0;
}

void HaveData::print(const char *label) const
{
    Message::print(label);
    info("%s", label);
}

//
// ClearData
//

ClearData::ClearData()
        :Message(CLEAR_DATA)
{
    set_pld_len_v(serial_pld_len());
}

uint16_t ClearData::serial_pld_len() const
{
    return 0;
}

int ClearData::check_type() const
{
    return _type == HAVE_DATA;
}

int ClearData::write_serial_payload(unsigned char *buf) const
{
    buf = NULL; // avoid compilation warning for unused variable.
    return 0;
}

int ClearData::read_serial_payload(const unsigned char *buf)
{
    buf = NULL; // avoid compilation warning for unused variable.
    return 0;
}

void ClearData::print(const char *label) const
{
    Message::print(label);
    info("%s", label);
}
