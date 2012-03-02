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

#include "state.hh"

const char *State::state_str[] = {
    "UNDEFINED",
    "CLOSED",
    "REGISTER",
    "UNBOUND",
    "REQUEST",
    "RESPOND",
    "BOUND",
    "CLOSING",
    "TIMEWAIT",
    "UNREGISTER",
    "RECONNECT",
    "RRESPOND",
    "LISTEN",
    "TCP_FINWAIT1",
    "TCP_FINWAIT2",
    "TCP_CLOSEWAIT",
    "TCP_LASTACK",
    "TCP_SIMCLOSE"
};

const char *PacketType::packettype_str[] = {
    "data",
    "syn",
    "synack",
    "ack",
    "reset",
    "close",
    "rsyn",
    "rsynack"
};

const char *State::state_s(const State::Type &v)
{
    if ((unsigned)v < State::MAX_STATES)
        return state_str[v];
    return "unknown";
}

const char *PacketType::packettype_s(const PacketType::Type &v)
{
    return packettype_str[v];
}

struct service_id _controller_srvid;
struct service_id _serval_srvid;
struct service_id _serval_null_srvid;
