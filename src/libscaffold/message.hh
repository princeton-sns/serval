/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef MESSAGE_HH
#define MESSAGE_HH

#include <netinet/scaffold.h>
#include "types.h"
#include "state.hh"
#include "sockio.hh"
#include "log.hh"

// todo: add pid to message hdr

class Message {
  public:
    typedef enum { UNKNOWN, BIND_REQ, BIND_RSP,
                   CONNECT_REQ, CONNECT_RSP,
                   LISTEN_REQ, LISTEN_RSP,
                   ACCEPT_REQ, ACCEPT_RSP,
                   ACCEPT_REQ2, ACCEPT_RSP2,
                   SEND_REQ, SEND_RSP,
                   RECV_REQ, RECV_RSP,
                   MIG_REQ, MIG_RSP,
                   RECONN_REQ, RECONN_RSP,
                   CLOSE_REQ, CLOSE_RSP,
                   RECVMESG, 
                   CLEAR_DATA, HAVE_DATA
    } Type;
    Message()
            : _version(version), _type(UNKNOWN), _pld_len_v(0) { }
    Message(Type type)
            : _version(version), _type(type), _pld_len_v(0) { }

    unsigned char type() const             { return _type; }
    uint16_t hdr_len() const;
    uint16_t total_len() const;
    uint16_t pld_len() const;
    uint16_t serial_len() const;

    uint16_t pld_len_v() const              { return _pld_len_v; }
    void set_pld_len_v(uint16_t v)          { _pld_len_v = v; }
    void set_nonserial_buf(unsigned char *v);

    virtual uint16_t nonserial_pld_len() const              { return 0; }
    virtual uint16_t serial_pld_len() const                 { return 0; }
    virtual int read_serial_payload(const unsigned char *)  { return 0; }
    virtual int write_serial_payload(unsigned char *) const { return 0; }
    virtual int check_type() const                          { return 0; }

    virtual const unsigned char *nonserial_buf() const      { return 0; }
    virtual unsigned char *nonserial_buf_mutable()          { return 0; }

    int write_serial(unsigned char *buf) const;
    int write_hdr(unsigned char *buf) const;
    int read_hdr(const unsigned char *buf);
    int write_to_stream_soc(int soc);
    int write_to_stream_soc(int soc, sf_err_t &err);
    int read_from_stream_soc(int soc, sf_err_t &err);
    int read_hdr_from_stream_soc(int soc, sf_err_t &err);
    int read_pld_from_stream_soc(int soc, sf_err_t &err);

    void print(const char *label) const;
    const char *type_cstr() const;

    static const unsigned char version = 1;

  protected:

    int check_buf(const unsigned char *buf,
                  const char *file, unsigned line) const;
    int check_hdr() const;
    int check_len() const  { return _pld_len_v >= pld_len(); }

  protected:
    unsigned char _version;
    unsigned char _type;
    uint16_t _pld_len_v;
};

inline int
Message::check_buf(const unsigned char *buf,
                   const char *file, unsigned line) const
{
    if (!buf) {
        lerr("%s:$s null buf during read/write of scafd messages",
             file, line);
        return -1;
    }
    return 0;
}

inline int
Message::check_hdr() const
{
    if (_version != version || check_type() < 0 ||
        check_len() < 0)
        return -1;
    return 0;
}

inline uint16_t
Message::total_len() const
{
    return serial_len() + nonserial_pld_len();
}

inline uint16_t
Message::serial_len() const
{
    return hdr_len() + serial_pld_len();
}

inline uint16_t
Message::pld_len() const
{
    return serial_pld_len() + nonserial_pld_len();
}

inline uint16_t
Message::hdr_len() const
{
    return sizeof(_version) +
            sizeof(_type) +
            sizeof(_pld_len_v);
}

#ifdef ENABLE_DEBUG
inline void
Message::print(const char *label) const
#else
        inline void
        Message::print(const char *) const
#endif
{
    info("%s: version = %d, type = %s, len = %d",
         label, _version, type_cstr(), _pld_len_v);
}

inline const char *
Message::type_cstr() const
{
    switch (_type) {
        case UNKNOWN:     return "unknown";
        case BIND_REQ:    return "bind_req";
        case BIND_RSP:    return "bind_rsp";
        case CONNECT_REQ: return "connect_req";
        case CONNECT_RSP: return "connect_rsp";
        case LISTEN_REQ:  return "listen_req";
        case LISTEN_RSP:  return "listen_rsp";
        case ACCEPT_REQ:  return "accept_req";
        case ACCEPT_RSP:  return "accept_rsp";
        case ACCEPT_REQ2: return "accept_req2";
        case ACCEPT_RSP2: return "accept_rsp2";
        case SEND_REQ:    return "send_req";
        case SEND_RSP:    return "send_rsp";
        case RECV_REQ:    return "recv_req";
        case RECV_RSP:    return "recv_rsp";
        case MIG_REQ:     return "mig_req";
        case MIG_RSP:     return "mig_rsp";
        case CLOSE_REQ:   return "close_req";
        case CLOSE_RSP:   return "close_rsp";
        case CLEAR_DATA:  return "clear_data";
        case HAVE_DATA:   return "have_data";
        default:
            return "unknown";
    }
}

#endif
