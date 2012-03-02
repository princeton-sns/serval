/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef MESSAGE_HH
#define MESSAGE_HH

#include <netinet/serval.h>
#include "types.h"
#include "state.hh"
#include "sockio.hh"
#include "log.hh"

class Message {
public:
    typedef enum { 
        UNKNOWN, 
        BIND_REQ, 
        BIND_RSP,
        CONNECT_REQ, 
        CONNECT_RSP,
        LISTEN_REQ, 
        LISTEN_RSP,
        ACCEPT_REQ, 
        ACCEPT_RSP,
        ACCEPT_REQ2, 
        ACCEPT_RSP2,
        SEND_REQ, 
        SEND_RSP,
        RECV_REQ, 
        RECV_RSP,
        CLOSE_REQ, 
        CLOSE_RSP,
        RECVMESG, 
        CLEAR_DATA, 
        HAVE_DATA
    } Type;
    Message()
        : _version(version), _type(UNKNOWN), _pld_len_v(0) { }
    Message(Type type)
        : _version(version), _type(type), _pld_len_v(0) { }
    virtual ~Message() {}

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
    int write_to_stream_soc(int soc, sv_err_t &err);
    int read_from_stream_soc(int soc, sv_err_t &err);
    int read_hdr_from_stream_soc(int soc, sv_err_t &err);
    int read_pld_from_stream_soc(int soc, sv_err_t &err);

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
private:
    static const char *msg_str[];
};

inline int Message::check_buf(const unsigned char *buf,
                              const char *file, unsigned line) const
{
    if (!buf) {
        lerr("%s:$s null buf during read/write of scafd messages",
             file, line);
        return -1;
    }
    return 0;
}

inline int Message::check_hdr() const
{
    if (_version != version) {
        lerr("bad version");
        return -1;
    }
    if (check_type() < 0) {
        lerr("bad type %u", _type);
    }
    if (check_len() < 0) {
        lerr("bad len expceted %d vs %d\n",
             _pld_len_v >= pld_len());
        return -1;
    }
    return 0;
}

inline uint16_t Message::total_len() const
{
    return serial_len() + nonserial_pld_len();
}

inline uint16_t Message::serial_len() const
{
    return hdr_len() + serial_pld_len();
}

inline uint16_t Message::pld_len() const
{
    return serial_pld_len() + nonserial_pld_len();
}

inline uint16_t Message::hdr_len() const
{
    return sizeof(_version) +
        sizeof(_type) +
        sizeof(_pld_len_v);
}

#ifdef ENABLE_DEBUG
inline void Message::print(const char *label) const
#else
    inline void
    Message::print(const char *) const
#endif
{
    info("%s: version = %d, type = %s, len = %d",
         label, _version, type_cstr(), _pld_len_v);
}

inline const char *Message::type_cstr() const
{
    return msg_str[_type];
}

#endif /* MESSAGE_H */
