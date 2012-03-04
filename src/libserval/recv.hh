/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef RECV_HH
#define RECV_HH

#include "message.hh"

class RecvRsp : public Message {
  public:
    RecvRsp(int err = SERVAL_OK);
    RecvRsp(unsigned char *buf, uint16_t len, int flags, int err = SERVAL_OK);
    RecvRsp(const sv_srvid_t& src_service_id,
            unsigned char *buf, uint16_t len, int flags);
    ~RecvRsp() { }
    
    sv_err_t err() const { return _err; }
    int check_type() const;
    int write_serial_payload(unsigned char *buf) const;
    int read_serial_payload(const unsigned char *buf);
    uint16_t serial_pld_len() const;
    uint16_t nonserial_pld_len() const { return _nonserial_len; }

    void reset_nonserial(unsigned char *buf, uint16_t v);

    unsigned char *nonserial_buf_mutable()     { return _nsbuf; }
    const unsigned char *nonserial_buf() const { return _nsbuf; }

    void print(const char *label) const;

    unsigned char *nsbuf()             { return _nsbuf; }
    const sv_srvid_t& src_service_id() const        { return _src_service_id; }
    const uint32_t& src_ipaddr() const {return _ipaddr;}

  private:
    sv_srvid_t _src_service_id;
    uint32_t _ipaddr;
    unsigned char *_nsbuf;
    uint16_t _nonserial_len;
    int _flags;
    sv_err_t _err;
};

inline void
RecvRsp::reset_nonserial(unsigned char *buf, uint16_t v)
{
    _nsbuf = buf;
    _nonserial_len = v;
    set_pld_len_v(serial_pld_len() + nonserial_pld_len());
}

class RecvReq : public Message {
  public:
    RecvReq(uint16_t len = 0, int flags = 0);

    uint16_t len() const { return _len; }
    int flags() const { return _flags; }

    int check_type() const;
    int write_serial_payload(unsigned char *buf) const;
    int read_serial_payload(const unsigned char *buf);
    uint16_t serial_pld_len() const;

    void print(const char *label) const;

private:
    uint16_t _len;
    int _flags;
};

#endif
