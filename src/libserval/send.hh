/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef SEND_HH
#define SEND_HH

#include "message.hh"

class SendReq : public Message {
  public:
    SendReq();
    SendReq(bool nb, unsigned char *buf, 
            uint16_t len, int flags);    // bound flow
    SendReq(sv_srvid_t dst_service_id, unsigned char *buf, uint16_t len,
            int flags);                                      // unbound flow
    SendReq(sv_srvid_t dst_service_id, uint32_t ipaddr, 
            unsigned char *buf, uint16_t len, int flags);  
    ~SendReq() { }  // user manages nsfbuf alloc/dealloc

    int check_type() const;
    int write_serial_payload(unsigned char *buf) const;
    int read_serial_payload(const unsigned char *buf);
    uint16_t serial_pld_len() const;
    uint16_t nonserial_pld_len() const  { return _nonserial_len; }
    void set_nonserial_len(uint16_t v)  { _nonserial_len = v; }
    bool nonblocking() const            { return _nb; }
    void reset_nonserial(unsigned char *buf, uint16_t v);

    unsigned char *nonserial_buf_mutable()     { return _nsbuf; }
    const unsigned char *nonserial_buf() const { return _nsbuf; }

    sv_srvid_t dst_service_id() const         { return _dst_service_id; }
    uint32_t dst_ipaddr() const { return _ipaddr; }
    void print(const char *label) const;

  private:
    bool _nb; // non-blocking
    sv_srvid_t _dst_service_id;        // don't care for conn. mode
    uint32_t _ipaddr;
    unsigned char *_nsbuf;
    uint16_t _nonserial_len;
    int _flags;
};

inline void
SendReq::reset_nonserial(unsigned char *buf, uint16_t v)
{
    _nsbuf = buf;
    _nonserial_len = v;
    set_pld_len_v(serial_pld_len() + nonserial_pld_len());
}

class SendRsp : public Message {
public:
    SendRsp();
    SendRsp(sv_err_t err);
    int check_type() const;
    int serial_size() const;
    int write_serial_payload(unsigned char *buf) const;
    int read_serial_payload(const unsigned char *buf);
    uint16_t serial_pld_len() const;
    void print(const char *label) const;

    sv_err_t err() const { return _err; }

  private:
    sv_err_t _err;
};


#endif
