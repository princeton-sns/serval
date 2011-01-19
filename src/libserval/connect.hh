/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef CONNECT_HH
#define CONNECT_HH

#include "message.hh"

class ConnectReq : public Message {
  public:
    ConnectReq();
    ConnectReq(sv_srvid_t obj_id, bool nb, uint16_t flags);

    int check_type() const;
    int serial_size() const;
    int write_serial_payload(unsigned char *buf) const;
    int read_serial_payload(const unsigned char *buf);
    uint16_t serial_pld_len() const;
    void print(const char *label) const;

    sv_srvid_t obj_id() const { return _obj_id; }
    bool nb() const         { return _nb; }
    uint16_t flags() const  { return _flags; }

  private:
    sv_srvid_t _obj_id;
    bool _nb;
    uint16_t _flags;  // from sockaddr_sv passed in by user
};

class ConnectRsp : public Message {
  public:
    ConnectRsp();
    ConnectRsp(sv_srvid_t obj_id, sv_err_t success);

    int check_type() const;
    int serial_size() const;
    int write_serial_payload(unsigned char *buf) const;
    int read_serial_payload(const unsigned char *buf);
    uint16_t serial_pld_len() const;
    void print(const char *label) const;

    sv_err_t err() const    { return _err; }
    sv_srvid_t obj_id() const { return _obj_id; }

  private:
    sv_srvid_t _obj_id;
    sv_err_t _err;
};


#endif
