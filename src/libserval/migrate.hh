/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef FAILOVER_WAIT_HH
#define FAILOVER_WAIT_HH

#include "message.hh"

class MigrateReq : public Message {
  public:
    MigrateReq();

    int check_type() const;
    int write_serial_payload(unsigned char *buf) const;
    int read_serial_payload(const unsigned char *buf);
    uint16_t serial_pld_len() const;
    void print(const char *label) const;
};

class MigrateRsp : public Message {
  public:
    MigrateRsp();
    MigrateRsp(sv_err_t err);

    int check_type() const;
    int write_serial_payload(unsigned char *buf) const;
    int read_serial_payload(const unsigned char *buf);
    uint16_t serial_pld_len() const;
    void print(const char *label) const;

    sv_err_t err() const    { return _err; }

  private:
    sv_err_t _err;
};

#endif
