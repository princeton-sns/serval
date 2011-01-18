/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef LISTEN_HH
#define LISTEN_HH

#include "message.hh"

class ListenReq : public Message {
  public:
    ListenReq();
    ListenReq(int backlog);
    ListenReq(sf_oid_t local_obj_id, int backlog);

    int write_serial_payload(unsigned char *buf) const;
    int read_serial_payload(const unsigned char *buf);
    uint16_t serial_pld_len() const;
    void print(const char *label) const;

    bool use_first() const        { return _use_first; }
    sf_oid_t local_obj_id() const { return _local_obj_id;}
    uint16_t backlog() const      { return _backlog; }

    static const unsigned int DEFAULT_BACKLOG = 16;

  private:
    bool     _use_first;
    sf_oid_t _local_obj_id;
    uint16_t _backlog;
};

class ListenRsp : public Message {
  public:
    ListenRsp();
    ListenRsp(sf_err_t err);

    int write_serial_payload(unsigned char *buf) const;
    int read_serial_payload(const unsigned char *buf);
    uint16_t serial_pld_len() const;
    void print(const char *label)  const;

    sf_err_t err() const { return _err; }

  private:
    sf_err_t _err;
};


#endif
