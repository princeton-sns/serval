/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef ACCEPT_HH
#define ACCEPT_HH

#include "message.hh"

class AcceptReq : public Message {
  public:
    AcceptReq();

    int check_type() const;
    int serial_size() const;
    int write_serial_payload(unsigned char *buf) const;
    int read_serial_payload(const unsigned char *buf);
    uint16_t serial_pld_len() const;
    void print(const char *label) const;
};

class AcceptRsp : public Message {
  public:
    AcceptRsp();
    AcceptRsp(sf_oid_t local_obj_id,
              sf_oid_t remote_obj_id,
              sf_sock_t sock_id, sf_err_t err);

    int check_type() const;
    int serial_size() const;
    int write_serial_payload(unsigned char *buf) const;
    int read_serial_payload(const unsigned char *buf);
    uint16_t serial_pld_len() const;
    void print(const char *label) const;

    sf_oid_t local_obj_id() const     {  return _local_obj_id; }
    sf_oid_t remote_obj_id() const    {  return _remote_obj_id; }
    sf_sock_t sock_id() const   {  return _sock_id; }
    sf_err_t err() const        {  return _err; }

  private:
    sf_oid_t  _local_obj_id;
    sf_oid_t  _remote_obj_id;
    sf_sock_t _sock_id;
    sf_err_t  _err;
};

class AcceptReq2 : public Message {
  public:
    AcceptReq2();
    AcceptReq2(sf_oid_t obj_id, sf_sock_t sock_id, bool nb = false);

    int check_type() const;
    int serial_size() const;
    int write_serial_payload(unsigned char *buf) const;
    int read_serial_payload(const unsigned char *buf);
    uint16_t serial_pld_len() const;
    void print(const char *label) const;

    sf_oid_t obj_id() const   { return _obj_id; }
    sf_sock_t sock_id() const { return _sock_id; }
    bool nb() const           { return _nb; }

  private:
    sf_oid_t _obj_id;
    sf_sock_t _sock_id;
    bool _nb;
};

class AcceptRsp2 : public Message {
  public:
    AcceptRsp2();
    AcceptRsp2(sf_err_t err);

    int check_type() const;
    int serial_size() const;
    int write_serial_payload(unsigned char *buf) const;
    int read_serial_payload(const unsigned char *buf);
    uint16_t serial_pld_len() const;
    void print(const char *label) const;

    sf_err_t err() const { return _err; }

  private:
    sf_err_t _err;
};

#endif
