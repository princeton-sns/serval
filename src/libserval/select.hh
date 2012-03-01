/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef SELECT_HH
#define SELECT_HH

#include "message.hh"

class HaveData : public Message {
  public:
    HaveData();

    int check_type() const;
    int serial_size() const;
    int write_serial_payload(unsigned char *buf) const;
    int read_serial_payload(const unsigned char *buf);
    uint16_t serial_pld_len() const;
    void print(const char *label) const;
};

class ClearData : public Message {
  public:
    ClearData();

    int check_type() const;
    int serial_size() const;
    int write_serial_payload(unsigned char *buf) const;
    int read_serial_payload(const unsigned char *buf);
    uint16_t serial_pld_len() const;
    void print(const char *label) const;
};

#endif /* SELECT_HH */
