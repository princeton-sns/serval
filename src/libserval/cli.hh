/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
#ifndef CLI_HH
#define CLI_HH

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/un.h>
#include <fcntl.h>

#include "state.hh"
#include "log.hh"

#include <libserval/serval.h>
#include <serval/list.h>

class Cli {
  struct list_head lh; // Must be first member
  friend class SFSockLib;
public:
  Cli(int fd = -1);
  Cli(const Cli &);
  ~Cli();
  int bind(sf_err_t &err);

  int fd() const { return _fd; }
  bool is_null() const { return _fd < 0; }
  
  bool is_blocking() const;
  bool is_non_blocking() const;
  bool is_connecting() const       { return _connect_in_progress; }
  int has_unread_data(int atleast, bool &v, sf_err_t &err) const;
  State::Type state() const              { return _state; } 
  sf_proto_t proto() const         { return _proto; }
  
  void set_proto(int proto)        { _proto.v = proto; }
  void set_fd(int fd)              { _fd = fd; }
  void set_rcvlowat(int lowat)     { _rcv_lowat = lowat; }
  void set_sndlowat(int lowat)     { _snd_lowat = lowat; }  
  void set_state(State::Type s)    { _state = s; }
  void set_err(sf_err_t err)       { _err = err; }
  void set_connect_in_progress(bool v)   { _connect_in_progress = v; }

  int set_sync();
  
  int save_flags();
  int restore_flags();
  
  int set_unreadable(sf_err_t &err);
  int set_unwritable(sf_err_t &err);
  int reset_readability(sf_err_t &err);
  int reset_writability(sf_err_t &err);

  int get_bufsize(bool rcv, int &len, sf_err_t &err);
  int set_bufsize(bool rcv, int len, sf_err_t &err);
#define STRBUFLEN 100
  static char strbuf[STRBUFLEN];
  const char *s(char *buf = strbuf, size_t buflen = STRBUFLEN) const;
  
  static void incr_unix_id() { _UNIX_ID++; }
  static const unsigned int MAX_BUF_SZ = 65536;
private:
  sf_proto_t _proto;
  int _unix_id;
  int _fd;
  int _rcv_lowat;
  int _snd_lowat;
  int _snd_buf;
  State::Type _state;
  sf_err_t _err;
  bool _connect_in_progress;
  int _flags;
  struct sockaddr_un _cli;      // local socket
  static uint32_t _UNIX_ID;
};

#endif
