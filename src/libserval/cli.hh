/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
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
#include <pthread.h>

#include "state.hh"
#include "log.hh"

#include <libserval/serval.h>
#include <serval/list.h>

class Cli {
    struct list_head lh; // Must be first member
    friend class SVSockLib;
public:
    Cli(int fd = -1);
    Cli(const Cli &);
    ~Cli();
    int bind(sv_err_t &err);

    int fd() const { return _fd; }
    bool is_null() const { return _fd < 0; }
    bool is_interrupted() const { return _interrupted; }
    bool is_blocking() const;
    bool is_non_blocking() const;
    bool is_connecting() const       { return _connect_in_progress; }
    enum data_val {
        DATA_ERROR = -1,
        DATA_CLOSED,
        DATA_NOT_ENOUGH,
        DATA_WOULD_BLOCK,
        DATA_READY,
    };
    enum data_val has_unread_data(int atleast, sv_err_t &err) const;
    State::Type state() const              { return _state; } 
    sv_proto_t proto() const         { return _proto; }
  
    pthread_mutex_t& get_lock() { return _lock; }
    void lock() { pthread_mutex_lock(&_lock); }
    void unlock() { pthread_mutex_unlock(&_lock); }

    void set_proto(int proto)        { _proto.v = proto; }
    void set_fd(int fd)              { _fd = fd; }
    void set_rcvlowat(int lowat)     { _rcv_lowat = lowat; }
    void set_sndlowat(int lowat)     { _snd_lowat = lowat; }  
    void set_state(State::Type s)    { _state = s; }
    void set_err(sv_err_t err)       { _err = err; }
    void set_connect_in_progress(bool v)   { _connect_in_progress = v; }
    void set_interrupted(bool val = true) { _interrupted = val; }
    int set_sync();
  
    int save_flags();
    int restore_flags();
  
    int set_unreadable(sv_err_t &err);
    int set_unwritable(sv_err_t &err);
    int reset_readability(sv_err_t &err);
    int reset_writability(sv_err_t &err);

    int get_bufsize(bool rcv, int &len, sv_err_t &err);
    int set_bufsize(bool rcv, int len, sv_err_t &err);
#define STRBUFLEN 100
    static char strbuf[STRBUFLEN];
    const char *s(char *buf = strbuf, size_t buflen = STRBUFLEN) const;
  
    static void incr_unix_id() { _UNIX_ID++; }
    static const unsigned int MAX_BUF_SZ = 65536;
private:
    sv_proto_t _proto;
    int _unix_id;
    int _fd;
    int _rcv_lowat;
    int _snd_lowat;
    int _snd_buf;
    State::Type _state;
    sv_err_t _err;
    bool _connect_in_progress;
    bool _interrupted;
    int _flags;
    struct sockaddr_un _cli;      // local socket
    pthread_mutex_t _lock;
    static uint32_t _UNIX_ID;
};

#endif /* CLI_HH */
