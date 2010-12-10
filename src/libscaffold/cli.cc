/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
// Copyright (c) 2010 The Trustees of Princeton University (Trustees)

// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and/or hardware specification (the “Work”) to deal
// in the Work without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Work, and to permit persons to whom the Work is
// furnished to do so, subject to the following conditions: The above
// copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Work.

// THE WORK IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE WORK OR THE USE OR OTHER
// DEALINGS IN THE WORK.

#include <scaffold/platform.h>
#include "cli.hh"

uint32_t Cli::_UNIX_ID = 0;

#if defined(OS_ANDROID)
# define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) 0)->sun_path))
#define UNIXCLI_STR "/cache/unixcli_%d_%d.str"
#else
#define UNIXCLI_STR "/tmp/unixcli_%d_%d.str"
#endif

char Cli::strbuf[STRBUFLEN] = { 0 };

Cli::Cli(int fd)
  : _unix_id(_UNIX_ID), _fd(fd), _rcv_lowat(0), _snd_lowat(0),
    _state(State::NEW), _err(0), _connect_in_progress(false), _flags(0)
{
  _err = 0;
  bzero(&_cli, sizeof(_cli));
  _proto.v = SCAFFOLD_PROTO_UDP;
}

Cli::Cli(const Cli &c)
    : _unix_id(c._unix_id), _fd(c._fd), _rcv_lowat(c._rcv_lowat), 
      _snd_lowat(c._snd_lowat), _state(c._state), 
      _err(c._err), _connect_in_progress(c._connect_in_progress),
      _flags(c._flags)
{
  _cli.sun_family = c._cli.sun_family;
  // sun_path is never anonymous; we always bind
  strcpy(_cli.sun_path, c._cli.sun_path);
  _proto.v = SCAFFOLD_PROTO_UDP;
}

Cli::~Cli()
{
  unlink(_cli.sun_path);
}

int
Cli::bind(sf_err_t &err)
{
  _cli.sun_family = AF_LOCAL;
  sprintf(_cli.sun_path, UNIXCLI_STR, getpid(), _unix_id);
  incr_unix_id();
  
  if (_fd < 0) {
    lerr("Cli::bind() fd < 0");
    err = ESFINTERNAL;
    return -1;
  }
  
  if (::bind(_fd, (struct sockaddr *)&_cli, SUN_LEN(&_cli)) < 0) {
    lerr("client bind failed :%s\n", strerror(errno));
    err = errno;
    return -1;
  }
  info("Successfully bound unix socket to fd %d (%s)", _fd, _cli.sun_path);
  return 0;
}

bool
Cli::is_blocking() const
{
  int flags;
  if ((flags = fcntl (_fd, F_GETFL, 0)) < 0) {
    fprintf(stderr, "F_GETFL error on fd %d (%s)", _fd,
	    strerror(errno));
    return -1;
  }
  return !(flags & O_NONBLOCK);
}

bool
Cli::is_non_blocking() const
{
  return !is_blocking();
}

int
Cli::save_flags()
{
  if ((_flags = fcntl (_fd, F_GETFL, 0)) < 0) {
    lerr("F_GETFL error on fd %d (%s)", _fd, strerror(errno));
    return -1;
  }
  return 0;
}

int
Cli::restore_flags()
{
  if (fcntl(_fd, F_SETFL, _flags) < 0) {
    lerr("F_SETFL error on fd %d (%s)", _fd, strerror(errno));
    return -1;
  }
  return 0;
}

int
Cli::set_sync()
{
  int flags;
  if ((flags = fcntl (_fd, F_GETFL, 0)) < 0) {
    lerr("F_GETFL error on fd %d (%s)", _fd, strerror(errno));
    return -1;
  }
  flags &= ~O_NONBLOCK;
  if (fcntl(_fd, F_SETFL, flags) < 0) {
    lerr("F_SETFL error on fd %d (%s)", _fd, strerror(errno));
    return -1;
  }
  return 0;
}

int
Cli::get_bufsize(bool rcv, int &len, sf_err_t &err)
{
  int l;
  socklen_t size = sizeof(l);
  int option = rcv ? SO_RCVBUF : SO_SNDBUF;
  if (getsockopt(_fd, SOL_SOCKET, option, (char *)&l, &size) < 0) {
    lerr("getsockopt %s failed on fd %d: %s", 
	 (rcv ? "SO_RCVBUF" : "SO_SNDBUF"), 
	 _fd, strerror(errno));
    return -1;
  }
  len = l;
  info("getsockopt: %s -> %d", (rcv ? "SO_RCVBUF" : "SO_SNDBUF"), len);
  return 0;
}

int
Cli::set_bufsize(bool rcv, int len, sf_err_t &err)
{
#ifdef USE_SO_SNDLOWAT
  int lowat;
  socklen_t lowat_size = sizeof(lowat);
  if (getsockopt(_fd, SOL_SOCKET, SO_SNDLOWAT, (char *)&lowat,
		 &lowat_size) < 0) {
    lerr("getsockopt SO_SNDLOWAT failed : %s", strerror(errno));
    err = errno;
    return -1;
  }
  info("SO_SNDLOWAT = %d", lowat);
#endif

  socklen_t size = sizeof(len);
  int option = rcv ? SO_RCVBUF : SO_SNDBUF;
  if (setsockopt(_fd, SOL_SOCKET, option, (char *)&len, size) < 0) {
    lerr("setsockopt %s failed on fd %d: %s", 
	 (rcv ? "SO_RCVBUF" : "SO_SNDBUF"), 
	 _fd, strerror(errno));
    return -1;
  }
  info("setsockopt: %s -> %d", (rcv ? "SO_RCVBUF" : "SO_SNDBUF"), len);
  return 0;
}

int
Cli::set_unreadable(sf_err_t &err)
{
  int len;
  socklen_t size = sizeof(len);
  if (get_bufsize(true, len, err) < 0)
    return -1;
  
  int lowat;
  socklen_t lowat_size = sizeof(lowat);
  if (getsockopt(_fd, SOL_SOCKET, SO_RCVLOWAT, (char *)&lowat, 
		 &lowat_size) < 0) {
    lerr("getsockopt SO_RCVLOWAT failed : %s", strerror(errno));
    err = errno;
    return -1;
  }
  set_rcvlowat(lowat);
  
  len = MAX_BUF_SZ ? MAX_BUF_SZ : (MAX_BUF_SZ + 1);
  info("fd %d: RCVLOWAT old = %d, new = %d", lowat, len);
  if (setsockopt(_fd, SOL_SOCKET, SO_RCVLOWAT, (char *)&len, size) < 0) {
    lerr("setsockopt SO_RCVLOWAT failed : %s", strerror(errno));
    err = errno;
    return -1;
  }
  return 0;
}

int
Cli::reset_readability(sf_err_t &err)
{
  if (setsockopt(_fd, SOL_SOCKET, SO_RCVLOWAT, (char *)&_rcv_lowat, 
		 sizeof(_rcv_lowat)) < 0) {
    lerr("setsockopt SO_RCVLOWAT failed : %s", strerror(errno));
    err = errno;
    return -1;
  }
  info("fd %d: RCVLOWAT reset to orig value = %d", _rcv_lowat);
  return 0;
}

int
Cli::set_unwritable(sf_err_t &err)
{
#ifdef USE_SO_SNDLOWAT   // SO_SNDLOWAT set is not implemented in Linux!
  int len;
  if (get_bufsize(false, len, err) < 0)
    return -1;
  
  int lowat;
  socklen_t lowat_size = sizeof(lowat);
  if (getsockopt(_fd, SOL_SOCKET, SO_SNDLOWAT, (char *)&lowat,
		 &lowat_size) < 0) {
    lerr("getsockopt SO_SNDLOWAT failed : %s", strerror(errno));
    err = errno;
    return -1;
  }
  set_sndlowat(lowat);
  len = MAX_BUF_SZ ? MAX_BUF_SZ : (MAX_BUF_SZ + 1);
  info("fd %d: SNDLOWAT old = %d, new = %d", _fd, lowat, len);

  if (setsockopt(_fd, SOL_SOCKET, SO_SNDLOWAT, (char *)&len, size) < 0) {
    lerr("setsockopt SO_SNDLOWAT failed : %s", strerror(errno));
    err = errno;
    return -1;
  }
  return 0;

#else 

  if (get_bufsize(false, _snd_buf, err) < 0 ||
      set_bufsize(false, 0, err) < 0)
    return -1;

  int snd_buf;
  get_bufsize(false, snd_buf, err);
  info("SO_SNDBUF set to %d", snd_buf);
  return 0;

#endif
}

int
Cli::reset_writability(sf_err_t &err)
{
#ifdef USE_SO_SNDLOWAT // Linux does not support SO_SNDLOWAT!
  if (setsockopt(_fd, SOL_SOCKET, SO_SNDLOWAT, 
		 (char *)&_snd_lowat, sizeof(_snd_lowat)) < 0) {
    lerr("setsockopt SO_SNDLOWAT failed : %s", strerror(errno));
    err = errno;
    return -1;
  }
  info("fd %d: SNDLOWAT reset to orig value = %d", _snd_lowat);
  return 0;

#endif

  int snd_buf;
  if (get_bufsize(false, snd_buf, err) < 0 ||
      snd_buf != 0 || _snd_buf <= 0 ||
      set_bufsize(false, _snd_buf, err) < 0)
    return -1;

  info("Reset SO_SNDBUF to %d (%d)", _snd_buf);
  return 0;
}

int
Cli::has_unread_data(int atleast, bool &v, sf_err_t &err) const
{
  char buf[atleast];
  int n;
  if ((n = recv(_fd, buf, atleast, MSG_PEEK | MSG_DONTWAIT)) < 0) {

    if (errno == EWOULDBLOCK) {
      v = false;
      return 0;
    }
    lerr("Cli::has_unread_data cannot PEEK socket : %s", strerror(errno));
    err = errno;
    return -1;
  }
  info("has_unread_data: found %d bytes, need atleast %d bytes",
       n, atleast);
  if (n >= atleast)
    v = true;
  else
    v = false;
  return 0;
}

const char *
Cli::s(char *buf, size_t buflen) const
{
  int len = 0;

  len += snprintf(buf + len, buflen - len, "[cli: unix_id=%d ", _unix_id);
  len += snprintf(buf + len, buflen - len, "fd=%d ", _fd);
  len += snprintf(buf + len, buflen - len, "rcv_lowat=%d ", _rcv_lowat);
  len += snprintf(buf + len, buflen - len, "snd_lowat=%d ", _snd_lowat);
  len += snprintf(buf + len, buflen - len, "state=%s ", State::state_s(_state));
  len += snprintf(buf + len, buflen - len, "err=%s ", strerror_sf(_err.v));
  len += snprintf(buf + len, buflen - len, "connecting=%s]", 
                  _connect_in_progress ? "true" : "false");
  return buf;
}

