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


#include <libserval/serval.h>
#include "socket.hh"

static SFSockLib sock;

int 
socket_sf(int domain, int type, int protocol)
{
  sf_err_t err;
  
  int s = sock.socket_sf(domain, type, protocol, err);
  if (s == SERVAL_SOCKET_ERROR) {
    errno = err.v;
    return -1;
  }
  return s;
}

int
bind_sf(int soc, const struct sockaddr *address, socklen_t address_len)
{
  sf_err_t err;

  int n = sock.bind_sf(soc, address, address_len, err);
  if (n  == SERVAL_SOCKET_ERROR) {
    errno = err.v;
    return -1;
  }
  return n;
}

int
connect_sf(int soc, const struct sockaddr *address, socklen_t address_len)
{
  sf_err_t err;

  if (address->sa_family != AF_SERVAL) {
    return ::connect(soc, address, address_len);
  }
  int n = sock.connect_sf(soc, address, address_len, err);
  if (n == SERVAL_SOCKET_ERROR) {
    errno = err.v;
    return -1;
  }
  return n;
}

int
listen_sf(int soc, int backlog)
{
  sf_err_t err;
  int n;
  n = sock.listen_sf(soc, backlog, err);
  if (n == SERVAL_SOCKET_ERROR) {
    errno = err.v;
    return -1;
  }
  return n;
}

int
mlisten_sf(int soc, int backlog, 
	   const struct sockaddr *addr, socklen_t address_len)
{
  sf_err_t err;
  int n;
  n = sock.listen_sf(soc, addr, address_len, backlog, err);
  if (n == SERVAL_SOCKET_ERROR) {
    errno = err.v;
    return -1;
  }
  return n;
}


int
accept_sf(int soc, struct sockaddr *address, socklen_t *addr_len)
{
  sf_err_t err;

  int fd = sock.accept_sf(soc, address, addr_len, err);
  if (fd == SERVAL_SOCKET_ERROR) {
    errno = err.v;
    return -1;
  }
  return fd;
}

ssize_t 
send_sf(int soc, const void *buffer, size_t length, int flags)
{
  sf_err_t err;
  int n = sock.send_sf(soc, buffer, length, flags, err);

  if (n == SERVAL_SOCKET_ERROR) {
    errno = err.v;
    return -1;
  } 
    
  return n;
}

ssize_t 
recv_sf(int soc, void *buffer, size_t length, int flags)
{
  sf_err_t err;
  int n = sock.recv_sf(soc, buffer, length, flags, err);
  if (n == SERVAL_SOCKET_ERROR) {
    errno = err.v;
    return -1;
  }
  return n;
}


ssize_t 
sendto_sf(int soc, const void *buffer, size_t length, int flags,
	  const struct sockaddr *dest_addr, socklen_t dest_len)
{
  sf_err_t err;
  int n = sock.sendto_sf(soc, buffer, length, flags, 
			 dest_addr, dest_len, err);
  if (n == SERVAL_SOCKET_ERROR) {
    errno = err.v;
    return -1;
  }
  return n;
}

ssize_t 
recvfrom_sf(int soc, void *buffer, size_t length, int flags,
	    struct sockaddr *address, socklen_t *address_len)
{
  sf_err_t err;
  int n = sock.recvfrom_sf(soc, buffer, length, flags, 
			   address, address_len, err);
  if (n == SERVAL_SOCKET_ERROR) {
    errno = err.v;
    return -1;
  }
  return n;
}

int
getsockopt_sf(int soc, int level, int option_name, 
	      void *option_value, socklen_t *option_len)
{
  sf_err_t err;
  int n = sock.getsockopt_sf(soc, level, option_name, option_value, 
			     option_len, err);
  if (n == SERVAL_SOCKET_ERROR) {
    errno = err.v;
    return -1;
  }
  return n;
}

int
close_sf(int fd)
{
  sf_err_t err;
  int n = sock.close_sf(fd, err);
  if (n == SERVAL_SOCKET_ERROR) {
    errno = err.v;
    return -1;
  }
  return n;
}

// sko begin
int
migrate_sf(int soc)
{
  sf_err_t err;
  int n = sock.migrate_sf(soc, err);
  if (n < 0) {
    errno = err.v;
    return -1;
  }
  return n;
}

char *
strerror_sf(int errnum)
{
  return _strerror_sf(errnum);
}
