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

#include "socket.hh"

const char *SFSockLib::DEFAULT_SF_CFG = "/etc/scaffold.conf";
const char *SFSockLib::SCAFD_TCP_PATH = "/tmp/scaffold-tcp.sock";
const char *SFSockLib::SCAFD_UDP_PATH = "/tmp/scaffold-udp.sock";
Cli SFSockLib::null_cli;
uint32_t SFSockLib::_scafd_id = 0;

//
// SFSockLib
//

SFSockLib::SFSockLib(int scafd_id)
{
  char logname[30];
  snprintf(logname, 29, "libscaffold-%u.log", getpid());
  Logger::initialize(logname);
  Logger::set_debug_level(Logger::DEBUG);

  if (!scafd_id) {
    char *scafd_id_str = getenv("SCAFD_ID");
    if (!scafd_id_str)
      _scafd_id = 0;
    else {
      _scafd_id = strtol(scafd_id_str, NULL, 10);
      if (errno == EINVAL) {
        lerr("illegal value (%s) found in SCAFD_ID; "
             "expected uint32_t; using 0");
        _scafd_id = 0;
      }
    }
  } else
    _scafd_id = scafd_id;
  bzero(&_udp_srv, sizeof(_udp_srv));
  _udp_srv.sun_family = AF_LOCAL;
  sprintf(_udp_srv.sun_path, SCAFD_UDP_PATH, _scafd_id);

  bzero(&_tcp_srv, sizeof(_tcp_srv));
  _tcp_srv.sun_family = AF_LOCAL;
  sprintf(_tcp_srv.sun_path, SCAFD_TCP_PATH, _scafd_id);
}

SFSockLib::~SFSockLib()
{ }

int
SFSockLib::socket_sf(int domain, int type, int proto, sf_err_t &err)
{
  if (domain != AF_SCAFFOLD) {
    err = EAFNOSUPPORT;     /* address family is not supported */
    return SCAFFOLD_SOCKET_ERROR;
  }
  
  if (type != SOCK_DGRAM && type != SOCK_STREAM) {
    err =  EPROTONOSUPPORT; /* proto type not supported within domain */
    return SCAFFOLD_SOCKET_ERROR;
  }
  
  if (!proto) {
    switch (type) {
    case SOCK_DGRAM:
      proto = SF_PROTO_UDP;
      break;
    case SOCK_STREAM:
      proto = SF_PROTO_TCP;
      break;
    default:
      lerr("Unsupported socket type\n");
      return SCAFFOLD_SOCKET_ERROR;
    }
  }
  int fd;
  sf_proto_t p;
  p.v = proto;
  if (create_cli(p, fd, err) < 0) {
    fprintf(stderr, "Could not create client\n");
    return SCAFFOLD_SOCKET_ERROR;
  }
  
  info("socket_sf: created socket for fd %d", fd);
  return fd;
}

Cli &
SFSockLib::get_cli(int soc, sf_err_t &err)
{
  map<int, Cli>::iterator i = _map.find(soc);
  if (i == _map.end()) {
    err = EBADF;
    return null_cli;
  }
  return i->second;
}

int
SFSockLib::basic_checks(int soc, const struct sockaddr *addr, 
                        socklen_t addr_len, bool check_local,
                        sf_err_t &err)
{
  //
  // todo: test if scafd is reachable
  //
  if (addr_len < sizeof(struct sockaddr_sf) || !addr) {
    err =  EINVAL;
    lerr("bad address length");
    return SCAFFOLD_SOCKET_ERROR;
  }

  const struct sockaddr_sf *sf_addr =  (const struct sockaddr_sf *)addr;
  if (!is_valid(*sf_addr, check_local)) {
    err = EADDRNOTAVAIL;
    lerr("invalid Scaffold address");
    return SCAFFOLD_SOCKET_ERROR;
  }
  return 0;
}

//
// Bind
//
 
int
SFSockLib::bind_sf(int soc, const struct sockaddr *addr, socklen_t addr_len,
                   sf_err_t &err)
{
  info("bind_sf: soc = %d", soc);
  Cli &cli = get_cli(soc, err);
  if (cli.is_null() ||
      basic_checks(soc, addr, addr_len, true, err) < 0)
    return ::bind(soc, addr, addr_len);

  if (check_state_for_bind(cli, err) < 0)
    return SCAFFOLD_SOCKET_ERROR;
  
  const struct sockaddr_sf *sf_addr =  (const struct sockaddr_sf *)addr;
  cli.save_flags();
  cli.set_sync();
  if (query_scafd_bind(sf_addr, cli, err) < 0) {
    cli.restore_flags();
    return SCAFFOLD_SOCKET_ERROR;
  }
  cli.restore_flags();
  cli.set_state(State::UNBOUND);
  err = SF_OK;
  info("bind_sf: bind on soc %d successful", soc);
  return 0;
}

int
SFSockLib::check_state_for_bind(const Cli &cli, sf_err_t &err) const
{
  if (cli.state() != State::NEW) {
    lerr("check_state_for_bind: failed state %s", 
         State::state_s(cli.state()));
    err = EADDRINUSE;
    return SCAFFOLD_SOCKET_ERROR;
  }
  return 0;
}

int
SFSockLib::query_scafd_bind(const struct sockaddr_sf *sf_addr,
                            const Cli &cli, sf_err_t &err)
{
  sf_oid_t u;
  u.s_oid = (sf_addr->sf_oid).s_oid;
  BindReq breq(u);
  if (breq.write_to_stream_soc(cli.fd(), err) < 0)
    return SCAFFOLD_SOCKET_ERROR;
  breq.print("bind:app:tx");
    
  BindRsp bresp;
  if (bresp.read_from_stream_soc(cli.fd(), err) < 0)
    return SCAFFOLD_SOCKET_ERROR;
  bresp.print("bind:app:rx");
    
  if (bresp.err().v) {
    err = bresp.err();
    info("Got bind error %d:%s", err.v, strerror(err.v));
    return SCAFFOLD_SOCKET_ERROR;
  }
  return 0;
}

bool 
SFSockLib::is_non_blocking(int fd) const
{
  int flags;
  if ((flags = fcntl (fd, F_GETFL, 0)) < 0) {
    lerr("F_GETFL error on fd %d (%s)", fd, strerror(errno));
    return SCAFFOLD_SOCKET_ERROR;
  }
  return (flags | O_NONBLOCK);
}

int
SFSockLib::check_state_for_connect(const Cli &cli, sf_err_t &err) const
{
  info("Checking whether state %s is valid", State::state_s(cli.state()));

  // Conn is non-blocking, and prev attempt not completed
  if (cli.state() == State::REQUEST) {
    if (is_non_blocking(cli.fd())) {
      err = EALREADY;
      info("error %s", strerror_sf(err.v));
    } else {
      lerr("strange state %s found while %s expected",
           State::state_s(cli.state()), 
           State::state_s(State::UNBOUND));
      err = ESFINTERNAL;
    }
    return SCAFFOLD_SOCKET_ERROR;
  }
  
  if (cli.state() == State::BOUND) {
    err = EISCONN;
    info("error %s", strerror_sf(err.v));
    return SCAFFOLD_SOCKET_ERROR;
  }
  
  if (cli.state() == State::LISTEN) {
    err = EOPNOTSUPP;
    info(" error %s", strerror_sf(err.v));
    return SCAFFOLD_SOCKET_ERROR;
  }
  
  if (cli.state() != State::UNBOUND && cli.state() != State::NEW) {
    // NEW is a valid state in case a client app does not want to
    // register its object id with the object router
    err = ESFINTERNAL;
    info("error %s", strerror_sf(err.v));
    return SCAFFOLD_SOCKET_ERROR;
  }
  info("OK");
  return 0;
}

int
SFSockLib::connect_sf(int soc, const struct sockaddr *addr, socklen_t addr_len,
                      sf_err_t &err)
{
  Cli &cli = get_cli(soc, err);

  lerr("connecting with address family %d", addr->sa_family);

  if (cli.is_null() ||
      basic_checks(soc, addr, addr_len, false, err) < 0) {
    return ::connect(soc, addr, addr_len);
  }

  if (check_state_for_connect(cli, err) < 0) {
    return SCAFFOLD_SOCKET_ERROR;
  }

  info("remote_obj_id %s", 
       oid_to_str(((const struct sockaddr_sf *)addr)->sf_oid));

  bool nb = false;
  if (cli.is_non_blocking()) {
    cli.set_connect_in_progress(true);
    nb = true;
  }
  
  const struct sockaddr_sf *sf_addr =  (const struct sockaddr_sf *)addr;
  cli.save_flags();
  cli.set_sync();
  if (query_scafd_connect(sf_addr, nb, cli, err) < 0) {
    cli.restore_flags();
    return SCAFFOLD_SOCKET_ERROR;
  }
  cli.restore_flags();
  cli.set_state(State::BOUND);
  err = SF_OK;
  return 0;
}

int
SFSockLib::query_scafd_connect(const struct sockaddr_sf *sf_addr, 
                               bool nb, Cli &cli, sf_err_t &err)
{
  sf_oid_t u;
  u.s_oid = sf_addr->sf_oid.s_oid;
  uint16_t flags = sf_addr->sf_flags;
  ConnectReq creq(u, nb, flags);
  if (creq.write_to_stream_soc(cli.fd(), err) < 0) {
    lerr("write to stream sock failed");
    return SCAFFOLD_SOCKET_ERROR;
  }
  creq.print("connect:app:tx");
  
  //
  // todo: handle local connect()
  // if the server to which we are connecting is on the same host, the
  // connection is normally established immediately when we call connect.
  //
  if (nb) {
    err = EINPROGRESS;
    lerr("nb is true, returning %s",
         strerror_sf(err.v));
    //
    // Linux does not support SO_SNDBUF modifications either
    // What a bummer!
    // avoid select()'ing before connect finished
    // if (cli.set_unwritable(err) < 0)
    // return SCAFFOLD_SOCKET_ERROR;
    //
    cli.set_state(State::REQUEST);
    return SCAFFOLD_SOCKET_ERROR;
  }
  
  info("nb = %s, b = %s", 
       (cli.is_non_blocking() ? "t" : "f"),
       (cli.is_blocking() ? "t" : "f"));
  info("reading on fd %d", cli.fd());
  
  // check: return EWOULDBLOCK when approp. 
  ConnectRsp cresp;
  if (cresp.read_from_stream_soc(cli.fd(), err) < 0) {
    lerr("read from stream sock failed");
    return SCAFFOLD_SOCKET_ERROR;
  }
  
  cresp.print("connect:app:rx");            // add TIMEOUT
  
  if (cresp.err().v) {
    err = cresp.err();
    lerr("bad response from scafd");
    return SCAFFOLD_SOCKET_ERROR;
  }
  return 0;
}

//
// todo: support other async errors; currently handles only connect()
// 
int
SFSockLib::getsockopt_sf(int soc, int level, int option_name, 
                         void *option_value, socklen_t *option_len,
                         sf_err_t &err)
{
  int *option = (int *)option_value;

  Cli &cli = get_cli(soc, err);
  if (cli.is_null()) 
    return ::getsockopt(soc, level, option_name, option_value, option_len);
  
  switch (option_name) {
  case SO_ERROR: { // Conn is non-blocking, and prev attempt not completed
    if (!cli.is_connecting()) { // no async errors to report
      info("cli %s is not connecting", cli.s().c_str());
      *option = 0;
      return 0;
    }

    ConnectRsp cresp;
    int atleast = cresp.total_len();
    bool v = false;
    if (cli.has_unread_data(atleast, v, err) < 0) {
      if (err.v == EWOULDBLOCK || err.v == EAGAIN) {
        lerr("cli %s returned EWOULDBLOCK", cli.s().c_str());
        *option = EWOULDBLOCK;
        //*option = EINPROGRESS;
        return 0;
      } else {
        lerr("cli %s has no unread data", cli.s().c_str());
        return SCAFFOLD_SOCKET_ERROR;
      }
    }

    if (!v) {
      info("no async errors to read; still connecting");
      *option = EINPROGRESS;
      return 0;
    }
    
    cli.save_flags();
    cli.set_sync();
    if (query_scafd_soerror(cli, err) < 0) {
      cli.restore_flags();
      return SCAFFOLD_SOCKET_ERROR;
    }
    cli.restore_flags();
    break;
  }
  default:
    lerr("SFSockLib::getsockopt_sf: option %d not supported", level);
    err = EINVAL;
    return SCAFFOLD_SOCKET_ERROR;
  }

  *option = 0;

  return 0;
}

int
SFSockLib::query_scafd_soerror(Cli &cli, sf_err_t &err)
{
  ConnectRsp cresp;
  if (cresp.read_from_stream_soc(cli.fd(), err) < 0) // nothing to read
    return SCAFFOLD_SOCKET_ERROR;
  cresp.print("connect:app:rx");
  
  if (cresp.err().v) {
    err = cresp.err();
    info("getsockopt_sf: ERR cli [%s] : %s", cli.s().c_str(),
         strerror_sf(err.v));
    return SCAFFOLD_SOCKET_ERROR;
  }
  //if (cli.reset_writability(err) < 0)
  //    return SCAFFOLD_SOCKET_ERROR;
  cli.set_state(State::BOUND);
  cli.set_connect_in_progress(false);
  info("getsockopt_sf: OK cli [%s]", cli.s().c_str());
  return 0;
}

//
// Listen on file objects
//
int
SFSockLib::listen_sf(int soc, int backlog, sf_err_t &err)
{ 
  Cli &cli = get_cli(soc, err);
  if (cli.is_null())
    return ::listen(soc, backlog);

  if (check_state_for_listen(cli, err) < 0)
    return SCAFFOLD_SOCKET_ERROR;
  
  cli.save_flags();
  cli.set_sync();
  if (query_scafd_listen(backlog, cli, err) < 0) {
    cli.restore_flags();
    return SCAFFOLD_SOCKET_ERROR;
  }
  cli.restore_flags();
  cli.set_state(State::LISTEN);
  return 0;
}


int
SFSockLib::listen_sf(int soc, const struct sockaddr *addr,
                     socklen_t addr_len,
                     int backlog, sf_err_t &err)
{
  Cli &cli = get_cli(soc, err);
  if (cli.is_null() ||
      basic_checks(soc, addr, addr_len, true, err) < 0)
    return SCAFFOLD_SOCKET_ERROR;

  const struct sockaddr_sf *sf_addr =  (const struct sockaddr_sf *)addr;
  sf_oid_t local_obj_id;
  local_obj_id.s_oid = sf_addr->sf_oid.s_oid;
  info("multi-listen: on obj id %s", oid_to_str(local_obj_id));
  cli.save_flags();
  cli.set_sync();
  if (query_scafd_listen(backlog, local_obj_id, cli, err) < 0) {
    cli.restore_flags();
    return SCAFFOLD_SOCKET_ERROR;
  }
  cli.restore_flags();
  cli.set_state(State::LISTEN);
  return 0;
}

int
SFSockLib::query_scafd_listen(int backlog, sf_oid_t local_obj_id, 
                              const Cli &cli, sf_err_t &err)
{
  ListenReq lreq(local_obj_id, backlog);
  if (lreq.write_to_stream_soc(cli.fd(), err) < 0)
    return SCAFFOLD_SOCKET_ERROR;
  lreq.print("listen:app:tx");

  ListenRsp lrsp;
  if (lrsp.read_from_stream_soc(cli.fd(), err) < 0)
    return SCAFFOLD_SOCKET_ERROR;
  lrsp.print("listen:app:rx");
  
  if (lrsp.err().v) {
    err = lrsp.err();
    return SCAFFOLD_SOCKET_ERROR;
  }
  return 0;
}

int
SFSockLib::check_state_for_listen(const Cli &cli, sf_err_t &err) const
{
  if (cli.state() != State::UNBOUND && cli.state() != State::LISTEN) {
    lerr("check_state_for_listen: failed state is %s", 
         State::state_s(cli.state()));
    err = EINVAL; // todo: support listen without bind(); OS assigns objid
    return SCAFFOLD_SOCKET_ERROR;
  }
  return 0;
}

int
SFSockLib::query_scafd_listen(int backlog, const Cli &cli, sf_err_t &err)
{
  ListenReq lreq(backlog);
  if (lreq.write_to_stream_soc(cli.fd(), err) < 0)
    return SCAFFOLD_SOCKET_ERROR;
  lreq.print("listen:app:tx");

  ListenRsp lrsp;
  if (lrsp.read_from_stream_soc(cli.fd(), err) < 0)
    return SCAFFOLD_SOCKET_ERROR;
  lrsp.print("listen:app:rx");
  
  if (lrsp.err().v) {
    err = lrsp.err();
    return SCAFFOLD_SOCKET_ERROR;
  }
  return 0;
}

//
// Accept
//

int
SFSockLib::accept_sf(int soc, struct sockaddr *addr, socklen_t *addr_len,
                     sf_err_t &err)
{

  Cli &cli = get_cli(soc, err);
  if (cli.is_null()) {
    return ::accept(soc, addr, addr_len);
  }

  if (*addr_len < sizeof(struct sockaddr_sf) || !addr) {
    err =  EINVAL;
    return SCAFFOLD_SOCKET_ERROR;
  } else if (*addr_len % sizeof(struct sockaddr_sf) != 0) {
    err = EINVAL;
    return SCAFFOLD_SOCKET_ERROR;
  }

  if (check_state_for_accept(cli, err) < 0)
    return SCAFFOLD_SOCKET_ERROR;

  bool nb = false;
  if (cli.is_non_blocking()) {
    info("accept_sf: non-blocking");
    nb = true;
  } else
    info("accept_sf: blocking");

  cli.save_flags();
  cli.set_sync();
  AcceptRsp aresp;
  if (query_scafd_accept1(nb, cli, aresp, err) < 0) {
    cli.restore_flags();
    return SCAFFOLD_SOCKET_ERROR;
  }
  cli.restore_flags();
  
  int new_soc;
  if (create_cli(cli.proto(), new_soc, err) < 0)
    return SCAFFOLD_SOCKET_ERROR;

  Cli &new_cli = get_cli(new_soc, err);
  if (new_cli.is_null())
    return SCAFFOLD_SOCKET_ERROR;
  
  // blocking by default
  if (query_scafd_accept2(nb, new_cli, aresp, err) < 0) {
    cli.restore_flags();
    delete_cli(new_cli, err);
    return SCAFFOLD_SOCKET_ERROR;
  }
  new_cli.set_state(State::BOUND);
  
  // On Linux, the new socket returned by accept() does not inherit file status
  // flags such as O_NONBLOCK and O_ASYNC from the listening socket. This
  // behaviour differs from the canonical BSD sockets implementation. Portable
  // programs should not rely on inheritance or non-inheritance of file status
  // flags and always explicitly set all required flags on the socket returned
  // from accept().
  struct sockaddr_sf *sf_addr =  (struct sockaddr_sf *)&addr[0];
  sf_addr->sf_family = AF_SCAFFOLD;
  sf_addr->sf_oid.s_oid = aresp.remote_obj_id().s_oid;

  if (*addr_len >= (2 * sizeof(struct sockaddr_sf))) {
    // also give back the remote object id
    struct sockaddr_sf *sf_addr2 =  (struct sockaddr_sf *)&addr[1];
    sf_addr2->sf_family = AF_SCAFFOLD;   
    sf_addr2->sf_oid.s_oid = aresp.remote_obj_id().s_oid;
    *addr_len = 2 * sizeof(struct sockaddr_sf);
  } else {
    *addr_len = sizeof(struct sockaddr_sf);
  }
    
  return new_cli.fd();
}

int
SFSockLib::query_scafd_accept2(bool nb, 
                               const Cli &cli, const AcceptRsp &aresp,
                               sf_err_t &err)
{
  AcceptReq2 areq2(aresp.remote_obj_id(), aresp.sock_id(), nb);
  if (areq2.write_to_stream_soc(cli.fd(), err) < 0)
    return SCAFFOLD_SOCKET_ERROR;
  areq2.print("accept2:app:tx");
  
  AcceptRsp2 aresp2;
  if (aresp2.read_from_stream_soc(cli.fd(), err) < 0)
    return SCAFFOLD_SOCKET_ERROR;
  aresp2.print("accept2:app:rx");
  if (aresp2.err().v) {
    err = aresp2.err();
    return SCAFFOLD_SOCKET_ERROR;
  }
  info("accepted new soc = %s", cli.s().c_str());
  return 0;
}

int
SFSockLib::create_cli(sf_proto_t proto, int &new_soc, sf_err_t &err)
{
  new_soc = socket(AF_LOCAL, SOCK_STREAM, 0);
  if (new_soc < 0) {
    lerr("create_cli cannot create new socket (%s)", 
         strerror(errno));
    err = errno;
    return SCAFFOLD_SOCKET_ERROR;
  }
  Cli new_cli;
  new_cli.set_fd(new_soc);
  new_cli.set_proto(proto.v);
  if (new_cli.bind(err) < 0)
    return SCAFFOLD_SOCKET_ERROR;
  
  // create a new soc for this accepted connection
  struct sockaddr_un *srv = NULL;
  switch (proto.v) {
  case SF_PROTO_UDP:
    srv = &_udp_srv;
    break;
  case SF_PROTO_TCP:
    srv = &_tcp_srv;
    break;
  default:
    lerr("illegal proto %d", proto.v);
    return SCAFFOLD_SOCKET_ERROR;
  }
  if (connect(new_soc, (struct sockaddr *)srv, sizeof(*srv)) < 0) {
    lerr("create_cli: connect error [unix path %s]: %s", 
         srv->sun_path, strerror(errno));
    return SCAFFOLD_SOCKET_ERROR;
  }
  
  if (new_cli.set_bufsize(true, RCV_BUFSIZE_LEN, err) < 0 ||
      new_cli.set_bufsize(false, SEND_BUFSIZE_LEN, err) < 0)
    return SCAFFOLD_SOCKET_ERROR;

  _map[new_cli.fd()] = new_cli;
  info("create_cli: %s", new_cli.s().c_str());
  return 0;
}

int
SFSockLib::delete_cli(Cli &cli, sf_err_t &err)
{
  if (cli.fd() >= 0)
    if (close(cli.fd()) < 0) {
      lerr("error closing fd %d", cli.fd());
      err = ESFINTERNAL;
      return SCAFFOLD_SOCKET_ERROR;
    }
  
  map<int, Cli>::iterator i = _map.find(cli.fd());
  if (i == _map.end()) {
    err = ESFINTERNAL;
    return SCAFFOLD_SOCKET_ERROR;
  }
  _map.erase(i);
  return 0;
}

int
SFSockLib::query_scafd_accept1(bool nb, const Cli &cli, AcceptRsp &aresp,
                               sf_err_t &err)
{
  if (nb) {
    int size = aresp.total_len();
    bool v;
    if (cli.has_unread_data(size, v, err) < 0)
      return SCAFFOLD_SOCKET_ERROR;
    if (!v) {
      lerr("accept1: no data to read");
      err = EAGAIN; // or EWOULDBLOCK
      return SCAFFOLD_SOCKET_ERROR;
    }
  }
  
  if (aresp.read_from_stream_soc(cli.fd(), err) < 0)
    return SCAFFOLD_SOCKET_ERROR;
  aresp.print("accept:app:rx");            // add TIMEOUT

  if (aresp.err().v) {
    err = aresp.err();
    return SCAFFOLD_SOCKET_ERROR;
  }
  return 0;
}

int
SFSockLib::check_state_for_accept(const Cli &cli, sf_err_t &err) const
{
  if (cli.state() != State::LISTEN) {
    lerr("check_state_for_accept: failed state is %s, expected %s", 
         State::state_s(cli.state()), 
         State::state_s(State::LISTEN));
    return SCAFFOLD_SOCKET_ERROR;
  }
  return 0;
}

ssize_t 
SFSockLib::send_sf(int soc, const void *buffer, size_t length, int flags,
                   sf_err_t &err)
{ 
  Cli &cli = get_cli(soc, err);

  if (cli.is_null())   // todo: what if local end is shut down ?
    return ::send(soc, buffer, length, flags);
  
  if (check_state_for_send(cli, err) < 0) {
    return SCAFFOLD_SOCKET_ERROR;
  }
  
  // buffer checks
  if (!buffer) {
    err = EINVAL;
    return SCAFFOLD_SOCKET_ERROR;
  }
  
  if (length == 0) {
    info("send_sf: 0 length send_sf");
    return 0;
  }

  int bufsize;
  if (cli.get_bufsize(false, bufsize, err) < 0)  // false => snd buf
    return SCAFFOLD_SOCKET_ERROR;
    
  if ((int)length > bufsize) {
    lerr("send: buf len (%d) > bufsize (%d)",  length, bufsize);
    err = EMSGSIZE;
    return SCAFFOLD_SOCKET_ERROR;
  }

  bool nb = false;
  if (cli.is_non_blocking())
    nb = true;
  
  cli.save_flags();
  cli.set_sync();
  if (query_scafd_send(nb, buffer, length, flags, cli, err) < 0) {
    cli.restore_flags();
    return SCAFFOLD_SOCKET_ERROR;
  }
  cli.restore_flags();
  return length;
}

ssize_t
SFSockLib::sendto_sf(int soc, const void *buffer, size_t length, int flags,
                     const struct sockaddr *dst_addr, socklen_t addr_len, 
                     sf_err_t &err)
{
  Cli &cli = get_cli(soc, err);
  if (cli.is_null() ||
      basic_checks(soc, dst_addr, addr_len, false, err) < 0)
    return ::sendto(soc, buffer, length, flags, dst_addr, addr_len);
  
  sf_oid_t remote_obj_id;
  remote_obj_id.s_oid = ((const struct sockaddr_sf *)dst_addr)->sf_oid.s_oid;
  
  info("sendto_sf: remote_obj_id %s", oid_to_str(remote_obj_id));
  if (check_state_for_sendto(cli, err) < 0)
    return SCAFFOLD_SOCKET_ERROR;

  if (length == 0) {
    info("send_sf: 0 length send_sf");
    return 0;
  }

  int bufsize;
  if (cli.get_bufsize(false, bufsize, err) < 0)  // false => snd buf
    return SCAFFOLD_SOCKET_ERROR;
    
  if ((int)length > bufsize) {
    lerr("send: buf len (%d) > bufsize (%d)",  length, bufsize);
    err = EMSGSIZE;
    return SCAFFOLD_SOCKET_ERROR;
  }
  
  cli.save_flags();
  cli.set_sync();
  if (query_scafd_sendto(remote_obj_id, buffer, length, flags, cli, err) < 0) {
    cli.restore_flags();
    return SCAFFOLD_SOCKET_ERROR;
  }
  cli.restore_flags();
  return length;
}

int
SFSockLib::check_state_for_send(const Cli &cli, sf_err_t &err) const
{
  if (cli.state() == State::REQUEST) {
    // What would be the correct thing to return here while connecting?
    err = EWOULDBLOCK;
    return SCAFFOLD_SOCKET_ERROR;
  }
  if (cli.state() != State::BOUND) {

    err = ENOTCONN;
    lerr("check_state_for_send: failed, state is %s", 
         State::state_s(cli.state()));
    return SCAFFOLD_SOCKET_ERROR;
  }
  return 0;
}

int
SFSockLib::check_state_for_sendto(const Cli &cli, sf_err_t &err) const
{
  if (cli.state() != State::BOUND &&   // allow sendto on connected sockets
      cli.state() != State::UNBOUND) {
    err = ESOCKNOTBOUND;
    lerr("check_state_for_sendto: failed, state is %s", 
         State::state_s(cli.state()));
    return SCAFFOLD_SOCKET_ERROR;
  }
  return 0;
}

int
SFSockLib::query_scafd_send(bool nb, const void *buffer, size_t length, int flags,
                            Cli &cli, sf_err_t &err)
{
  SendReq sreq(nb, (unsigned char *)buffer, length, flags);
  if (sreq.write_to_stream_soc(cli.fd(), err) < 0)
    return SCAFFOLD_SOCKET_ERROR;
  sreq.print("send:app:tx");
    
  bool got_havedata_msg = false;
  if (cli.proto().v == SF_PROTO_TCP) {

    Message m;
    if (m.read_hdr_from_stream_soc(cli.fd(), err) < 0)
      return SCAFFOLD_SOCKET_ERROR;
  
    if (m.type() == Message::HAVE_DATA) {
      info("Got HaveData before SendRsp; discarding");
      HaveData hdata;
      hdata.read_pld_from_stream_soc(cli.fd(), err);
      hdata.print("hdata:app:rx");
      got_havedata_msg = true;
      // read SendRsp
      m = Message();
      m.read_hdr_from_stream_soc(cli.fd(), err);
      if (m.type() != Message::SEND_RSP) {
        lerr("expected SendRsp message got %d type", 
             m.type());
        err = ESFINTERNAL;
        return SCAFFOLD_SOCKET_ERROR;
      }
    } else if (errno == EAGAIN)
      info("no data to read; ok to send req");

    if (m.type() == Message::SEND_RSP) {
      // Only message payload to read
      SendRsp srsp;
      if (srsp.read_pld_from_stream_soc(cli.fd(), err) < 0)
        return SCAFFOLD_SOCKET_ERROR;
      
      srsp.print("send:app:rx");
      if (srsp.err().v) {
        err = srsp.err();
        return SCAFFOLD_SOCKET_ERROR;
      }
      info("sent %d bytes through soc %s", length, cli.s().c_str());
    } else
      lerr("got invalid message, expected SEND_RSP got %s", 
           m.type_cstr());
    
    if (got_havedata_msg) {
      ClearData cdata;
      if (cdata.write_to_stream_soc(cli.fd(), err) < 0)
        return SCAFFOLD_SOCKET_ERROR;
    }
  }
  return 0;
}

int
SFSockLib::query_scafd_sendto(sf_oid_t dst_obj_id,
                              const void *buffer, size_t length, int flags,
                              Cli &cli, sf_err_t &err)
{
  SendReq sreq(dst_obj_id, (unsigned char *)buffer, length, flags);
  if (sreq.write_to_stream_soc(cli.fd(), err) < 0)
    return SCAFFOLD_SOCKET_ERROR;
  return 0;
}

ssize_t 
SFSockLib::recv_sf(int soc, void *buffer, size_t length, int flags,
                   sf_err_t &err)
{
  Cli &cli = get_cli(soc, err);
  if (cli.is_null())   // todo: what if local end is shut down ?
    return ::recv(soc, buffer, length, flags);

  if (!buffer) {
    err = EINVAL;
    return SCAFFOLD_SOCKET_ERROR;
  }
  
  bool nb = false;
  if (cli.is_non_blocking())
    nb = true;
  
  info("receiving data");

  sf_oid_t src_obj_id; // ignore this since it's connected 
  
  cli.save_flags();
  cli.set_sync();
  if (query_scafd_recv(nb, (unsigned char *)buffer, length, flags, src_obj_id, 
                       cli, err) < 0) {
    cli.restore_flags();
    lerr("query_scafd_recv returned error '%s'", strerror_sf(err.v));
    return SCAFFOLD_SOCKET_ERROR;
  }
  cli.restore_flags();
  
  info("received %ld bytes data", length);

  return length;
}

ssize_t 
SFSockLib::recvfrom_sf(int soc, void *buffer, size_t length, int flags,
                       struct sockaddr *src_addr, socklen_t *addr_len,
                       sf_err_t &err)
{
  Cli &cli = get_cli(soc, err);
  if (cli.is_null())   // todo: what if local end is shut down ?
    return ::recvfrom(soc, buffer, length, flags, src_addr, addr_len);

  if (!buffer) {
    err = EINVAL;
    return SCAFFOLD_SOCKET_ERROR;
  }
  
  int bufsize;
  if (cli.get_bufsize(true, bufsize, err) < 0)  // false => rcv buf
    return SCAFFOLD_SOCKET_ERROR;

  if (bufsize == 0) {
    lerr("recv buffer size is 0");
    return SCAFFOLD_SOCKET_ERROR;
  }
  
  bool nb = false;
  if (cli.is_non_blocking())
    nb = true;
  
  sf_oid_t src_obj_id;
  
  cli.save_flags();
  cli.set_sync();
  if (query_scafd_recv(nb, (unsigned char *)buffer, length, flags, src_obj_id, 
                       cli, err) < 0) {
    cli.restore_flags();
    return SCAFFOLD_SOCKET_ERROR;
  }
  cli.restore_flags();

  struct sockaddr_sf *sf_addr = (struct sockaddr_sf *)&src_addr[0];
  sf_addr->sf_family = AF_SCAFFOLD;
  sf_addr->sf_oid.s_oid = src_obj_id.s_oid;

  if (*addr_len >= 2 * sizeof(struct sockaddr_sf)) {
    struct sockaddr_sf *sf_addr2 = (struct sockaddr_sf *)&src_addr[1];
    sf_addr2->sf_family = AF_SCAFFOLD;
    sf_addr2->sf_oid.s_oid = htons(SCAFFOLD_NULL_OID);
    *addr_len = 2 * sizeof(struct sockaddr_sf);
  } else { 
    *addr_len = sizeof(struct sockaddr_sf);
  }
  return length;
}


int
SFSockLib::query_scafd_recv(bool nb, unsigned char *buffer, size_t &len, 
                            int flags, sf_oid_t &src_obj_id, 
                            Cli &cli, sf_err_t &err)
{
  info("query_scafd_recv");
  bool got_havedata_msg = false;
  if (cli.proto().v == SF_PROTO_TCP) {
    if (nb) {  // NON-BLOCKING
      // first check for null HaveData message
      // this is used to activate select
      info("tcp non-blocking");
      HaveData hdata;
      int size = hdata.total_len();
      bool v;
      if (cli.has_unread_data(size, v, err) < 0) {
        lerr("has_unread_data returned error");
        return SCAFFOLD_SOCKET_ERROR;
      }
      if (!v) {
        err = EWOULDBLOCK;           // or EAGAIN
        lerr("TCP non-blocking would block");
        return SCAFFOLD_SOCKET_ERROR;
      }
      info("reading hdata in nb mode");
      hdata.read_from_stream_soc(cli.fd(), err);
      hdata.print("hdata:app:rx");
      // we have a message, request for data
    } else {          // BLOCKING
      // check if HaveData exists and discard it
      // This allows select() to wake up without
      // reading anything from the socket buffers
      info("recv_sf on blocking socket");
      bool v;
      if (cli.has_unread_data(1, v, err) >= 0) {
        if (v) {
          // This must be HaveData
          info("reading hdata in blocking mode");
          HaveData hdata;
          //int size = hdata.total_len();
          if (hdata.read_from_stream_soc(cli.fd(), err) < 0) {
            lerr("found unexpected msg (want HaveData)");
            err = ESFINTERNAL;
            return SCAFFOLD_SOCKET_ERROR;
          } else {
            info("Got HaveData Msg");
            hdata.print("hdata:app:rx");
            got_havedata_msg = true;
          }
        }
      } else if (errno == EAGAIN)
        info("no data to read; ok to send req");
    }
    // Now ready to send read request
    info("sending recv req of len %d", len);
    RecvReq rreq(len, flags);
    if (rreq.write_to_stream_soc(cli.fd(), err) < 0) {
      lerr("Error writing RecvReq to stream");
      return SCAFFOLD_SOCKET_ERROR;
    }
    rreq.print("recv:app:tx");
  } else {    // UDP NON-BLOCKING
    if (nb) {
      RecvRsp rresp(NULL, 1, 0); // at least 1 byte data
      int size = rresp.total_len();
      bool v;
      if (cli.has_unread_data(size, v, err) < 0)
        return SCAFFOLD_SOCKET_ERROR;
      if (!v) {
        err = EWOULDBLOCK;           // or EAGAIN
        lerr("Would block");
        return SCAFFOLD_SOCKET_ERROR;
      }
    }
  }

  // In 3 diff cases, we still reach here
  // TCP non-blocking, we found a HaveData message,
  //  and we sent a RecvReq, and waiting for a resp
  // TCP blocking, we sent a RecvReq, and waiting for a resp
  // UDP blocking, we simply wait for a RecvRsp, no RecvReq necessary
  Message m;
  if (m.read_hdr_from_stream_soc(cli.fd(), err) < 0) {
    lerr("Cannot read response message from stream");
    return SCAFFOLD_SOCKET_ERROR;
  }

  if (cli.proto().v == SF_PROTO_TCP && m.type() == Message::HAVE_DATA) {
    info("Got HaveData before RecvRsp; discarding");
    HaveData hdata;
    hdata.read_pld_from_stream_soc(cli.fd(), err);
    hdata.print("hdata:app:rx");
    got_havedata_msg = true;
    // read RecvRsp
    m = Message();
    m.read_hdr_from_stream_soc(cli.fd(), err);
    if (m.type() != Message::RECV_RSP) {
      lerr("expected RecvRsp message got %d type", 
           m.type());
      err = ESFINTERNAL;
      return SCAFFOLD_SOCKET_ERROR;
    }
  }

  // We read RecvRsp header; now send a ClearData message if TCP NON-BLOCKING
  // OR, if we received a HaveData in blocking mode to wake up 
  // a select(), to clear the notification
  if (cli.proto().v == SF_PROTO_TCP && (nb || got_havedata_msg)) {
    ClearData cdata;
    if (cdata.write_to_stream_soc(cli.fd(), err) < 0) {
      lerr("Error writing ClearData to stream");
      return SCAFFOLD_SOCKET_ERROR;
    }
    cdata.print("cdata:app:tx");
  }

  m.print("recv:app:rx:hdr");
  if (m.pld_len_v()) {
    RecvRsp rresp(SF_OK);
    uint16_t nonserial_len = m.pld_len_v() - rresp.serial_pld_len();
    if (nonserial_len > len) {
      err = ENOMEM;          // todo: support incoming msg truncation
      lerr("No memory error for RecvRsp");
      return SCAFFOLD_SOCKET_ERROR;
    }
    rresp.reset_nonserial(buffer, nonserial_len);
    if (rresp.read_pld_from_stream_soc(cli.fd(), err) < 0) {
      lerr("Error reading RecvRsp from stream");
      return SCAFFOLD_SOCKET_ERROR;
    }
    rresp.print("recv:app:rx:hdr");

    if (rresp.err().v) {
      err = rresp.err();
      lerr("RecvRsp has error %s", strerror_sf(err.v));
      return SCAFFOLD_SOCKET_ERROR;
    }

    if (len > rresp.nonserial_pld_len())
      len = rresp.nonserial_pld_len();
    src_obj_id = rresp.src_obj_id();
  } else {
    info("recv: expected to read data, found EOF on soc %s", 
         cli.s().c_str());
    len = 0;
    return 0;
  }
  //SockIO::print("recv:app:data", (const unsigned char *)buffer, len);
  return 0;
}

int
SFSockLib::close_sf(int soc, sf_err_t &err)
{
  Cli &cli = get_cli(soc, err);
  if (cli.is_null()) {
    return ::close(soc);
  }

  info("closing scaffold socket");

  cli.save_flags();
  cli.set_sync();

  if (query_scafd_close(cli, err) < 0) {
    cli.restore_flags();
    lerr("query_scafd_close failed");
    return -2;
  }
  
  cli.restore_flags();
  //
  // Socket -> CLOSED or TIMEDWAIT
  //
  delete_cli(cli, err);
  return 0;
}

int
SFSockLib::query_scafd_close(const Cli &cli, sf_err_t &err)
{
  CloseReq creq;
  if (creq.write_to_stream_soc(cli.fd(), err) < 0)
    return SCAFFOLD_SOCKET_ERROR;
  creq.print("close:app:tx");

   Message m;
   if (m.read_hdr_from_stream_soc(cli.fd(), err) < 0)
     return SCAFFOLD_SOCKET_ERROR;
   
   if (m.type() == Message::HAVE_DATA) {
     info("Got HaveData before CloseRsp; discarding");
     HaveData hdata;
     hdata.read_pld_from_stream_soc(cli.fd(), err);
     hdata.print("hdata:app:rx");
          
     // Expect a CloseRsp directly after HaveData
     CloseRsp crsp;
     if (crsp.read_from_stream_soc(cli.fd(), err) < 0)
       return SCAFFOLD_SOCKET_ERROR;
     crsp.print("close:app:rx");
     
     if (crsp.err().v) {
       err = crsp.err();
       return SCAFFOLD_SOCKET_ERROR;
     }
   } else if (m.type() == Message::CLOSE_RSP) {
     CloseRsp crsp;
     crsp.read_pld_from_stream_soc(cli.fd(), err);
     crsp.print("close:app:rx");
     
     if (crsp.err().v) {
       err = crsp.err();
       return SCAFFOLD_SOCKET_ERROR;
     }
   } else {
     lerr("unexpected message after CloseReq");
     return SCAFFOLD_SOCKET_ERROR;
   }
   
   return 0;
}

bool
SFSockLib::is_valid(const struct sockaddr_sf &addr, bool local) const
{
  if (addr.sf_family == AF_SCAFFOLD) {
    if ((local && !is_reserved(addr.sf_oid)) ||
        (!local && !is_reserved(addr.sf_oid)))
      return true;
    else {
      lerr("local !is_reserved");
    }
  } else {
    lerr("Bad address family %d", addr.sf_family);
  }
  return false;
}

bool
SFSockLib::is_reserved(sf_oid_t obj_id) const
{
  if  (obj_id.s_oid == htons(CONTROLLER_OID) || 
       obj_id.s_oid == htons(SCAFFOLD_OID) || 
       obj_id.s_oid == htons(SCAFFOLD_NULL_OID)) {
    fprintf(stderr, "object ID %s not allowed", oid_to_str(obj_id));
    return true;
  }
  return false;
}

int
SFSockLib::migrate_sf(int soc, sf_err_t &err)
{
  info("migrate_sf");
  Cli &cli = get_cli(soc, err);
  if (cli.is_null())
    return SCAFFOLD_SOCKET_ERROR;

  if (cli.state() != State::BOUND) {
    err = ENOTCONN;
    lerr("migrate_sf: not BOUND");
    return SCAFFOLD_SOCKET_ERROR;
  }

  cli.save_flags();
  cli.set_sync();
  if (query_scafd_migrate(cli, err) < 0) {
    cli.restore_flags();
    return SCAFFOLD_SOCKET_ERROR;
  }
  cli.restore_flags();

  // within Scafd socket state transitions to 
  // one of the SFSock::is_user_closed_state(s), 
  // it's OK to delete the app end of the socket
  delete_cli(cli, err);
  return 0;
}

int
SFSockLib::query_scafd_migrate(const Cli &cli, sf_err_t &err)
{
  info("query_scafd_migrate");
  MigrateReq mreq;
  if (mreq.write_to_stream_soc(cli.fd(), err) < 0)
    return SCAFFOLD_SOCKET_ERROR;
  mreq.print("migrate:app:tx");

  // reuse CloseRsp
  CloseRsp crsp;
  if (crsp.read_from_stream_soc(cli.fd(), err) < 0)
    return SCAFFOLD_SOCKET_ERROR;
  crsp.print("migrate:app:rx");
  
  if (crsp.err().v) {
    err = crsp.err();
    return SCAFFOLD_SOCKET_ERROR;
  }
  return 0;
}
