/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
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
#include <libserval/serval.h>
#include <serval/platform.h>
#include "lock.hh"

#if defined(OS_ANDROID)
const char *SVSockLib::SERVAL_TCP_PATH = "/data/local/tmp/serval-tcp.sock";
const char *SVSockLib::SERVAL_UDP_PATH = "/data/local/tmp/serval-udp.sock";
#else
const char *SVSockLib::SERVAL_TCP_PATH = "/tmp/serval-tcp.sock";
const char *SVSockLib::SERVAL_UDP_PATH = "/tmp/serval-udp.sock";
#endif
Cli SVSockLib::null_cli;
uint32_t SVSockLib::_serval_id = 0;

//
// SVSockLib
//

SVSockLib::SVSockLib(int serval_id)
{
    char logname[30];
    memset(logname, 0, 30);
    snprintf(logname, 29, "libserval-%u.log", getpid());
    Logger::initialize(logname);
    Logger::set_debug_level(Logger::LOG_DEBUG);

    if (!serval_id) {
        char *serval_id_str = getenv("SERVAL_ID");
        if (!serval_id_str)
            _serval_id = 0;
        else {
            _serval_id = strtol(serval_id_str, NULL, 10);
            if (errno == EINVAL) {
                lerr("illegal value (%s) found in SERVAL_ID; "
                     "expected uint32_t; using 0");
                _serval_id = 0;
            }
        }
    } else
        _serval_id = serval_id;
    bzero(&_udp_srv, sizeof(_udp_srv));
    _udp_srv.sun_family = AF_LOCAL;
    sprintf(_udp_srv.sun_path, SERVAL_UDP_PATH, _serval_id);

    bzero(&_tcp_srv, sizeof(_tcp_srv));
    _tcp_srv.sun_family = AF_LOCAL;
    sprintf(_tcp_srv.sun_path, SERVAL_TCP_PATH, _serval_id);

    INIT_LIST_HEAD(&_cli_list);
}

SVSockLib::~SVSockLib()
{
    while (1) {
        if (list_empty(&_cli_list))
            break;

        Cli *c = (Cli *)_cli_list.next;
        sv_err_t err;

        delete_cli(c, err);
    }
}

int SVSockLib::socket_sv(int domain, int type, int proto, sv_err_t &err)
{
    if (domain != AF_SERVAL) {
        err = EAFNOSUPPORT;     /* address family is not supported */
        return SERVAL_SOCKET_ERROR;
    }
  
    if (type != SOCK_DGRAM && type != SOCK_STREAM) {
        err =  EPROTONOSUPPORT; /* proto type not supported within domain */
        return SERVAL_SOCKET_ERROR;
    }
  
    if (!proto) {
        switch (type) {
        case SOCK_DGRAM:
            proto = SERVAL_PROTO_UDP;
            break;
        case SOCK_STREAM:
            proto = SERVAL_PROTO_TCP;
            break;
        default:
            lerr("Unsupported socket type\n");
            return SERVAL_SOCKET_ERROR;
        }
    }
    int fd;
    sv_proto_t p = { proto };

    if (create_cli(p, fd, err) < 0) {
        fprintf(stderr, "Could not create client\n");
        return SERVAL_SOCKET_ERROR;
    }
  
    info("socket_sv: created socket for fd %d", fd);
    return fd;
}

Cli &SVSockLib::get_cli(int soc, sv_err_t &err)
{
    struct list_head *pos;

    list_for_each(pos, &_cli_list) {
        Cli *c = (Cli *)pos;
        if (c->fd() == soc) {
            return *c;
        }
    }

    err = EBADF;
    return null_cli;
}

int SVSockLib::basic_checks(int soc, const struct sockaddr *addr, 
                            socklen_t addr_len, bool check_local,
                            sv_err_t &err)
{
    if (addr_len < (socklen_t)sizeof(struct sockaddr_sv) || !addr) {
        err =  EINVAL;
        lerr("bad address length");
        return SERVAL_SOCKET_ERROR;
    }

    const struct sockaddr_sv *sv_addr =  (const struct sockaddr_sv *)addr;
    if (!is_valid(*sv_addr, check_local)) {
        err = EADDRNOTAVAIL;
        lerr("invalid Serval address");
        return SERVAL_SOCKET_ERROR;
    }
    return 0;
}

//
// Bind
//
int SVSockLib::bind_sv(int soc, const struct sockaddr *addr, socklen_t addr_len,
                       sv_err_t &err)
{
    Cli &cli = get_cli(soc, err);
    if (cli.is_null() ||
        basic_checks(soc, addr, addr_len, true, err) < 0)
        return ::bind(soc, addr, addr_len);

    if (check_state_for_bind(cli, err) < 0)
        return SERVAL_SOCKET_ERROR;

    SimpleLock slock(cli.get_lock());

    const struct sockaddr_sv *sv_addr =  (const struct sockaddr_sv *)addr;
    cli.save_flags();
    cli.set_sync();
    if (query_serval_bind(sv_addr, cli, err) < 0) {
        cli.restore_flags();
        return SERVAL_SOCKET_ERROR;
    }
    cli.restore_flags();
    cli.set_state(State::UNBOUND);
    err = SERVAL_OK;
    info("bind_sv: bind on soc %d successful", soc);
    return 0;
}

int SVSockLib::check_state_for_bind(const Cli &cli, sv_err_t &err) const
{
    if (cli.state() != State::CLOSED) {
        lerr("check_state_for_bind: failed state %s", 
             State::state_s(cli.state()));
        err = EADDRINUSE;
        return SERVAL_SOCKET_ERROR;
    }
    return 0;
}

int SVSockLib::query_serval_bind(const struct sockaddr_sv *sv_addr,
                                 Cli &cli, sv_err_t &err)
{
    BindReq breq(sv_addr->sv_srvid, sv_addr->sv_flags, 
                 sv_addr->sv_prefix_bits);

    if (breq.write_to_stream_soc(cli.fd(), err) < 0)
        return SERVAL_SOCKET_ERROR;
    breq.print("bind:app:tx");
    
    BindRsp bresp;
    if (bresp.read_from_stream_soc(cli.fd(), err) < 0)
        return SERVAL_SOCKET_ERROR;
    bresp.print("bind:app:rx");
    
    if (bresp.err().v) {
        err = bresp.err();
        info("Got bind error %d:%s", err.v, strerror(err.v));
        return SERVAL_SOCKET_ERROR;
    }
    return 0;
}

bool SVSockLib::is_non_blocking(int fd) const
{
    int flags;
    
    if ((flags = fcntl (fd, F_GETFL, 0)) < 0) {
        lerr("F_GETFL error on fd %d (%s)", fd, strerror(errno));
        return SERVAL_SOCKET_ERROR;
    }
    return (flags | O_NONBLOCK);
}

int SVSockLib::check_state_for_connect(const Cli &cli, sv_err_t &err) const
{
    info("Checking whether state %s is valid", State::state_s(cli.state()));

    // Conn is non-blocking, and prev attempt not completed
    if (cli.state() == State::REQUEST) {
        if (is_non_blocking(cli.fd())) {
            err = EALREADY;
            info("error %s", strerror_sv(err.v));
        } else {
            lerr("strange state %s found while %s expected",
                 State::state_s(cli.state()), 
                 State::state_s(State::UNBOUND));
            err = ESVINTERNAL;
        }
        return SERVAL_SOCKET_ERROR;
    }
  
    if (cli.state() == State::BOUND) {
        err = EISCONN;
        info("error %s", strerror_sv(err.v));
        return SERVAL_SOCKET_ERROR;
    }
  
    if (cli.state() == State::LISTEN) {
        err = EOPNOTSUPP;
        info(" error %s", strerror_sv(err.v));
        return SERVAL_SOCKET_ERROR;
    }
  
    if (cli.state() != State::UNBOUND && cli.state() != State::CLOSED) {
        // CLOSED is a valid state in case a client app does not want to
        // register its service id with the service router
        err = ESVINTERNAL;
        info("error %s", strerror_sv(err.v));
        return SERVAL_SOCKET_ERROR;
    }
    info("OK");
    return 0;
}

int SVSockLib::connect_sv(int soc, const struct sockaddr *addr, socklen_t addr_len,
                          sv_err_t &err)
{
    Cli &cli = get_cli(soc, err);

    info("connecting with address family %d", addr->sa_family);

    if (cli.is_null() ||
        basic_checks(soc, addr, addr_len, false, err) < 0) {
        return ::connect(soc, addr, addr_len);
    }

    if (check_state_for_connect(cli, err) < 0) {
        return SERVAL_SOCKET_ERROR;
    }

    SimpleLock slock(cli.get_lock());

    info("remote_service_id %s", 
         service_id_to_str(&((const struct sockaddr_sv *)addr)->sv_srvid));

    bool nb = false;
    if (cli.is_non_blocking()) {
        cli.set_connect_in_progress(true);
        nb = true;
    }
  
    const struct sockaddr_sv *sv_addr =  (const struct sockaddr_sv *)addr;
    cli.save_flags();
    cli.set_sync();
    if (query_serval_connect(sv_addr, nb, cli, err) < 0) {
        cli.restore_flags();
        return SERVAL_SOCKET_ERROR;
    }
    cli.restore_flags();
    cli.set_state(State::BOUND);
    err = SERVAL_OK;
    return 0;
}

int SVSockLib::query_serval_connect(const struct sockaddr_sv *sv_addr, 
                                    bool nb, Cli &cli, sv_err_t &err)
{
    uint16_t flags = sv_addr->sv_flags;
    ConnectReq creq(sv_addr->sv_srvid, nb, flags);

    if (creq.write_to_stream_soc(cli.fd(), err) < 0) {
        lerr("write to stream sock failed");
        return SERVAL_SOCKET_ERROR;
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
             strerror_sv(err.v));
        //
        // Linux does not support SO_SNDBUF modifications either
        // What a bummer!
        // avoid select()'ing before connect finished
        // if (cli.set_unwritable(err) < 0)
        // return SERVAL_SOCKET_ERROR;
        //
        cli.set_state(State::REQUEST);
        return SERVAL_SOCKET_ERROR;
    }
  
    info("nb = %s, b = %s", 
         (cli.is_non_blocking() ? "t" : "f"),
         (cli.is_blocking() ? "t" : "f"));
    info("reading on fd %d", cli.fd());
  
    // check: return EWOULDBLOCK when approp. 
    ConnectRsp cresp;
    if (cresp.read_from_stream_soc(cli.fd(), err) < 0) {
        lerr("read from stream sock failed");
        if (err == EINTR) 
            cli.set_interrupted(true);
        return SERVAL_SOCKET_ERROR;
    }
  
    cresp.print("connect:app:rx");            // add TIMEOUT
  
    if (cresp.err().v) {
        err = cresp.err();
        lerr("bad response from serval");
        return SERVAL_SOCKET_ERROR;
    }
    return 0;
}

//
// todo: support other async errors; currently handles only connect()
// 
int SVSockLib::getsockopt_sv(int soc, int level, int option_name, 
                             void *option_value, socklen_t *option_len,
                             sv_err_t &err)
{
    int *option = (int *)option_value;

    Cli &cli = get_cli(soc, err);
    if (cli.is_null()) 
        return ::getsockopt(soc, level, option_name, option_value, option_len);
  
    switch (option_name) {
    case SO_ERROR: { // Conn is non-blocking, and prev attempt not completed
        if (!cli.is_connecting()) { // no async errors to report
            info("cli %s is not connecting", cli.s());
            *option = 0;
            return 0;
        }

        ConnectRsp cresp;
        int atleast = cresp.total_len();

        switch (cli.has_unread_data(atleast, err)) {
        case Cli::DATA_ERROR:
                lerr("cli %s has no unread data", cli.s());
                return SERVAL_SOCKET_ERROR;
        case Cli::DATA_NOT_ENOUGH:
            info("no async errors to read; still connecting");
            *option = EINPROGRESS;
            return -1;
        case Cli::DATA_WOULD_BLOCK:
            lerr("cli %s returned EWOULDBLOCK", cli.s());
                *option = EWOULDBLOCK;
                //*option = EINPROGRESS;
                return -1;
        case Cli::DATA_CLOSED:
            return 0;
        case Cli::DATA_READY:
            break;
        }
    
        SimpleLock slock(cli.get_lock());

        cli.save_flags();
        cli.set_sync();
        if (query_serval_soerror(cli, err) < 0) {
            cli.restore_flags();
            return SERVAL_SOCKET_ERROR;
        }
        cli.restore_flags();
        break;
    }
    default:
        lerr("SVSockLib::getsockopt_sv: option %d not supported", level);
        err = EINVAL;
        return SERVAL_SOCKET_ERROR;
    }

    *option = 0;

    return 0;
}

int SVSockLib::query_serval_soerror(Cli &cli, sv_err_t &err)
{
    ConnectRsp cresp;

    if (cresp.read_from_stream_soc(cli.fd(), err) < 0) // nothing to read
        return SERVAL_SOCKET_ERROR;
    cresp.print("connect:app:rx");
  
    if (cresp.err().v) {
        err = cresp.err();
        info("getsockopt_sv: ERR cli [%s] : %s", cli.s(),
             strerror_sv(err.v));
        return SERVAL_SOCKET_ERROR;
    }
    //if (cli.reset_writability(err) < 0)
    //    return SERVAL_SOCKET_ERROR;
    cli.set_state(State::BOUND);
    cli.set_connect_in_progress(false);
    info("getsockopt_sv: OK cli [%s]", cli.s());
    return 0;
}

//
// Listen
//
int SVSockLib::listen_sv(int soc, int backlog, sv_err_t &err)
{ 
    Cli &cli = get_cli(soc, err);
    if (cli.is_null())
        return ::listen(soc, backlog);

    if (check_state_for_listen(cli, err) < 0)
        return SERVAL_SOCKET_ERROR;

    SimpleLock slock(cli.get_lock());

    cli.save_flags();
    cli.set_sync();
    if (query_serval_listen(backlog, cli, err) < 0) {
        cli.restore_flags();
        return SERVAL_SOCKET_ERROR;
    }
    cli.restore_flags();
    cli.set_state(State::LISTEN);
    return 0;
}


int SVSockLib::listen_sv(int soc, const struct sockaddr *addr,
                         socklen_t addr_len,
                         int backlog, sv_err_t &err)
{
    Cli &cli = get_cli(soc, err);
    if (cli.is_null() ||
        basic_checks(soc, addr, addr_len, true, err) < 0)
        return SERVAL_SOCKET_ERROR;

    SimpleLock slock(cli.get_lock());

    const struct sockaddr_sv *sv_addr =  (const struct sockaddr_sv *)addr;

    info("multi-listen: on service id %s", service_id_to_str(&sv_addr->sv_srvid));
    cli.save_flags();
    cli.set_sync();
    if (query_serval_listen(backlog, sv_addr->sv_srvid, cli, err) < 0) {
        cli.restore_flags();
        return SERVAL_SOCKET_ERROR;
    }
    cli.restore_flags();
    cli.set_state(State::LISTEN);
    return 0;
}
 
int SVSockLib::query_serval_listen(int backlog, const sv_srvid_t& local_service_id, 
                                   Cli &cli, sv_err_t &err)
{
    ListenReq lreq(local_service_id, backlog);

    if (lreq.write_to_stream_soc(cli.fd(), err) < 0)
        return SERVAL_SOCKET_ERROR;
    lreq.print("listen:app:tx");

    ListenRsp lrsp;
    if (lrsp.read_from_stream_soc(cli.fd(), err) < 0)
        return SERVAL_SOCKET_ERROR;
    lrsp.print("listen:app:rx");
  
    if (lrsp.err().v) {
        err = lrsp.err();
        return SERVAL_SOCKET_ERROR;
    }
    return 0;
}

int SVSockLib::check_state_for_listen(const Cli &cli, sv_err_t &err) const
{
    if (cli.state() != State::UNBOUND && cli.state() != State::LISTEN) {
        lerr("check_state_for_listen: failed state is %s", 
             State::state_s(cli.state()));
        err = EINVAL; // todo: support listen without bind(); OS assigns serviceid
        return SERVAL_SOCKET_ERROR;
    }
    return 0;
}

int SVSockLib::query_serval_listen(int backlog, Cli &cli, sv_err_t &err)
{
    ListenReq lreq(backlog);

    if (lreq.write_to_stream_soc(cli.fd(), err) < 0)
        return SERVAL_SOCKET_ERROR;
    lreq.print("listen:app:tx");

    ListenRsp lrsp;
    if (lrsp.read_from_stream_soc(cli.fd(), err) < 0)
        return SERVAL_SOCKET_ERROR;
    lrsp.print("listen:app:rx");
  
    if (lrsp.err().v) {
        err = lrsp.err();
        return SERVAL_SOCKET_ERROR;
    }
    return 0;
}

//
// Accept
//
int SVSockLib::accept_sv(int soc, struct sockaddr *addr, socklen_t *addr_len,
                         sv_err_t &err)
{

    Cli &cli = get_cli(soc, err);
    if (cli.is_null()) {
        return ::accept(soc, addr, addr_len);
    }

    if (*addr_len < (socklen_t)sizeof(struct sockaddr_sv) || !addr) {
        err =  EINVAL;
        return SERVAL_SOCKET_ERROR;
    } else if (*addr_len % sizeof(struct sockaddr_sv) != 0) {
        err = EINVAL;
        return SERVAL_SOCKET_ERROR;
    }

    if (check_state_for_accept(cli, err) < 0)
        return SERVAL_SOCKET_ERROR;

    //using simple lock effectively synchronizes the entire function
    //to synchronize a code block for concurrent socket (cli) access
    //use cli.lock() and cli.unlock()
    SimpleLock slock(cli.get_lock());

    bool nb = false;
    if (cli.is_non_blocking()) {
        info("accept_sv: non-blocking");
        nb = true;
    } else
        info("accept_sv: blocking");

    cli.save_flags();
    cli.set_sync();
    AcceptRsp aresp;
    if (query_serval_accept1(nb, cli, aresp, err) < 0) {
        cli.restore_flags();
        return SERVAL_SOCKET_ERROR;
    }
    cli.restore_flags();
  
    int new_soc;
    if (create_cli(cli.proto(), new_soc, err) < 0)
        return SERVAL_SOCKET_ERROR;

    Cli &new_cli = get_cli(new_soc, err);
    if (new_cli.is_null())
        return SERVAL_SOCKET_ERROR;
  
    info("accept2");
    // blocking by default
    if (query_serval_accept2(nb, new_cli, aresp, err) < 0) {
        cli.restore_flags();
        delete_cli(&new_cli, err);
        return SERVAL_SOCKET_ERROR;
    }
    new_cli.set_state(State::BOUND);
  
    // On Linux, the new socket returned by accept() does not inherit file status
    // flags such as O_NONBLOCK and O_ASYNC from the listening socket. This
    // behaviour differs from the canonical BSD sockets implementation. Portable
    // programs should not rely on inheritance or non-inheritance of file status
    // flags and always explicitly set all required flags on the socket returned
    // from accept().
    struct sockaddr_sv *sv_addr =  (struct sockaddr_sv *)&addr[0];
    sv_addr->sv_family = AF_SERVAL;
    memcpy(&sv_addr->sv_srvid, &aresp.remote_service_id(), sizeof(sv_addr->sv_srvid));

    if (*addr_len >= (socklen_t)(2 * sizeof(struct sockaddr_sv))) {
        // also give back the remote service id
        struct sockaddr_sv *sv_addr2 =  (struct sockaddr_sv *)&addr[1];
        sv_addr2->sv_family = AF_SERVAL;   
        memcpy(&sv_addr2->sv_srvid, &aresp.remote_service_id(), sizeof(sv_addr2->sv_srvid));
        *addr_len = 2 * sizeof(struct sockaddr_sv);
    } else {
        *addr_len = sizeof(struct sockaddr_sv);
    }
    
    return new_cli.fd();
}

int SVSockLib::query_serval_accept2(bool nb, 
                                    Cli &cli, const AcceptRsp &aresp,
                                    sv_err_t &err)
{
    AcceptReq2 areq2(aresp.local_service_id(), aresp.flow_id(), nb);

    if (areq2.write_to_stream_soc(cli.fd(), err) < 0)
        return SERVAL_SOCKET_ERROR;
    areq2.print("accept2:app:tx");
  
    AcceptRsp2 aresp2;
    if (aresp2.read_from_stream_soc(cli.fd(), err) < 0)
        return SERVAL_SOCKET_ERROR;
    aresp2.print("accept2:app:rx");
    if (aresp2.err().v) {
        err = aresp2.err();
        return SERVAL_SOCKET_ERROR;
    }
    info("accepted new soc = %s", cli.s());
    return 0;
}

int SVSockLib::create_cli(sv_proto_t proto, int &new_soc, sv_err_t &err)
{
    new_soc = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (new_soc < 0) {
        lerr("create_cli cannot create new socket (%s)", 
             strerror(errno));
        err = errno;
        return SERVAL_SOCKET_ERROR;
    }
    Cli *new_cli = new Cli();

    if (!new_cli)
        return -1;

    new_cli->set_fd(new_soc);
    new_cli->set_proto(proto.v);
    if (new_cli->bind(err) < 0)
        return SERVAL_SOCKET_ERROR;
  
    // create a new soc for this accepted connection
    struct sockaddr_un *srv = NULL;
    switch (proto.v) {
    case SERVAL_PROTO_UDP:
        srv = &_udp_srv;
        break;
    case SERVAL_PROTO_TCP:
        srv = &_tcp_srv;
        break;
    default:
        lerr("illegal proto %d", proto.v);
        return SERVAL_SOCKET_ERROR;
    }
    if (connect(new_soc, (struct sockaddr *)srv, sizeof(*srv)) < 0) {
        lerr("create_cli: connect error [unix path %s]: %s", 
             srv->sun_path, strerror(errno));
        return SERVAL_SOCKET_ERROR;
    }
  
    if (new_cli->set_bufsize(true, RCV_BUFSIZE_LEN, err) < 0 ||
        new_cli->set_bufsize(false, SEND_BUFSIZE_LEN, err) < 0)
        return SERVAL_SOCKET_ERROR;

    list_add_tail(&new_cli->lh, &_cli_list);

    info("create_cli: %s", new_cli->s());

    return 0;
}

int SVSockLib::delete_cli(Cli *cli, sv_err_t &err)
{
    if (cli->fd() >= 0)
        if (::close(cli->fd()) < 0) {
            //lerr("error closing fd %d", cli->fd());
            err = ESVINTERNAL;
            return SERVAL_SOCKET_ERROR;
        }
  
    if (get_cli(cli->fd(), err).is_null()) {
        err = ESVINTERNAL;
        return SERVAL_SOCKET_ERROR;
    }
  
    list_del(&cli->lh);
    delete cli;

    return 0;
}

int SVSockLib::query_serval_accept1(bool nb, Cli &cli, AcceptRsp &aresp,
                                    sv_err_t &err)
{
    AcceptReq areq;

    if (areq.write_to_stream_soc(cli.fd(), err) < 0)
        return SERVAL_SOCKET_ERROR;

    areq.print("accept:app:tx");

    if (nb) {
        int size = aresp.total_len();

        switch (cli.has_unread_data(size, err)) {
        case Cli::DATA_ERROR:
            return SERVAL_SOCKET_ERROR;
        case Cli::DATA_WOULD_BLOCK:
        case Cli::DATA_NOT_ENOUGH:
            lerr("accept1: no data to read");
            err = EAGAIN; // or EWOULDBLOCK
            return SERVAL_SOCKET_ERROR;
        case Cli::DATA_CLOSED:
            return 0;
        case Cli::DATA_READY:
            break;
        }
    }
  
    if (aresp.read_from_stream_soc(cli.fd(), err) < 0)
        return SERVAL_SOCKET_ERROR;
    aresp.print("accept:app:rx");            // add TIMEOUT

    if (aresp.err().v) {
        err = aresp.err();
        return SERVAL_SOCKET_ERROR;
    }
    return 0;
}

int SVSockLib::check_state_for_accept(const Cli &cli, sv_err_t &err) const
{
    if (cli.state() != State::LISTEN) {
        lerr("check_state_for_accept: failed state is %s, expected %s", 
             State::state_s(cli.state()), 
             State::state_s(State::LISTEN));
        return SERVAL_SOCKET_ERROR;
    }
    return 0;
}

ssize_t SVSockLib::sendmsg_sv(int soc, const struct msghdr *message, int flags,
                              sv_err_t &err) {
  
    info("sending message for socket %i", soc);
    if (!message || !message->msg_iov) {
        err = EINVAL;
        return SERVAL_SOCKET_ERROR;
    }
  
    //simply copy into a buffer and send it using normal send
    uint8_t buffer[MAX_MSG_SIZE];
  
    uint8_t* head = buffer;
  
    size_t i = 0;
  
    for(i = 0; i < (size_t)message->msg_iovlen; i++) {
        memcpy(head, message->msg_iov[i].iov_base, message->msg_iov[i].iov_len);
        head += message->msg_iov[i].iov_len;
    }
  
    if(message->msg_name && message->msg_namelen > 0) {
        if(message->msg_namelen < sizeof(struct sockaddr_sv)) {
            err = EINVAL;
            return SERVAL_SOCKET_ERROR;
        }
    
        return sendto_sv(soc, buffer, head - buffer, flags, (struct sockaddr*) message->msg_name, message->msg_namelen, err);
    }
  
    return send_sv(soc, buffer, head - buffer, flags, err);
}

ssize_t SVSockLib::recvmsg_sv(int soc, struct msghdr *message, int flags,
                              sv_err_t &err) {
    
    if (!message || !message->msg_iov) {
        err = EINVAL;
        return SERVAL_SOCKET_ERROR;
    }
  
    //simply recv in a buffer and copy it into the iov message
    uint8_t buffer[MAX_MSG_SIZE];
  
    size_t totallen = 0;
    size_t i = 0;
    for(i = 0; i < (size_t)message->msg_iovlen; i++) {
        totallen += message->msg_iov[i].iov_len;
    }
  
    if(totallen > MAX_MSG_SIZE) {
        err = EINVAL;
        return SERVAL_SOCKET_ERROR;
    }

    ssize_t ret = recv_sv(soc, buffer, totallen, flags,err);

    if(ret < 0) {
        return SERVAL_SOCKET_ERROR;
    }

    uint8_t* head = buffer;
    for(i = 0; i < (size_t)message->msg_iovlen; i++) {
        memcpy(message->msg_iov[i].iov_base, head, message->msg_iov[i].iov_len);
        head += message->msg_iov[i].iov_len;
    }

    return ret;
}


ssize_t SVSockLib::send_sv(int soc, const void *buffer, size_t length, int flags,
                           sv_err_t &err)
{ 
    Cli &cli = get_cli(soc, err);

    if (cli.is_null())   // todo: what if local end is shut down ?
        return ::send(soc, buffer, length, flags);
  
    if (check_state_for_send(cli, err) < 0) {
        return SERVAL_SOCKET_ERROR;
    }
  
    // buffer checks
    if (!buffer) {
        err = EINVAL;
        return SERVAL_SOCKET_ERROR;
    }
  
    if (length == 0) {
        info("send_sv: 0 length send_sv");
        return 0;
    }

    int bufsize;
    if (cli.get_bufsize(false, bufsize, err) < 0)  // false => snd buf
        return SERVAL_SOCKET_ERROR;
    
    if ((int)length > bufsize) {
        lerr("send: buf len (%d) > bufsize (%d)",  length, bufsize);
        err = EMSGSIZE;
        return SERVAL_SOCKET_ERROR;
    }

    SimpleLock slock(cli.get_lock());

    bool nb = false;
    if (cli.is_non_blocking())
        nb = true;
  
    cli.save_flags();
    cli.set_sync();
    if (query_serval_send(nb, buffer, length, flags, cli, err) < 0) {
        cli.restore_flags();
        return SERVAL_SOCKET_ERROR;
    }
    cli.restore_flags();
    return length;
}

ssize_t SVSockLib::sendto_sv(int soc, const void *buffer, size_t length, int flags,
                             const struct sockaddr *dst_addr, socklen_t addr_len, 
                             sv_err_t &err)
{
    uint32_t ipaddr = 0;
    Cli &cli = get_cli(soc, err);

    info("cli %s", cli.is_null() ? "null" : cli.s());

    if (cli.is_null() ||
        basic_checks(soc, dst_addr, addr_len, false, err) < 0)
        return ::sendto(soc, buffer, length, flags, dst_addr, addr_len);
  
    const sv_srvid_t *remote_service_id;
    remote_service_id = &((const struct sockaddr_sv *)dst_addr)->sv_srvid;
  
    if (addr_len >= sizeof(struct sockaddr_sv) + sizeof(struct sockaddr_in)) {
        struct sockaddr_in *saddr = 
            (struct sockaddr_in *)(((char *)dst_addr) + sizeof(struct sockaddr_sv));
        if (saddr->sin_family == AF_INET)
            memcpy(&ipaddr, &saddr->sin_addr, sizeof(ipaddr));
    }
    info("sendto_sv: remote_service_id %s addr %u", 
         service_id_to_str(remote_service_id), ipaddr);

    if (check_state_for_sendto(cli, err) < 0)
        return SERVAL_SOCKET_ERROR;

    if (length == 0) {
        info("send_sv: 0 length send_sv");
        return 0;
    }

    int bufsize;
    if (cli.get_bufsize(false, bufsize, err) < 0)  // false => snd buf
        return SERVAL_SOCKET_ERROR;
    
    if ((int)length > bufsize) {
        lerr("send: buf len (%d) > bufsize (%d)",  length, bufsize);
        err = EMSGSIZE;
        return SERVAL_SOCKET_ERROR;
    }
  
    SimpleLock slock(cli.get_lock());

    cli.save_flags();
    cli.set_sync();
    if (query_serval_sendto(*remote_service_id, ipaddr, 
                            buffer, length, flags, cli, err) < 0) {
        cli.restore_flags();
        return SERVAL_SOCKET_ERROR;
    }
    cli.restore_flags();
    return length;
}

int SVSockLib::check_state_for_send(const Cli &cli, sv_err_t &err) const
{
    if (cli.state() == State::REQUEST) {
        // What would be the correct thing to return here while connecting?
        err = EWOULDBLOCK;
        return SERVAL_SOCKET_ERROR;
    }
    if (cli.state() != State::BOUND) {

        err = ENOTCONN;
        lerr("check_state_for_send: failed, state is %s", 
             State::state_s(cli.state()));
        return SERVAL_SOCKET_ERROR;
    }
    return 0;
}

int SVSockLib::check_state_for_sendto(const Cli &cli, sv_err_t &err) const
{
    if (cli.state() != State::CLOSED &&
        cli.state() != State::BOUND &&   // allow sendto on connected sockets
        cli.state() != State::UNBOUND) {
        err = ESOCKNOTBOUND;
        lerr("check_state_for_sendto: failed, state is %s", 
             State::state_s(cli.state()));
        return SERVAL_SOCKET_ERROR;
    }
    return 0;
}

int SVSockLib::query_serval_send(bool nb, const void *buffer, 
                                 size_t length, int flags,
                                 Cli &cli, sv_err_t &err)
{
    SendReq sreq(nb, (unsigned char *)buffer, length, flags);

    if (sreq.write_to_stream_soc(cli.fd(), err) < 0)
        return SERVAL_SOCKET_ERROR;
    sreq.print("send:app:tx");
    
    bool got_havedata_msg = false;
 
    Message m;
    if (m.read_hdr_from_stream_soc(cli.fd(), err) < 0)
        return SERVAL_SOCKET_ERROR;
  
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
            err = ESVINTERNAL;
            return SERVAL_SOCKET_ERROR;
        }
    } else if (errno == EAGAIN)
        info("no data to read; ok to send req");
  
    if (m.type() == Message::SEND_RSP) {
        // Only message payload to read
        SendRsp srsp;
        if (srsp.read_pld_from_stream_soc(cli.fd(), err) < 0)
            return SERVAL_SOCKET_ERROR;
    
        srsp.print("send:app:rx");
        if (srsp.err().v) {
            err = srsp.err();
            return SERVAL_SOCKET_ERROR;
        }
        info("sent %d bytes through soc %s", length, cli.s());
    } else
        lerr("got invalid message, expected SEND_RSP got %s", 
             m.type_cstr());
  
    if (got_havedata_msg) {
        ClearData cdata;
        if (cdata.write_to_stream_soc(cli.fd(), err) < 0)
            return SERVAL_SOCKET_ERROR;
    }
  
    return 0;
}

int SVSockLib::query_serval_sendto(const sv_srvid_t& dst_service_id,
                                   uint32_t ipaddr,
                                   const void *buffer, size_t length, int flags,
                                   Cli &cli, sv_err_t &err)
{
    SendReq sreq(dst_service_id, ipaddr, (unsigned char *)buffer, length, flags);

    if (sreq.write_to_stream_soc(cli.fd(), err) < 0)
        return SERVAL_SOCKET_ERROR;

    sreq.print("sendto:app:tx");

    bool got_havedata_msg = false;

    Message m;
    if (m.read_hdr_from_stream_soc(cli.fd(), err) < 0)
        return SERVAL_SOCKET_ERROR;

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
            lerr("expected SendRsp message got %d type", m.type());
            err = ESVINTERNAL;
            return SERVAL_SOCKET_ERROR;
        }
    } else if (errno == EAGAIN) {
        info("no data to read; ok to send req");
    }

    if (m.type() == Message::SEND_RSP) {
        // Only message payload to read
        SendRsp srsp;
        if (srsp.read_pld_from_stream_soc(cli.fd(), err) < 0)
            return SERVAL_SOCKET_ERROR;

        srsp.print("send:app:rx");
        if (srsp.err().v) {
            err = srsp.err();
            return SERVAL_SOCKET_ERROR;
        }
        info("sent %d bytes through soc %s", length, cli.s());
    } else {
        lerr("got invalid message, expected SEND_RSP got %s",m.type_cstr());
    }

    if (got_havedata_msg) {
        ClearData cdata;
        if (cdata.write_to_stream_soc(cli.fd(), err) < 0)
            return SERVAL_SOCKET_ERROR;
    }

    return 0;
}

ssize_t SVSockLib::recv_sv(int soc, void *buffer, size_t length, int flags,
                           sv_err_t &err)
{
    Cli &cli = get_cli(soc, err);
    if (cli.is_null())   // todo: what if local end is shut down ?
        return ::recv(soc, buffer, length, flags);

    if (!buffer) {
        err = EINVAL;
        return SERVAL_SOCKET_ERROR;
    }
  
    SimpleLock slock(cli.get_lock());

    bool nb = false;
    if (cli.is_non_blocking())
        nb = true;
  
    info("receiving data");

    sv_srvid_t src_service_id; // ignore this since it's connected 
    uint32_t src_ipaddr;
    cli.save_flags();
    cli.set_sync();
    if (query_serval_recv(nb, (unsigned char *)buffer, 
                          length, flags, src_service_id, src_ipaddr,
                          cli, err) < 0) {
        cli.restore_flags();
        lerr("query_serval_recv returned error '%s'", strerror_sv(err.v));
        return SERVAL_SOCKET_ERROR;
    }
    cli.restore_flags();
  
    info("received %zu bytes data", length);

    return length;
}

ssize_t SVSockLib::recvfrom_sv(int soc, void *buffer, size_t length, int flags,
                               struct sockaddr *src_addr, socklen_t *addr_len,
                               sv_err_t &err)
{
    Cli &cli = get_cli(soc, err);
    if (cli.is_null())   // todo: what if local end is shut down ?
        return ::recvfrom(soc, buffer, length, flags, src_addr, addr_len);

    if (!buffer) {
        err = EINVAL;
        return SERVAL_SOCKET_ERROR;
    }
  
    int bufsize;
    if (cli.get_bufsize(true, bufsize, err) < 0)  // false => rcv buf
        return SERVAL_SOCKET_ERROR;

    if (bufsize == 0) {
        lerr("recv buffer size is 0");
        return SERVAL_SOCKET_ERROR;
    }
  
    SimpleLock slock(cli.get_lock());

    bool nb = false;
    if (cli.is_non_blocking())
        nb = true;
  
    sv_srvid_t src_service_id;
    uint32_t src_ipaddr = 0;
  
    cli.save_flags();
    cli.set_sync();
    if (query_serval_recv(nb, (unsigned char *)buffer, 
                          length, flags, src_service_id, src_ipaddr,
                          cli, err) < 0) {
        cli.restore_flags();
        return SERVAL_SOCKET_ERROR;
    }
    cli.restore_flags();

    struct sockaddr_sv *sv_addr = (struct sockaddr_sv *)&src_addr[0];
    sv_addr->sv_family = AF_SERVAL;
    memcpy(&sv_addr->sv_srvid, &src_service_id, sizeof(sv_addr->sv_srvid));

    if (*addr_len >= sizeof(struct sockaddr_sv) + sizeof(struct sockaddr_in)) {
        struct sockaddr_in* saddr = (struct sockaddr_in*) (sv_addr + 1);
        saddr->sin_family = AF_INET;
        saddr->sin_addr.s_addr = src_ipaddr;
        *addr_len = sizeof(struct sockaddr_sv) + sizeof(struct sockaddr_in);
    } else { 
        *addr_len = sizeof(struct sockaddr_sv);
    }
    return length;
}


int SVSockLib::query_serval_recv(bool nb, unsigned char *buffer, size_t &len, 
                                 int flags, sv_srvid_t &src_service_id, 
                                 uint32_t& src_ipaddr,
                                 Cli &cli, sv_err_t &err)
{
    info("query_serval_recv");
    bool got_havedata_msg = false;

    //if (cli.proto().v == SERVAL_PROTO_TCP) {
    if (nb) {  // NON-BLOCKING
        // first check for null HaveData message
        // this is used to activate select

        info("non-blocking socket %i, type = %i", cli.fd(), cli.proto().v);
        HaveData hdata;
        int size = hdata.total_len();

        switch (cli.has_unread_data(size, err)) {
        case Cli::DATA_ERROR:
            lerr("has_unread_data returned error");
            return SERVAL_SOCKET_ERROR;
        case Cli::DATA_WOULD_BLOCK:
        case Cli::DATA_NOT_ENOUGH:
            err = EWOULDBLOCK;           // or EAGAIN
            lerr("non-blocking would block");
            return SERVAL_SOCKET_ERROR;
        case Cli::DATA_CLOSED:
            len = 0;
            return 0;
        case Cli::DATA_READY:
            break;
        }
        info("reading hdata in nb mode");
        hdata.read_from_stream_soc(cli.fd(), err);
        hdata.print("hdata:app:rx");
        // we have a message, request for data
    } else {          // BLOCKING
        // check if HaveData exists and discard it
        // This allows select() to wake up without
        // reading anything from the socket buffers
        info("recv_sv on blocking socket %i",cli.fd());
        
        switch (cli.has_unread_data(1, err)) {
        case Cli::DATA_ERROR:
            return -1;
        case Cli::DATA_WOULD_BLOCK:
            break;
        case Cli::DATA_NOT_ENOUGH:
            break;
        case Cli::DATA_CLOSED:
            len = 0;
            return 0;
        case Cli::DATA_READY:
            // This must be HaveData
            HaveData hdata;
            //int size = hdata.total_len();
            int len = hdata.read_from_stream_soc(cli.fd(), err);

            if (len < 0) {
                lerr("found unexpected msg (want HaveData)");
                err = ESVINTERNAL;
                return SERVAL_SOCKET_ERROR;
            } else {
                info("Got HaveData Msg len=%d", len);
                hdata.print("hdata:app:rx");
                got_havedata_msg = true;
            }
            break;
        }
    }

    // Now ready to send read request
    info("sending recv req of len %d", len);
    RecvReq rreq(len, flags);
    if (rreq.write_to_stream_soc(cli.fd(), err) < 0) {
        lerr("Error writing RecvReq to stream");
        return SERVAL_SOCKET_ERROR;
    }
    rreq.print("recv:app:tx");

    // In 3 diff cases, we still reach here
    // TCP non-blocking, we found a HaveData message,
    //  and we sent a RecvReq, and waiting for a resp
    // TCP blocking, we sent a RecvReq, and waiting for a resp
    // UDP blocking, we simply wait for a RecvRsp
    Message m;
    if (m.read_hdr_from_stream_soc(cli.fd(), err) < 0) {
        lerr("Cannot read response message from stream");
        return SERVAL_SOCKET_ERROR;
    }

    info("read message type=%s", m.type_cstr());

    //if (cli.proto().v == SERVAL_PROTO_TCP && m.type() == Message::HAVE_DATA) {
    if (m.type() == Message::HAVE_DATA) {
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
            err = ESVINTERNAL;
            return SERVAL_SOCKET_ERROR;
        }
    }

    // We read RecvRsp header; now send a ClearData message if TCP NON-BLOCKING
    // OR, if we received a HaveData in blocking mode to wake up 
    // a select(), to clear the notification
    //if (cli.proto().v == SERVAL_PROTO_TCP && (nb || got_havedata_msg)) {
    if (nb || got_havedata_msg) {
        ClearData cdata;
        if (cdata.write_to_stream_soc(cli.fd(), err) < 0) {
            lerr("Error writing ClearData to stream");
            return SERVAL_SOCKET_ERROR;
        }
        cdata.print("cdata:app:tx");
    }

    m.print("recv:app:rx:hdr");

    if (m.pld_len_v()) {
        RecvRsp rresp(SERVAL_OK);
        uint16_t nonserial_len = m.pld_len_v() - rresp.serial_pld_len();
        if (nonserial_len > len) {
            err = ENOMEM;          // todo: support incoming msg truncation
            lerr("No memory error for RecvRsp");
            return SERVAL_SOCKET_ERROR;
        }
        info("reading recv rsp");
        rresp.reset_nonserial(buffer, nonserial_len);
        if (rresp.read_pld_from_stream_soc(cli.fd(), err) < 0) {
            lerr("Error reading RecvRsp from stream");
            return SERVAL_SOCKET_ERROR;
        }
        rresp.print("recv:app:rx:hdr");

        if (rresp.err().v) {
            err = rresp.err();
            lerr("RecvRsp has error %s", strerror_sv(err.v));
            return SERVAL_SOCKET_ERROR;
        }
        info("read recv response");

        if (len > rresp.nonserial_pld_len())
            len = rresp.nonserial_pld_len();
        memcpy(&src_service_id, &rresp.src_service_id(), 
               sizeof(src_service_id));
        src_ipaddr = rresp.src_ipaddr();
    } else {
        info("recv: expected to read data, found EOF on soc %s", 
             cli.s());
        len = 0;
        return 0;
    }
    info("returning length=%u", len);
    //SockIO::print("recv:app:data", (const unsigned char *)buffer, len);
    return 0;
}

int SVSockLib::close_sv(int soc, sv_err_t &err)
{
    int ret = 0;
    Cli &cli = get_cli(soc, err);

    if (cli.is_null()) {
        return ::close(soc);
    } else if (!cli.is_interrupted()) {
        // Must scope this lock, since we cannot unlock after we delete
        // the client
        SimpleLock slock(cli.get_lock());
    
        info("closing serval socket");
    
        cli.save_flags();
        cli.set_sync();
    
        if (query_serval_close(cli, err) < 0) {
            cli.restore_flags();
            lerr("query_serval_close failed");
            err = -1;
        }
    
        cli.restore_flags();
        //
        // Socket -> CLOSED or TIMEDWAIT
        //

        // unlock happens here.
    }
    delete_cli(&cli, err);
    return ret;
}

int SVSockLib::query_serval_close(Cli &cli, sv_err_t &err)
{
    CloseReq creq;

    if (creq.write_to_stream_soc(cli.fd(), err) < 0)
        return SERVAL_SOCKET_ERROR;
    creq.print("close:app:tx");

    Message m;
    if (m.read_hdr_from_stream_soc(cli.fd(), err) < 0)
        return SERVAL_SOCKET_ERROR;
   
    if (m.type() == Message::HAVE_DATA) {
        info("Got HaveData before CloseRsp; discarding");
        HaveData hdata;
        hdata.read_pld_from_stream_soc(cli.fd(), err);
        hdata.print("hdata:app:rx");
          
        // Expect a CloseRsp directly after HaveData
        CloseRsp crsp;
        if (crsp.read_from_stream_soc(cli.fd(), err) < 0)
            return SERVAL_SOCKET_ERROR;
        crsp.print("close:app:rx");
     
        if (crsp.err().v) {
            err = crsp.err();
            return SERVAL_SOCKET_ERROR;
        }
    } else if (m.type() == Message::CLOSE_RSP) {
        CloseRsp crsp;
        crsp.read_pld_from_stream_soc(cli.fd(), err);
        crsp.print("close:app:rx");
     
        if (crsp.err().v) {
            err = crsp.err();
            return SERVAL_SOCKET_ERROR;
        }
    } else {
        lerr("unexpected message after CloseReq");
        return SERVAL_SOCKET_ERROR;
    }
   
    return 0;
}

bool SVSockLib::is_valid(const struct sockaddr_sv &addr, bool local) const
{
    if (addr.sv_family == AF_SERVAL) {
        if ((local && !is_reserved(addr.sv_srvid)) ||
            (!local && !is_reserved(addr.sv_srvid)))
            return true;
        else {
            lerr("local !is_reserved");
        }
    } else {
        lerr("Bad address family %d", addr.sv_family);
    }
    return false;
}

bool SVSockLib::is_reserved(const sv_srvid_t& service_id) const
{
    /*
      if  (memcmp(&service_id, CONTROLLER_SID, sizeof(service_id)) == 0 || 
      memcmp(&service_id, SERVAL_SID, sizeof(service_id)) == 0 || 
      memcmp(&service_id, SERVAL_NULL_SID, sizeof(service_id)) == 0) {
      fprintf(stderr, "service ID %s not allowed", service_id_to_str(&service_id));
      return true;
      }
    */
    return false;
}
