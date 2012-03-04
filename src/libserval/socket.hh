/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef SERVAL_SOCKET_HH
#define SERVAL_SOCKET_HH

#include <libserval/serval.h>
#include <serval/list.h>

#include "message.hh"
#include "bind.hh"
#include "connect.hh"
#include "listen.hh"
#include "accept.hh"
#include "send.hh"
#include "recv.hh"
#include "close.hh"
#include "cli.hh"
#include "select.hh"

#define SERVAL_SOCKET_ERROR -2
#define MAX_MSG_SIZE 1500

/* TODO
 * As it stands, the user space serval socket library does NOT support full duplex
 * operation (concurrent send/receive), since all operations traverse the same
 * unix domain socket and must be serialized: send cli req/recv cli resp. To properly
 * interleave send_sv/recv_sv requests, we probably need to add a cli response
 * demultiplexing facility
 */
class SVSockLib {
public:
    SVSockLib(int serval_id = 0);
    ~SVSockLib();

    static const char *SERVAL_TCP_PATH;
    static const char *SERVAL_UDP_PATH;
    static const sv_srvid_t CONTROLLER_SERVICE_ID;
  
    int socket_sv(int domain, int type, int protocol, sv_err_t &err);
    int bind_sv(int soc, const struct sockaddr *address, 
                socklen_t address_len, sv_err_t &err);
    int connect_sv(int soc, const struct sockaddr *addr, socklen_t addr_len,
                   sv_err_t &err);
    int listen_sv(int soc, int backlog, sv_err_t &err);
    int listen_sv(int soc, const struct sockaddr *addr,
                  socklen_t address_len,
                  int backlog, sv_err_t &err);
    int accept_sv(int soc, struct sockaddr *addr, socklen_t *addr_len,
                  sv_err_t &err);
    ssize_t send_sv(int socket, const void *buffer, size_t length, int flags,
                    sv_err_t &err);
    ssize_t recv_sv(int socket, void *buffer, size_t length, int flags, 
                    sv_err_t &err);
    ssize_t sendmsg_sv(int socket, const struct msghdr *message, int flags,
                       sv_err_t &err);
    ssize_t recvmsg_sv(int socket, struct msghdr *message, int flags,
                       sv_err_t &err);

    int close_sv(int soc, sv_err_t &err);
  
    ssize_t sendto_sv(int socket, const void *buffer, size_t length, int flags,
                      const struct sockaddr *dest_addr, socklen_t dest_len,
                      sv_err_t &err);
    ssize_t recvfrom_sv(int socket, void *buffer, size_t length, int flags,
                        struct sockaddr *address, socklen_t *address_len,
                        sv_err_t &err);

    int getsockopt_sv(int soc, int level, int option_name, 
                      void *option_value, socklen_t *option_len,
                      sv_err_t &err);
   
    static Cli null_cli;
    static const unsigned int SEND_BUFSIZE_LEN = 1024 * 1024;
    static const unsigned int RCV_BUFSIZE_LEN = 1024 * 1024;

private:
    Cli & get_cli(int soc, sv_err_t &err);
    int create_cli(sv_proto_t proto, int &soc, sv_err_t &err);
    int delete_cli(Cli *cli, sv_err_t &err);
  
    bool is_valid(const struct sockaddr_sv &addr, 
                  bool is_valid) const;
    bool is_reserved(const sv_srvid_t& service_id) const;
    bool is_non_blocking(int soc) const;

    void print(const char *label, const unsigned char *buf, int buflen);
    int basic_checks(int soc, const struct sockaddr *addr, 
                     socklen_t addr_len, bool check_local,
                     sv_err_t &err);
  
    int check_state_for_bind(const Cli &cli, sv_err_t &err) const;
    int check_state_for_connect(const Cli &cli, sv_err_t &err) const;
    int check_state_for_listen(const Cli &cli, sv_err_t &err) const;
    int check_state_for_accept(const Cli &cli, sv_err_t &err) const;
    int check_state_for_send(const Cli &cli, sv_err_t &err) const;
    int check_state_for_sendto(const Cli &cli, sv_err_t &err) const;
    int check_state_for_recv(const Cli &cli, sv_err_t &err) const;
    int check_state_for_recvfrom(const Cli &cli, sv_err_t &err) const;
  
    int query_serval_bind(const struct sockaddr_sv *sv_addr, 
                          Cli &cli, sv_err_t &err);
    int query_serval_connect(const struct sockaddr_sv *sv_addr, 
                             bool nb, Cli &cli, sv_err_t &err);
    int query_serval_soerror(Cli &cli, sv_err_t &err);
    int query_serval_listen(int backlog, Cli &cli, sv_err_t &err);
    int query_serval_listen(int backlog, const sv_srvid_t& local_service_id, 
                            Cli &cli, sv_err_t &err);
    int query_serval_accept1(bool nb, Cli &cli, AcceptRsp &aresp,
                             sv_err_t &err);
    int query_serval_accept2(bool nb, Cli &cli, const AcceptRsp &aresp,
                             sv_err_t &err);
    int query_serval_send(bool nb, const void *buffer, size_t length, int flags,
                          Cli &cli, sv_err_t &err);
    int query_serval_sendto(const sv_srvid_t& dst_service_id, uint32_t ipaddr,
                            const void *buffer, size_t length, int flags,
                            Cli &cli, sv_err_t &err);
    int query_serval_recv(bool nb, unsigned char *buffer, size_t &len, int flags,
                          sv_srvid_t &src_service_id, uint32_t& src_ipaddr,
                          Cli &cli, sv_err_t &err);
    int query_serval_close(Cli &cli, sv_err_t &err);
  
    struct sockaddr_un _tcp_srv;
    struct sockaddr_un _udp_srv;
    struct list_head _cli_list;
    static uint32_t _serval_id;
};

#endif
