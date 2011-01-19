/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
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
#include "migrate.hh"

#define SERVAL_SOCKET_ERROR -2

class SVSockLib {
public:
  SVSockLib(int scafd_id = 0);
  ~SVSockLib();

  static const char *DEFAULT_SF_CFG;
  static const char *SCAFD_TCP_PATH;
  static const char *SCAFD_UDP_PATH;
  static const sv_srvid_t CONTROLLER_OBJ_ID;
  
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
  // sko begin
  int migrate_sv(int soc, sv_err_t &err);
  // sko end
  
  static Cli null_cli;
  static const unsigned int SEND_BUFSIZE_LEN = 1024 * 1024;
  static const unsigned int RCV_BUFSIZE_LEN = 1024 * 1024;

private:
  Cli & get_cli(int soc, sv_err_t &err);
  int create_cli(sv_proto_t proto, int &soc, sv_err_t &err);
  int delete_cli(Cli *cli, sv_err_t &err);
  
  bool is_valid(const struct sockaddr_sv &addr, 
		bool is_valid) const;
  bool is_reserved(sv_srvid_t obj_id) const;
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
  
  int query_scafd_bind(const struct sockaddr_sv *sv_addr, 
		       const Cli &cli, sv_err_t &err);
  int query_scafd_connect(const struct sockaddr_sv *sv_addr, 
			  bool nb, Cli &cli, sv_err_t &err);
  int query_scafd_soerror(Cli &cli, sv_err_t &err);
  int query_scafd_listen(int backlog, const Cli &cli, sv_err_t &err);
  int query_scafd_listen(int backlog, sv_srvid_t local_obj_id, 
			 const Cli &cli, sv_err_t &err);
  int query_scafd_accept1(bool nb, const Cli &cli, AcceptRsp &aresp,
			  sv_err_t &err);
  int query_scafd_accept2(bool nb, const Cli &cli, const AcceptRsp &aresp,
			  sv_err_t &err);
  int query_scafd_send(bool nb, const void *buffer, size_t length, int flags,
		       Cli &cli, sv_err_t &err);
  int query_scafd_sendto(sv_srvid_t dst_obj_id, 
			 const void *buffer, size_t length, int flags,
			 Cli &cli, sv_err_t &err);
  int query_scafd_recv(bool nb, unsigned char *buffer, size_t &len, int flags,
		       sv_srvid_t &src_obj_id, Cli &cli, sv_err_t &err);
  int query_scafd_close(const Cli &cli, sv_err_t &err);
  int query_scafd_migrate(const Cli &cli, sv_err_t &err);
  
  struct sockaddr_un _tcp_srv;
  struct sockaddr_un _udp_srv;
  struct list_head _cli_list;
  static uint32_t _scafd_id;
};

#endif
