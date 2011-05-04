/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include "serval_tcp.h"

/* tcp.c */

int sysctl_tcp_mem[3];
int sysctl_tcp_wmem[3];
int sysctl_tcp_rmem[3];

/* tcp_input.c */

int sysctl_serval_tcp_timestamps = 1;
int sysctl_serval_tcp_sack = 1;
int sysctl_serval_tcp_fack = 1;
int sysctl_serval_tcp_reordering = TCP_FASTRETRANS_THRESH;
int sysctl_serval_tcp_ecn = 2;
int sysctl_serval_tcp_dsack = 1;
int sysctl_serval_tcp_app_win = 31;

#define NR_FILE 1 /* TODO: set appropriate value */

int sysctl_serval_tcp_stdurg = 0;
int sysctl_serval_tcp_rfc1337 = 0;
int sysctl_serval_tcp_max_orphans = NR_FILE;
int sysctl_serval_tcp_frto = 2;
int sysctl_serval_tcp_frto_response = 0;
int sysctl_serval_tcp_nometrics_save = 0;

int sysctl_serval_tcp_thin_dupack = 0;

int sysctl_serval_tcp_abc = 0;

/* tcp_output.c */
int sysctl_serval_tcp_retrans_collapse = 1;

/* This limits the percentage of the congestion window which we
 * will allow a single TSO frame to consume.  Building TSO frames
 * which are too large can cause TCP streams to be bursty.
 */
int sysctl_serval_tcp_mtu_probing = 0;
int sysctl_serval_tcp_base_mss = 512;

int sysctl_serval_tcp_cookie_size = 0; /* TCP_COOKIE_MAX */

/* tcp_ipv4.c */

int sysctl_serval_tcp_tw_reuse = 0;

int tcp_memory_pressure;

void tcp_enter_memory_pressure(struct sock *sk)
{
	if (!tcp_memory_pressure) {
		//NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPMEMORYPRESSURES);
		tcp_memory_pressure = 1;
	}
}

void serval_tcp_init(void)
{        
        unsigned long limit;
        int max_share;
        
        limit = 128UL;
	limit = min(limit, INT_MAX * 4UL / 3 / 2);
	sysctl_tcp_mem[0] = limit / 4 * 3;
	sysctl_tcp_mem[1] = limit;
	sysctl_tcp_mem[2] = sysctl_tcp_mem[0] * 2;

	/* Set per-socket limits to no more than 1/128 the pressure threshold */
	limit = ((unsigned long)sysctl_tcp_mem[1]) << (PAGE_SHIFT - 7);
	max_share = min(4UL*1024*1024, limit);

	sysctl_tcp_wmem[0] = SK_MEM_QUANTUM;
	sysctl_tcp_wmem[1] = 16*1024;
	sysctl_tcp_wmem[2] = max(64*1024, max_share);
        
	sysctl_tcp_rmem[0] = SK_MEM_QUANTUM;
	sysctl_tcp_rmem[1] = 87380;
	sysctl_tcp_rmem[2] = max(87380, max_share);
}
