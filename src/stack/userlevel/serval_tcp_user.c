/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include "serval_tcp.h"

/* tcp.c */

int sysctl_tcp_fin_timeout = TCP_FIN_TIMEOUT;

int sysctl_tcp_mem[3];
int sysctl_tcp_wmem[3];
int sysctl_tcp_rmem[3];

atomic_t tcp_memory_allocated;	/* Current allocated memory. */

/*
 * Pressure flag: try to collapse.
 * Technical note: it is used by multiple contexts non atomically.
 * All the __sk_mem_schedule() is of this nature: accounting
 * is strict, actions are advisory and have some latency.
 */
int tcp_memory_pressure;

/* tcp_input.c */

int sysctl_tcp_timestamps = 1;
int sysctl_tcp_window_scaling = 1;
int sysctl_tcp_sack = 1;
int sysctl_tcp_fack = 1;
int sysctl_tcp_reordering = TCP_FASTRETRANS_THRESH;
int sysctl_tcp_ecn = 2;
int sysctl_tcp_dsack = 1;
int sysctl_tcp_app_win = 31;
int sysctl_tcp_adv_win_scale = 2;

#define NR_FILE 1 /* TODO: set appropriate value */

int sysctl_tcp_stdurg = 0;
int sysctl_tcp_rfc1337 = 0;
int sysctl_tcp_max_orphans = NR_FILE;
int sysctl_tcp_frto = 2;
int sysctl_tcp_frto_response = 0;
int sysctl_tcp_nometrics_save = 0;

int sysctl_tcp_thin_dupack = 0;

int sysctl_tcp_abc = 0;

/* tcp_output.c */
int sysctl_tcp_retrans_collapse = 1;

/* This limits the percentage of the congestion window which we
 * will allow a single TSO frame to consume.  Building TSO frames
 * which are too large can cause TCP streams to be bursty.
 */
int sysctl_tcp_mtu_probing = 0;
int sysctl_tcp_base_mss = 512;

int sysctl_tcp_cookie_size = 0; /* TCP_COOKIE_MAX */

/* tcp_ipv4.c */

int sysctl_tcp_tw_reuse = 0;
int sysctl_tcp_low_latency = 0;
