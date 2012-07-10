/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <sys/time.h>
#include <assert.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <netinet/serval.h>
#include <libserval/serval.h>
#include "common.h"

static const char *progname = "foo";
static unsigned short DEFAULT_SERVER_SID = 16385;
static struct service_id server_srvid;
static int should_exit = 0;
#define RECVBUF_SIZE (sizeof(long) * 1460)

static void signal_handler(int sig)
{
        printf("signal caught! exiting...\n");
        should_exit = 1;        
}

static int set_reuse_ok(int soc)
{
        int option = 1;
    
        if (setsockopt(soc, SOL_SOCKET, SO_REUSEADDR, 
                       &option, sizeof(option)) < 0) {
                fprintf(stderr, "proxy setsockopt error");
                return -1;
        }

        return 0;
}

static int recv_file(int sock, const char *filepath,
                     unsigned char digest[SHA_DIGEST_LENGTH])
{
        char recvbuf[RECVBUF_SIZE];
        ssize_t n;
        size_t total_bytes = 0, total_bytes_session = 0;    
        SHA_CTX ctx;
        int ret = EXIT_FAILURE;
        FILE *f;
        struct timeval start_time, end_time, diff_time = { 0, 0 };

        if (!filepath)
                filepath = "/tmp/data";

        f = fopen(filepath, "w");

        if (!f) {
                fprintf(stderr, "Could not open file %s for writing\n", 
                        filepath);
                return EXIT_FAILURE;
        }

        SHA1_Init(&ctx);

        gettimeofday(&start_time, NULL);

        printf("Writing data to %s\n", filepath);
    
        while (!should_exit) {
                n = recv_sv(sock, recvbuf, RECVBUF_SIZE, 0);
        
                /* printf("received %zd bytes\n", n); */

                if (n < 0) {
                        fprintf(stderr, "\rerror receiving data: %s\n",
                                strerror(errno));
                        ret = EXIT_FAILURE;
                        break;
                }
        
                if (n == 0) {
                        fprintf(stdout, "\rconnection closed\n");
                        ret = EXIT_SUCCESS;
                        should_exit = 1;
                        SHA1_Final(digest, &ctx);
                        gettimeofday(&end_time, NULL);
                        break;
                }
        
                total_bytes += n;
                total_bytes_session += n;
        
                print_tick();

                //printf("Received %zd bytes data, total=%zu\n", n, total_bytes);
                //long pos = ftell(f);
                size_t nmem = fwrite(recvbuf, n, 1, f);
        
                SHA1_Update(&ctx, recvbuf, n);
        
                if (nmem != 1) {
                        fprintf(stderr, "\rError writing to file\n");
                        break;
                }
                //printf("Wrote %ld bytes data to %s\n", ftell(f) - pos, filepath);
        }
    
        if (ret == EXIT_SUCCESS) {
                timeval_sub(&diff_time, &end_time, &start_time);
                printf("Finished successfully in %ld.%06ld seconds\n", 
                       diff_time.tv_sec, (long)diff_time.tv_usec);
        }
        fprintf(stdout, "Read %zu bytes total\n", total_bytes);
        fprintf(stdout, "Wrote to file %s\n", filepath);
        fprintf(stdout, "Closing sockets...\n");
 
        return ret;
}

static int client(const char *filepath, 
                  struct in_addr *srv_inetaddr, int port)
{
        int sock, ret = EXIT_FAILURE;
        union {
                struct sockaddr_sv serval;
                struct sockaddr_in inet;
                struct sockaddr saddr;
        } cliaddr, srvaddr;
        socklen_t addrlen = 0;
        unsigned char digest[SHA_DIGEST_LENGTH];
        unsigned short srv_inetport = (unsigned short)port;
        int family = AF_SERVAL;

        memset(&cliaddr, 0, sizeof(cliaddr));
        memset(&srvaddr, 0, sizeof(srvaddr));

        if (srv_inetaddr) {
                family = AF_INET;
                cliaddr.inet.sin_family = family;
                cliaddr.inet.sin_port = htons(6767);
                srvaddr.inet.sin_family = family;
                srvaddr.inet.sin_port = htons(srv_inetport);
                memcpy(&srvaddr.inet.sin_addr, srv_inetaddr, 
                       sizeof(*srv_inetaddr));
                addrlen = sizeof(cliaddr.inet);
        } else {
                cliaddr.serval.sv_family = family;
                cliaddr.serval.sv_srvid.s_sid32[0] = htonl(getpid());
                srvaddr.serval.sv_family = AF_SERVAL;
                memcpy(&srvaddr.serval.sv_srvid, 
                       &server_srvid, sizeof(server_srvid));
                addrlen = sizeof(cliaddr.serval);
                /* srvaddr.sv_flags = SV_WANT_FAILOVER; */
        }
        
        sock = socket_sv(family, SOCK_STREAM, 0);
        
        set_reuse_ok(sock);
        
        if (family == AF_SERVAL) {
                ret = bind_sv(sock, &cliaddr.saddr, addrlen);
                
                if (ret < 0) {
                        fprintf(stderr, "error client binding socket: %s\n", 
                                strerror_sv(errno));
                        goto out;
                }
        }
        
        if (family == AF_INET) {
                char buf[18];
                printf("Connecting to service %s:%u\n",
                       inet_ntop(family, srv_inetaddr, buf, 18), 
                       srv_inetport);
        } else {
                printf("Connecting to service id %s\n", 
                       service_id_to_str(&srvaddr.serval.sv_srvid));
        }
        ret = connect_sv(sock, &srvaddr.saddr, addrlen);
    
        if (ret < 0) {
                fprintf(stderr, "ERROR connecting: %s\n",
                        strerror_sv(errno));
                goto out;
        }
#if defined(SERVAL_NATIVE)
        {
                struct {
                        struct sockaddr_sv sv;
                        struct sockaddr_in in;
                } saddr;
                socklen_t addrlen = sizeof(saddr.in);
                char ipaddr[18];

                memset(&saddr, 0, sizeof(saddr));
                
                ret = getsockname(sock, (struct sockaddr *)&saddr, &addrlen);

                if (ret == -1) {
                        fprintf(stderr, "Could not get sock name : %s\n",
                                strerror(errno));
                } else {
                        printf("sock name is %s @ %s\n",
                               service_id_to_str(&saddr.sv.sv_srvid),
                               inet_ntop(AF_INET, &saddr.in.sin_addr, 
                                         ipaddr, 18));
                }

                memset(&saddr, 0, sizeof(saddr));
                
                ret = getpeername(sock, (struct sockaddr *)&saddr, &addrlen);

                if (ret == -1) {
                        fprintf(stderr, "Could not get peer name : %s\n",
                                strerror(errno));
                } else {
                        printf("peer name is %s @ %s\n",
                               service_id_to_str(&saddr.sv.sv_srvid),
                               inet_ntop(AF_INET, &saddr.in.sin_addr, 
                                         ipaddr, 18));
                }
        } 
#endif
        printf("Connected successfully!\n");
        
        ret = recv_file(sock, filepath, digest);
        
        if (ret == EXIT_SUCCESS) {
                printf("SHA1 digest is [%s]\n", digest_to_str(digest));
        } else {
                printf("Receive failed\n");
        }
out:
        fprintf(stderr, "Closing socket...\n");
        close_sv(sock);

        return ret;
}

static void print_help()
{
        printf("Usage: %s [OPTIONS]\n", progname);
        printf("-h, --help                        - Print this information.\n"
               "-f, --file FILE                   - Write data to FILE.\n"
               "-s, --serviceid SERVICE_ID        - ServiceID to connect to.\n"
               "-i, --inet IP_ADDR                - Use AF_INET\n");
}

static int parse_inet_str(char *inet_str, 
                          struct in_addr *ip, int *port)
{
        if (!ip)
                return -1;
        
        if (port) {
                char *p;
                char *save;
                /* Find out whether there is a port number */
                p = strtok_r(inet_str, ":", &save);
                
                printf("parsing %s p=%c\n", inet_str, *p);

                if (!p)
                        goto out;

                p = strtok_r(NULL, ":", &save);
                
                if (p != NULL && p != inet_str)
                        *port = atoi(p);
        }
 out:
        return inet_pton(AF_INET, inet_str, ip) == 1;
}

int
main(int argc, char **argv)
{
	struct sigaction action;
        char *filepath = NULL;
        struct in_addr srv_inetaddr;
        int port = DEFAULT_SERVER_SID;
        int family = AF_SERVAL;

        server_srvid.s_sid32[0] = htonl(DEFAULT_SERVER_SID);    

	memset (&action, 0, sizeof(struct sigaction));
        action.sa_handler = signal_handler;
    
	/* This server should shut down on these signals. */
        sigaction(SIGTERM, &action, 0);
        sigaction(SIGHUP, &action, 0);
        sigaction(SIGINT, &action, 0);

        progname = argv[0];
        argc--;
        argv++;
    
        while (argc && argv) {
                if (strcmp("-f", argv[0]) == 0 || 
                    strcmp("--file", argv[0]) == 0) {
                        if (argv[1]) {
                                filepath = argv[1];
                                argc--;
                                argv++;
                        }
                } else if (strcmp("-i", argv[0]) == 0 || 
                           strcmp("--inet", argv[0]) == 0) {
                        if (argv[1] && 
                            parse_inet_str(argv[1], 
                                           &srv_inetaddr, &port) == 1) {
                                family = AF_INET;
                                argc--;
                                argv++;
                        }
                } else if (strcmp("-h", argv[0]) == 0 || 
                           strcmp("--help", argv[0]) == 0) {
                        print_help();
                        return EXIT_SUCCESS;
                } else if (strcmp("-s", argv[0]) == 0 ||
                            strcmp("--serviceid", argv[0]) == 0) {
                        char *endptr = NULL;
                        unsigned long sid = strtoul(argv[1], &endptr, 10);

                        if (*endptr != '\0') {
                                fprintf(stderr, "invalid service id %s", 
                                        argv[1]);
                                return EXIT_FAILURE;
                        } else  {
                                server_srvid.s_sid32[0] = htonl(sid);
                        }
                        argc--;
                        argv++;
                } else {
                        print_help();
                        return EXIT_FAILURE;
                }
                argc--;
                argv++;
        }
    
        return client(filepath, family == AF_INET ? &srv_inetaddr : NULL, port);
}
