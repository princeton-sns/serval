/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/* 
   Copyright (c) 2010 The Trustees of Princeton University (Trustees)

   Permission is hereby granted, free of charge, to any person obtaining a
   copy of this software and/or hardware specification (the “Work”) to deal
   in the Work without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or
   sell copies of the Work, and to permit persons to whom the Work is
   furnished to do so, subject to the following conditions: The above
   copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Work.
   
   THE WORK IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
   THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
   OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
   ARISING FROM, OUT OF OR IN CONNECTION WITH THE WORK OR THE USE OR OTHER
   DEALINGS IN THE WORK.
*/
#include <sys/time.h>
#include <assert.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <netinet/serval.h>
#include <libserval/serval.h>
#include "common.h"

static const char *progname = "foo";
static unsigned short DEFAULT_LISTEN_SID = 16385;
static struct service_id listen_srvid;
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

static int check_migration(int sock, size_t offset)
{
        int ret = 0; // assume error
        /*
        uint32_t network_offset = htonl(offset);

        switch (errno) {

        case EFRESYNCPROG:
                printf("resync after failover in progress\n");
                break;
        case EFRESYNCFAIL:
                printf("resync after failover failed\n");
                break;
        case ENEWINSTANCE:
                printf("Sending data offset %zu to server\n", offset);
            
                ret = send_sv(sock, &network_offset, sizeof(network_offset), 0);

                if (ret < 0) {
                        fprintf(stderr, "cannot send initial offset to server: %s\n", 
                                strerror_sv(errno));
                        ret = -1;
                } else {
                        printf("Sent offset %zu to server\n", offset);
                        ret = 1; // Migration happened
                }
                break;
                
        default:
                break;
        }
        */
        return ret;
}

static int recv_file(int sock, const char *filepath, int handle_migration,
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

        if (handle_migration) {
                uint32_t offset = 0;
                printf("Sending data offset %u to server\n", offset);
                ret = send_sv(sock, &offset, sizeof(offset), 0);

                if (ret < 0) {
                        fprintf(stderr, 
                                "cannot send initial offset to server: %s\n", 
                                strerror_sv(errno));
                        return EXIT_FAILURE;
                }
        }
        gettimeofday(&start_time, NULL);

        printf("Writing data to %s\n", filepath);
    
        while (!should_exit) {
                n = recv_sv(sock, recvbuf, RECVBUF_SIZE, 0);
        
                if (n < 0) {
                        ret = check_migration(sock, total_bytes);
            
                        if (ret == 1) {
                                printf("\rRecovery after server failure.\n"
                                       "Read %zu bytes in session for a total of %zu.\n"
                                       "Got error: %s.\n", 
                                       total_bytes_session, total_bytes, 
                                       strerror_sv(errno));
                                total_bytes_session = 0;
                                continue;
                        } 
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
                       diff_time.tv_sec, diff_time.tv_usec);
        }
        fprintf(stdout, "Read %zu bytes total\n", total_bytes);
        fprintf(stdout, "Wrote to file %s\n", filepath);
        fprintf(stdout, "Closing sockets...\n");
 
        return ret;
}

static int client(const char *filepath, int handle_migration)
{
        int sock, ret = EXIT_FAILURE;
        struct sockaddr_sv cliaddr;
        struct sockaddr_sv srvaddr;
        unsigned char digest[SHA_DIGEST_LENGTH];

        memset(&cliaddr, 0, sizeof(cliaddr));
        cliaddr.sv_family = AF_SERVAL;
        cliaddr.sv_srvid.s_sid16[0] = htons(getpid());
  
        bzero(&srvaddr, sizeof(srvaddr));
        srvaddr.sv_family = AF_SERVAL;
        memcpy(&srvaddr.sv_srvid, &listen_srvid, sizeof(listen_srvid));
        /* srvaddr.sv_flags = SV_WANT_FAILOVER; */
  
        sock = socket_sv(AF_SERVAL, SOCK_STREAM, 0);
        set_reuse_ok(sock);

        ret = bind_sv(sock, (struct sockaddr *) &cliaddr, sizeof(cliaddr));
    
        if (ret < 0) {
                fprintf(stderr, "error client binding socket: %s\n", 
                        strerror_sv(errno));
                goto out;
        }
        
        ret = connect_sv(sock, (struct sockaddr *)&srvaddr, sizeof(srvaddr));
    
        if (ret < 0) {
                fprintf(stderr, "error client connecting to socket: %s\n",
                        strerror_sv(errno));
                goto out;
        }
        
        fprintf(stderr, "Connected to service id %s\n", 
                service_id_to_str(&srvaddr.sv_srvid));
        sleep(2);
    
        ret = recv_file(sock, filepath, handle_migration, digest);
        
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
        printf("Usage: %s [-hfm]\n", progname);
        printf("-h, --help              - Print this information.\n"
               "-f, --file FILE         - Read data from FILE.\n"
               "-m, --migration         - Handle migration.\n");
}

int
main(int argc, char **argv)
{
	struct sigaction action;
        char *filepath = NULL;
        int handle_migration = 0;

        listen_srvid.s_sid16[0] = htons(DEFAULT_LISTEN_SID);    

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
                } else if (strcmp("-h", argv[0]) == 0 || 
                           strcmp("--help", argv[0]) == 0) {
                        print_help();
                        return EXIT_SUCCESS;
                } else if (strcmp("-m", argv[0]) == 0 || 
                           strcmp("--migration", argv[0]) == 0) {
                        handle_migration = 1;
                }  else if (strcmp("-s", argv[0]) == 0 ||
                            strcmp("--serviceid", argv[0]) == 0) {
                        long v = strtol(argv[1], NULL, 10);
                        if (v > 65535 || v < 0) {
                                fprintf(stderr, "invalid service id %ld", v);
                                return EXIT_FAILURE;
                        } else  {
                                listen_srvid.s_sid16[0] = htons((short)v);
                                printf("listen service id: %s\n", 
                                       service_id_to_str(&listen_srvid));
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
    
        return client(filepath, handle_migration);
}
