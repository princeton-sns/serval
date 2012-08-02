/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <openssl/sha.h>
#include <libserval/serval.h>
#include <netinet/serval.h>
#include "common.h"

static const char *progname;
static unsigned short DEFAULT_LISTEN_SID = 16385;
static struct service_id listen_srvid;
static int should_exit = 0;
#define SENDBUF_SIZE (sizeof(long) * 1460)

static void signal_handler(int sig)
{
        switch (sig) {
        case SIGHUP:
                printf("Doing failover\n");
                break;
                // kill -TERM requests graceful termination (may hang if
                // in syscall in which case a subsequent SIGINT is reqd.
        case SIGTERM:
                printf("signal term caught! exiting...\n");
                should_exit = 1; 
                break;
                // ctrl-c does abnormal termination
        case SIGINT:
                printf("abnormal termination! exiting..\n");
                signal(sig, SIG_DFL);
                raise(sig);
                break;
        default:
                printf("unknown signal");
                signal(sig, SIG_DFL);
                raise(sig);
                break;
        }
}

static int set_reuse_ok(int soc)
{
        int option = 1;
        if (setsockopt(soc, SOL_SOCKET, SO_REUSEADDR, &option, 
                       sizeof(option)) < 0) {
                fprintf(stderr, "proxy setsockopt error");
                return -1;
        }
        return 0;
}

static int send_file(int sock, const char *filepath,
                     long file_offset,
                     unsigned char digest[SHA_DIGEST_LENGTH])
{
        int ret = EXIT_FAILURE;
        ssize_t n = 0;
        static size_t total_bytes = 0;
        size_t total_bytes_session = 0, nread = 0;
        char sendbuf[SENDBUF_SIZE];
        int stop_sending = 0;
        SHA_CTX ctx;
        FILE *f;

        if (!filepath)
                filepath = "/tmp/data";

        f = fopen(filepath, "r");
    
        if (!f) {
                fprintf(stderr, "cannot open file %s : %s\n", 
                        filepath, strerror(errno));
                return EXIT_FAILURE;
        }

        if (file_offset > 0) {
                if (fseek(f, file_offset, SEEK_SET) == -1) {
                        fprintf(stderr, "fseek() failed, bad offset %ld\n", 
                                file_offset);
                        fclose(f);
                        return EXIT_FAILURE;
                }
        }

        SHA1_Init(&ctx);

        printf("sending file %s, starting at offset %ld\n", 
               filepath, file_offset);

        while (!stop_sending) {
                long pos = ftell(f);
                size_t count = fread(sendbuf, SENDBUF_SIZE, 1, f);
        
                nread = ftell(f) - pos;
        
                if (count != 1) {
            
                        if (feof(f) != 0) {
                                if (nread == 0) {
                                        printf("\rEOF reached, file successfully sent\n");
                                        ret = EXIT_SUCCESS;
                                        break;
                                }
                        } else if (ferror(f) != 0) {
                                fprintf(stderr, "\rError reading file\n");
                                break;
                        } else {
                                fprintf(stderr, "\rUnknown error when reading file\n");
                                break;
                        }
                }
        
                //printf("Read %zu bytes from file %s\n", nread, filepath);

                count = 0;

                SHA1_Update(&ctx, sendbuf, nread);

                while (!stop_sending && count < nread) {

                        n = send_sv(sock, sendbuf + count, nread - count, 0);

                        if (n < 0) {
                                if (errno == EAGAIN) {
                                        fprintf(stderr, 
                                                "\rEAGAIN, continuing..\n");
                                        continue;
                                } 
                
                                fprintf(stderr, "\rerror sending data: %s\n",
                                        strerror_sv(errno));
                                stop_sending = 1;
                                break;
                        }
            
                        /* 
                           printf("Sent %zd bytes, total bytes=%zu\n", 
                           n, total_bytes_session);
                        */
                        print_tick();

                        count =+ n;
                        total_bytes += n;
                        total_bytes_session += n;
                }
        }
    
        SHA1_Final(digest, &ctx);

        printf("Sent total %zu bytes, session %zu bytes\n", 
               total_bytes, total_bytes_session);
        
        fclose(f);
    
        return ret;
}

static int send_memory_buffer(int sock, size_t bytes_to_send,
                              unsigned char digest[SHA_DIGEST_LENGTH])
{
        char sendbuf[SENDBUF_SIZE];
        ssize_t n = 0;
        size_t total_bytes = 0;
        SHA_CTX ctx;
        int ret = EXIT_FAILURE;

        SHA1_Init(&ctx);

        printf("Sending %zu bytes of randomized data\n", bytes_to_send);

        while (!should_exit) {
                size_t count = 0, i;
                size_t bufsize = 
                        bytes_to_send < SENDBUF_SIZE ? 
                        bytes_to_send : SENDBUF_SIZE;

                if (bytes_to_send == 0) {
                        ret = EXIT_SUCCESS;
                        break;
                }
                for (i = 0; i < bufsize; i += sizeof(long)) {
                        long *l = (long *)&sendbuf[i];
                        *l = random();
                }
        
                SHA1_Update(&ctx, sendbuf, bufsize);

                while (!should_exit && count < bufsize) {
            
                        n = send_sv(sock, sendbuf + count, 
                                    bufsize - count, 0);
            
                        if (n < 0) {
                                if (errno == EAGAIN) {
                                        fprintf(stderr, 
                                                "client: EAGAIN\n");
                                        continue;
                                } else if (errno == EPIPE) {
                                        printf("client closed abruptly\n");
                                        should_exit = 1;
                                        ret = EXIT_SUCCESS;
                                        break;
                                }
                
                                fprintf(stderr, "client: error: %d - %s\n",
                                        errno, strerror_sv(errno));

                                should_exit = 1;
                                break;
                        }
             
                        count += n;
                        total_bytes += n;
                        /*
                        printf("Sent %zd bytes, total %zu bytes\n", 
                               n, total_bytes);
                        */
                }
                bytes_to_send -= count;
        }

        SHA1_Final(digest, &ctx);
    
        printf("Sent total %zu bytes\n", total_bytes);

        return ret;
}

static int server(const char *filepath, 
                  size_t send_memory_buffer_size, 
                  int family)
{
        int sock;
        int backlog = 8;    
        union {
                 struct sockaddr_sv serval;
                struct sockaddr_in inet;
                struct sockaddr saddr;
        } cliaddr, srvaddr;
        socklen_t addrlen = 0;
        unsigned char digest[SHA_DIGEST_LENGTH];
        int ret = EXIT_FAILURE;
        unsigned short srv_inetport = 49254;

        memset(&cliaddr, 0, sizeof(cliaddr));
        memset(&srvaddr, 0, sizeof(srvaddr));

        if (family == AF_INET) {
                cliaddr.inet.sin_family = family;
                srvaddr.inet.sin_family = family;
                srvaddr.inet.sin_addr.s_addr = INADDR_ANY;
                srvaddr.inet.sin_port = htons(srv_inetport);
                addrlen = sizeof(srvaddr.inet);
        } else {
                cliaddr.serval.sv_family = family;
                srvaddr.serval.sv_family = AF_SERVAL;
                memcpy(&srvaddr.serval.sv_srvid,
                       &listen_srvid, sizeof(listen_srvid));
                addrlen = sizeof(cliaddr.serval);
        }
      
        sock = socket_sv(family, SOCK_STREAM, 0);

        if (sock < 0) {
                fprintf(stderr, "error creating AF_SERVAL socket: %s\n", 
                        strerror(errno));
                return EXIT_FAILURE;
        }
  
        set_reuse_ok(sock);
        
        ret = bind_sv(sock, &srvaddr.saddr, addrlen);
  
        if (ret < 0) {
                fprintf(stderr, "error binding socket: %s\n", strerror(errno));
                close_sv(sock);
                return ret;
        }
        
        if (family == AF_INET) {
                printf("server: bound to port %u\n",
                       srv_inetport);
        } else {
                printf("server: bound to service id %s\n", 
                       service_id_to_str(&listen_srvid));
        }
        
        ret = listen_sv(sock, backlog);

        if (ret < 0) {
                fprintf(stderr, "error setting listening socket: %s\n", 
                        strerror(errno));
                close_sv(sock);
                return ret;
        }
    
        while (!should_exit) {
                socklen_t l = addrlen;
                int client_sock;
                long offset = 0;

                printf("Waiting for new connections\n");
                
                client_sock = accept_sv(sock, &cliaddr.saddr, &l);
        
                if (client_sock < 0) {
                        fprintf(stderr, "error accepting new conn: %s\n", 
                                strerror_sv(errno));
                        continue;
                }
                
                if (family == AF_INET) {
                        char buf[18];
                        printf("Connect request from %s:%u\n",
                               inet_ntop(family, 
                                         &cliaddr.inet.sin_addr, buf, 18),
                               ntohs(cliaddr.inet.sin_port));
                } else {
                        printf("Connect req from service id %s (sock = %d)\n",
                               service_id_to_str(&cliaddr.serval.sv_srvid), 
                               client_sock);
                }
                
                if (send_memory_buffer_size > 0)
                        ret = send_memory_buffer(client_sock, 
                                                 send_memory_buffer_size, 
                                                 digest);
                else
                        ret = send_file(client_sock, filepath, offset, 
                                        digest);

                if (ret == EXIT_SUCCESS) {
                        printf("Send successful\n");
                        printf("SHA1 digest is [%s]\n", digest_to_str(digest));
                } else if (ret < 0) {
                        fprintf(stderr, "Failed data transfer to client\n");
                        //should_exit = 1;
                }
                close_sv(client_sock);
        } 

        close_sv(sock);

        return ret;
}

static void print_help()
{
        printf("Usage: %s [OPTIONS]\n", progname);
        printf("-h, --help                        - Print this information.\n"
               "-f, --file FILE                   - Read data from FILE.\n"
               "-b, --buffer BYTES                - Generate BYTES bytes random data using a memory buffer.\n"
               "-e, --seed SEED                   - Set PRNG seed to SEED.\n"
               "-s, --serviceid SERVICE_ID        - Set the serviceID to listen on\n"
               "-i, --inet                        - Use AF_INET\n");
}

int
main(int argc, char **argv)
{
        struct sigaction action;
        size_t send_memory_buffer = 10000000; /* Send 10 Mb by default */
        char *filepath = NULL;
        unsigned int seed = 2;
        int family = AF_SERVAL;

        listen_srvid.s_sid32[0] = htonl(DEFAULT_LISTEN_SID);

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
                                send_memory_buffer = 0;
                                argc--;
                                argv++;
                        }
                } else if (strcmp("-i", argv[0]) == 0 || 
                           strcmp("--inet", argv[0]) == 0) {
                        family = AF_INET;
                } else if (strcmp("-b", argv[0]) == 0 || 
                           strcmp("--buffer", argv[0]) == 0) {
                        if (argv[1]) {
                                char *endptr = NULL;
                                send_memory_buffer = strtoul(argv[1], 
                                                             &endptr, 10);

                                if (*endptr != '\0') {
                                        // failure
                                        send_memory_buffer = 0;
                                } else {
                                        argc--;
                                        argv++;
                                }
                        }
                } else if (strcmp("-e", argv[0]) == 0 || 
                           strcmp("--seed", argv[0]) == 0) {
                        if (argv[1]) {
                                char *endptr = NULL;
                                seed = (unsigned int)strtoul(argv[1], 
                                                             &endptr, 10);

                                if (*endptr != '\0') {
                                        // failure
                                        seed = 2;
                                } else {
                                        printf("Seed set to %u\n", seed);
                                }
                                argc--;
                                argv++;
                        }
                } else if (strcmp("-s", argv[0]) == 0 || 
                           strcmp("--serviceid", argv[0]) == 0) {
                        if (argv[1]) {
                                char *endptr = NULL;
                                unsigned long sid;

                                sid = strtoul(argv[1], &endptr, 10);
                                
                                if (*endptr != '\0') {
                                        // conversion failure
                                } else {
                                        listen_srvid.s_sid32[0] = htonl(sid);
                                }
                                argc--;
                                argv++;
                        } 
                } else if (strcmp("-h", argv[0]) == 0 || 
                           strcmp("--help", argv[0]) == 0) {
                        print_help();
                        return EXIT_SUCCESS;
                } else {
                        print_help();
                        return EXIT_FAILURE;
                }
                argc--;
                argv++;
        }
    
        srandom(seed);
        
        return server(filepath, send_memory_buffer, family);
}
