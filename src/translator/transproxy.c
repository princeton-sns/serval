/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/serval.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sys/select.h>
#include <signal.h>
#include <netdb.h>
#include <linux/netfilter_ipv4.h>
#include "log.h"

static unsigned int client_num = 0;

struct client {
        int family;
        unsigned int id;
        struct sockaddr_in saddr;
        pthread_t thr;
        int inet_sock;
        int serval_sock;
        int pipefd[2];
        int should_exit;
};

static unsigned short translator_port = 8080;
static const char *server_ip = "192.168.56.101";
static LOG_DEFINE(logh);

static ssize_t forward_data(int from, int to, int pipefd[2])
{
        ssize_t rlen, wlen = 0;

         rlen = splice(from, NULL, pipefd[1], NULL, 
                       INT_MAX, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        
        if (rlen == -1) {
                fprintf(stderr, "splice1: %s\n",
                        strerror(errno));
                return rlen;
        } else if (rlen == 0) {
                printf("Other end closed\n");
        }
        
        /* printf("splice1 %zd bytes\n", rlen); */
        
        while (rlen) {
                ssize_t w = splice(pipefd[0], NULL, to, NULL,
                                   rlen, SPLICE_F_MOVE | SPLICE_F_MORE);
                
                if (w == -1) {
                        fprintf(stderr, "splice2: %s\n",
                                strerror(errno));
                        break;
                }
                wlen += w;
                rlen -= w;
        }
        
        /* printf("splice2 %zd bytes\n", wlen); */
        
        return wlen;
}

static ssize_t forward_buf(int to, char *buf, int buf_len)
{
        ssize_t rlen = buf_len, wlen = 0;
        while (rlen) {
                ssize_t w = write(to, buf, rlen);
                if (w < 0) {
                        fprintf(stderr, "write: %s\n", strerror(errno));
                        break;
                }
                wlen += w;
                rlen -= w;
        }
        
        return wlen;
}

static ssize_t legacy_to_serval(struct client *c)
{
        struct sockaddr_in myaddr;
        socklen_t mylen = sizeof(myaddr);
        char *saveptr;
        char *end_req;
        char *method, *path, *proto;
        char buf[8192] = "\0";
        char result[8192] = "\0";
        char dest[16] = "\0";
        int r = read(c->inet_sock, buf, 8191);
        int new_size;

        /* parse the request line, the only part that needs to change */
        end_req = strstr(buf, "\r\n");
        method = strtok_r(buf, " ", &saveptr);
        path = strtok_r(NULL, " ", &saveptr);
        proto = strtok_r(NULL, "\r\n", &saveptr);

        /* get original address before redirection so proxy knows */
        getsockopt(c->inet_sock, SOL_IP, SO_ORIGINAL_DST, &myaddr, &mylen);

        if (end_req) {
                inet_ntop(AF_INET, &myaddr.sin_addr, dest, 16);

                sprintf(result, "%s http://%s%s %s\r\n%s", method, dest, path, 
                        proto, (end_req + 2));
                printf("%s", result);
                /* 7 for 'http://' and the added length of the ip addr */
                new_size = r + 7 + strlen(dest);
                return forward_buf(c->serval_sock, result, new_size);
        }

        return -1;
}

static ssize_t serval_to_legacy(struct client *c)
{
        return forward_data(c->serval_sock, c->inet_sock, c->pipefd);
}

struct client *client_create(int inet_sock, int family, 
                             struct sockaddr *sa, socklen_t salen)
{
        struct client *c;
        int ret;

        c = malloc(sizeof(*c));

        if (c) {
                memset(c, 0, sizeof(*c));
                c->id = client_num++;
                c->inet_sock = inet_sock;
        }        
        c->family = family;

        ret = pipe(c->pipefd);

        if (ret == -1) {
                fprintf(stderr, "pipe: %s\n",
			strerror(errno));
                goto fail_pipe;
        }
        
        c->serval_sock = socket(family, SOCK_STREAM, 0);
        
	if (c->serval_sock == -1) {
		fprintf(stderr, "serval socket: %s\n",
			strerror(errno));
                goto fail_sock;
	}
        memcpy(&c->saddr, sa, salen);
out:        
        return c;
fail_sock:        
        close(c->pipefd[0]);
        close(c->pipefd[1]);
fail_pipe:
        free(c);
        c = NULL;
        goto out;
}

void client_free(struct client *c)
{
        close(c->serval_sock);
        close(c->inet_sock);
        close(c->pipefd[0]);
        close(c->pipefd[1]);
        free(c);
}

void *client_thread(void *arg)
{
        struct client *c = (struct client *)arg;
        union {
                struct sockaddr sa;
                struct sockaddr_sv sv;
                struct sockaddr_in in;
        } addr;
        socklen_t addrlen;
        int inet_port = 49254;
        char srcstr[18];
        int ret;

        memset(&addr, 0, sizeof(addr));
        
        if (c->family == AF_SERVAL) {
                addr.sv.sv_family = c->family;
                addr.sv.sv_srvid.s_sid32[0] = htonl(translator_port);
                addrlen = sizeof(addr.sv);
        } else {
                addr.in.sin_family = c->family;
                inet_pton(AF_INET, server_ip, &addr.in.sin_addr);
                addr.in.sin_port = htons(inet_port);
                addrlen = sizeof(addr.in);
        }
        
        inet_ntop(AF_INET, &c->saddr.sin_addr, 
                  srcstr, sizeof(srcstr));
        
        if (c->family == AF_SERVAL) {
                printf("client %u from %s connecting to service %s...\n",
                       c->id, srcstr, service_id_to_str(&addr.sv.sv_srvid));
        } else {
                printf("client %u from %s connecting to %s:%u...\n",
                       c->id, srcstr, server_ip, inet_port);
        }

        ret = connect(c->serval_sock, &addr.sa, addrlen);

        if (ret == -1) {
                fprintf(stderr, "connect failed: %s\n",
                        strerror(errno));
                client_free(c);
                return NULL;
        }

        printf("client %u connected successfully!\n", c->id);

        while (!c->should_exit) {
                fd_set fds;
                ssize_t bytes = 0;
                int maxfd = c->serval_sock > c->inet_sock ? 
                        c->serval_sock : c->inet_sock;

                FD_ZERO(&fds);
                FD_SET(c->inet_sock, &fds);
                FD_SET(c->serval_sock, &fds);
                
                ret = select(maxfd + 1, &fds, NULL, NULL, NULL);

                if (ret == -1) {
                        fprintf(stderr, "select: %s\n",
                                strerror(errno));
                        break;
                } else if (ret > 0) {
                        if (FD_ISSET(c->inet_sock, &fds)) {
                                bytes = legacy_to_serval(c);

                                if (bytes == 0) {
                                        break;
                                } else if (bytes < 0) {
                                        fprintf(stderr, "forwarding error\n");
                                        break;
                                } 
                        }

                        if (FD_ISSET(c->serval_sock, &fds)) {
                                bytes = serval_to_legacy(c);
                                
                                if (bytes == 0) {
                                        break;
                                } else if (bytes < 0) {
                                        fprintf(stderr, "forwarding error\n");
                                        break;
                                } 
                        }
                }
        }

        printf("client %u exits\n", c->id);

        client_free(c);

        return NULL;
}

static void signal_handler(int sig)
{
        printf("signal %u caught!\n", sig);
}

void print_usage(void)
{
        printf("Usage: translator OPTIONS\n");
        printf("OPTIONS:\n");
        printf("\t-p, --port PORT\t\t port to listen on.\n");
        printf("\t-l, --log LOG_FILE\t\t file to write client IPs to.\n");
}

int main(int argc, char **argv)
{       
	struct sigaction action;
	int sock, ret = 0;
	struct sockaddr_in saddr;
	int family = AF_SERVAL;

        argc--;
	argv++;
        
	while (argc) {
                if (strcmp(argv[0], "-p") == 0 ||
		    strcmp(argv[0], "--port") == 0) {
                        if (argc == 1) {
                                print_usage();
                                goto fail;
                        }
                        
                        translator_port = atoi(argv[1]);
                        argv++;
                        argc--;
                } else if (strcmp(argv[0], "-h") == 0 ||
                           strcmp(argv[0], "--help") ==  0) {
                        print_usage();
                        goto fail;
                } else if (strcmp(argv[0], "-l") == 0 ||
                           strcmp(argv[0], "--log") ==  0) {
                        if (argc == 1 || log_is_open(&logh)) {
                                print_usage();
                                goto fail;
                        }
                        ret = log_open(&logh, argv[1]);

                        if (ret == -1) {
                                fprintf(stderr, "bad log file %s\n",
                                        argv[1]);
                                goto fail;
                        }

                        printf("Writing client log to '%s'\n",
                               argv[1]);
                        argv++;
                        argc--;
                }

		argc--;
		argv++;
	}	
        
        memset(&action, 0, sizeof(struct sigaction));
        action.sa_handler = signal_handler;
        
	/* The server should shut down on these signals. */
        sigaction(SIGTERM, &action, 0);
	sigaction(SIGHUP, &action, 0);
	sigaction(SIGINT, &action, 0);
        sigaction(SIGPIPE, &action, 0);
	
	sock = socket(AF_INET, SOCK_STREAM, 0);

	if (sock == -1) {
		fprintf(stderr, "inet socket: %s\n",
			strerror(errno));
                goto fail;
	}

        ret = 1;
        
        ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &ret, sizeof(ret));
        
        if (ret == -1) {
                fprintf(stderr, "Could not set SO_REUSEADDR - %s\n",
                        strerror(errno));
        }
        
        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = INADDR_ANY;
        saddr.sin_port = htons(translator_port);

        printf("Serval translator running on port %u\n", 
               translator_port);

        ret = bind(sock, (struct sockaddr *)&saddr, sizeof(saddr));

        if (ret == -1) {
		fprintf(stderr, "inet bind: %s\n",
			strerror(errno));
                goto fail_bind_sock;
	}

        ret = listen(sock, 10);

        if (ret == -1) {
                fprintf(stderr, "inet listen: %s\n",
			strerror(errno));
                goto fail_bind_sock;
        }


        while (1) {
                int client_sock;
                socklen_t addrlen = sizeof(saddr);
                struct client *c;
                
                printf("Waiting for new clients...\n");

                client_sock = accept(sock, (struct sockaddr *)&saddr,
                                     &addrlen);

                if (client_sock == -1) {
                        switch (errno) {
                        case EINTR:
                                /* This means we should exit
                                 * (ctrl-c) */
                                break;
                        default:
                                /* Other error, exit anyway */
                                fprintf(stderr, "accept: %s\n",
                                        strerror(errno));
                        }
                        break;
                } 

                c = client_create(client_sock, family, 
                                  (struct sockaddr *)&saddr, addrlen);

                if (!c) {
                        fprintf(stderr, "Could not create client\n");
                        close(client_sock);
                        break;
                }
                
                ret = pthread_create(&c->thr, NULL, client_thread, c);

                if (ret != 0) {
                        fprintf(stderr, "pthread_create: %s\n",
                                strerror(errno));
                        client_free(c);
                        break;
                }
                
                ret = pthread_detach(c->thr);

                if (ret != 0) {
                        fprintf(stderr, "detach: %s\n",
                                strerror(errno));
                        break;
                }
                
                /* Make a note in our client log */
                if (log_is_open(&logh)) {
                        struct hostent *h;
                        char buf[18];
                                                
                        h = gethostbyaddr(&saddr.sin_addr, 4, AF_INET);

                        log_write_line(&logh, "c %s %s",
                                       inet_ntop(AF_INET, &saddr.sin_addr, 
                                                 buf, sizeof(buf)),
                                       h ? h->h_name : "unknown hostname");
                }
                
        }
        
        printf("Translator exits.\n");
fail_bind_sock:
	close(sock);
fail:
        if (log_is_open(&logh))
                log_close(&logh);

	return ret;
}
