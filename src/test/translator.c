/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/serval.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sys/select.h>
#include <signal.h>

static unsigned int client_num = 0;

struct client {
        int family;
        unsigned int id;
        pthread_t thr;
        int inet_sock;
        int serval_sock;
        int pipefd[2];
        int should_exit;
};

#define TRANSLATOR_PORT 8080
static const char *server_ip = "192.168.56.101";

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

static ssize_t legacy_to_serval(struct client *c)
{
        return forward_data(c->inet_sock, c->serval_sock, c->pipefd);
}

static ssize_t serval_to_legacy(struct client *c)
{
        return forward_data(c->serval_sock, c->inet_sock, c->pipefd);
}

struct client *client_create(int inet_sock, int family)
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
        int ret;

        memset(&addr, 0, sizeof(addr));
        
        if (c->family == AF_SERVAL) {
                addr.sv.sv_family = c->family;
                addr.sv.sv_srvid.s_sid32[0] = htonl(TRANSLATOR_PORT);
                addrlen = sizeof(addr.sv);
        } else {
                addr.in.sin_family = c->family;
                inet_pton(AF_INET, server_ip, &addr.in.sin_addr);
                addr.in.sin_port = htons(inet_port);
                addrlen = sizeof(addr.in);
        }

        if (c->family == AF_SERVAL) {
                printf("client %u connecting to service %s... ",
                       c->id, service_id_to_str(&addr.sv.sv_srvid));
        } else {
                printf("client %u connecting to %s:%u... ",
                       c->id, server_ip, inet_port);
        }

        ret = connect(c->serval_sock, &addr.sa, addrlen);

        if (ret == -1) {
                fprintf(stderr, "connect failed: %s\n",
                        strerror(errno));
                client_free(c);
                return NULL;
        }

        printf("success!\n");

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

int main(int argc, char **argv)
{       
	struct sigaction action;
	int sock, ret = 0;
	struct sockaddr_in saddr;
	int family = AF_SERVAL;

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
                goto fail_sock;
	}
        
        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = INADDR_ANY;
        saddr.sin_port = htons(TRANSLATOR_PORT);

        printf("Serval translator running on port %u\n", 
               TRANSLATOR_PORT);

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

        ret = 1;
        
        ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &ret, sizeof(ret));
        
        if (ret == -1) {
                fprintf(stderr, "Could not set SO_REUSEADDR - %s\n",
                        strerror(errno));
        }

        while (1) {
                int client_sock;
                socklen_t addrlen = sizeof(saddr);
                struct client *c;
                
                printf("Waiting for client...\n");

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

                printf("client connected\n");

                c = client_create(client_sock, family);

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
        }
        
        printf("Translator exits.\n");
fail_bind_sock:
	close(sock);
fail_sock:

	return ret;
}
