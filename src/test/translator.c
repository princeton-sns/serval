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

static unsigned int client_num = 0;

struct client {
        unsigned int id;
        pthread_t thr;
        int inet_sock;
        int serval_sock;
        int pipefd[2];
        int should_exit;
};

static ssize_t forward_data(int from, int to, int pipefd[2])
{
        ssize_t rlen, wlen;

         rlen = splice(from, NULL, pipefd[1], NULL, 
                       INT_MAX, SPLICE_F_MOVE | SPLICE_F_MORE);
         
         if (rlen == -1) {
                 fprintf(stderr, "splice1: %s\n",
                         strerror(errno));
                 return rlen;
         } 
         
         printf("splice1 %zd bytes\n", rlen);
         
         wlen = splice(pipefd[0], NULL, to, NULL,
                       rlen, SPLICE_F_MOVE | SPLICE_F_MORE);
         
         if (wlen == -1) {
                 fprintf(stderr, "splice2: %s\n",
                                strerror(errno));
                 return wlen;
         }
         
         printf("splice2 %zd bytes\n", wlen);

         return wlen;
}

static ssize_t legacy_to_serval(struct client *c)
{
        printf("forwarding legacy to serval\n");
        return forward_data(c->inet_sock, c->serval_sock, c->pipefd);
}

static ssize_t serval_to_legacy(struct client *c)
{
        printf("forwarding serval to legacy\n");
        return forward_data(c->serval_sock, c->inet_sock, c->pipefd);
}

struct client *client_create(int inet_sock)
{
        struct client *c;
        int ret;

        c = malloc(sizeof(*c));

        if (c) {
                memset(c, 0, sizeof(*c));
                c->id = client_num++;
                c->inet_sock = inet_sock;
        }        

        ret = pipe(c->pipefd);

        if (ret == -1) {
                fprintf(stderr, "pipe: %s\n",
			strerror(errno));
                goto fail_pipe;
        }
        
        c->serval_sock = socket(AF_SERVAL, SOCK_DGRAM, 0);
        
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
        struct sockaddr_sv svaddr;
        int ret;

        memset(&svaddr, 0, sizeof(svaddr));
        svaddr.sv_family = AF_SERVAL;
        svaddr.sv_srvid.s_sid16[0] = htons(16385);

        ret = connect(c->serval_sock, 
                      (struct sockaddr *)&svaddr, sizeof(svaddr));

        if (ret == -1) {
                fprintf(stderr, "client %u connect failed: %s\n",
                        c->id, strerror(errno));
                client_free(c);
                return NULL;
        }
        
        printf("client %u connected to service %s\n",
               c->id, service_id_to_str(&svaddr.sv_srvid));

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
                                printf("inet_sock readable\n");
                                bytes = legacy_to_serval(c);

                                if (bytes == 0) {
                                        printf("tcp sock closed\n");
                                        break;
                                }
                        }

                        if (FD_ISSET(c->serval_sock, &fds)) {
                                printf("serval_sock readable\n");
                                bytes = serval_to_legacy(c);
                                
                                if (bytes == 0) {
                                        printf("serval sock closed\n");
                                        break;
                                }
                        }

                        if (bytes < 0) {
                                fprintf(stderr, "forwarding error\n");
                                break;
                        } 
                        printf("forwarded %zd bytes\n", bytes);
                }
        }

        client_free(c);

        return NULL;
}

int main(int argc, char **argv)
{
	int sock, ret = 0;
	struct sockaddr_in saddr;

	sock = socket(AF_INET, SOCK_STREAM, 0);

	if (sock == -1) {
		fprintf(stderr, "inet socket: %s\n",
			strerror(errno));
                goto fail_sock;
	}
        
        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = INADDR_ANY;
        saddr.sin_port = htons(5555);

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
                
                printf("Waiting for legacy client\n");

                client_sock = accept(sock, (struct sockaddr *)&saddr,
                                     &addrlen);

                if (client_sock == -1) {
                        fprintf(stderr, "accept: %s\n",
                                strerror(errno));
                        break;
                }

                printf("accepted new client\n");

                c = client_create(client_sock);

                if (!c) {
                        fprintf(stderr, "Could not create client\n");
                        close(client_sock);
                        break;
                }
                
                ret = pthread_create(&c->thr, NULL, client_thread, c);

                if (ret != 0) {
                        fprintf(stderr, "pthread_create: %s\n",
                                strerror(errno));
                        break;
                }
                
                printf("new client %u\n", c->id);

                ret = pthread_detach(c->thr);

                if (ret != 0) {
                        fprintf(stderr, "detach: %s\n",
                                strerror(errno));
                        break;
                }
        }
        
fail_bind_sock:
	close(sock);
fail_sock:

	return ret;
}
