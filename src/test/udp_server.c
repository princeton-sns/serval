/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
// Copyright (c) 2010 The Trustees of Princeton University (Trustees)

// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and/or hardware specification (the “Work”) to deal
// in the Work without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Work, and to permit persons to whom the Work is
// furnished to do so, subject to the following conditions: The above
// copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Work.

// THE WORK IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE WORK OR THE USE OR OTHER
// DEALINGS IN THE WORK.
#include <libscaffold/scaffold.h>
#include <netinet/scaffold.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>

static unsigned short ECHO_OBJECT_ID = 16385;

int set_reuse_ok(int sock);

void server(void)
{
        int sock;
        struct sockaddr_sf servaddr, cliaddr;  
    
        if ((sock = socket_sf(AF_SCAFFOLD, SOCK_DGRAM, SCAFFOLD_PROTO_UDP)) < 0) {
                fprintf(stderr, "error creating AF_SCAFFOLD socket: %s", 
                        strerror(errno));
                exit(EXIT_FAILURE);
        }
  
        bzero((void *)&servaddr, sizeof(servaddr));
        servaddr.sf_family = AF_SCAFFOLD;
        servaddr.sf_srvid.s_sid16 = htons(ECHO_OBJECT_ID);
  
        set_reuse_ok(sock);
  
        if (bind_sf(sock, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
                fprintf(stderr, "error binding socket: %s", strerror(errno));
                exit(EXIT_FAILURE);
        }
        fprintf(stdout, "server: bound to object id %d\n", ECHO_OBJECT_ID);

        int backlog = 8;
        listen_sf(sock, backlog);

        do {
                socklen_t l = sizeof(cliaddr);        
                int fd = accept_sf(sock, (struct sockaddr *)&cliaddr, &l);
                if (fd < 0) {
                        fprintf(stderr, "error accepting new conn %s", strerror_sf(errno));
                        exit(EXIT_FAILURE);
                }
                fprintf(stdout, "server: recv conn from object id %s; got fd = %d\n",
                        service_id_to_str(&cliaddr.sf_srvid), fd);
        
                int k = 0;
                do {
                        unsigned N = 512;
                        char buf[N];
                        int n;
      
                        fprintf(stderr, "server: waiting on client request\n");
                        if ((n = recv_sf(fd, buf, N, 0)) < 0) {
                                fprintf(stderr, 
                                        "server: error receiving client request: %s\n",
                                        strerror(errno));
                                break;
                        }
                        if (n == 0) {
                                fprintf(stderr, "server: received EOF; "
                                        "listening for new conns\n");
                                break;
                        }
                        buf[n] = '\0';
                        if (n > 0) {
                                char buf2[n];
                                int i = 0;
                                for (; i < n; i++)
                                        buf2[i] = toupper(buf[i]);
                                fprintf(stderr, "Server: Convert and send upcase:");
                                for (i = 0; i < n; i++)
                                        fprintf(stderr, "%c", buf2[i]);
                                fprintf(stderr, "\n");
                                send_sf(fd, buf2, n, 0);
                                if (strcmp(buf, "quit") == 0)
                                        break;
                        }
                        k++;
                } while (1);
                fprintf(stderr, "Server listening for NEW connections\n");
        } while (1);
        exit(EXIT_SUCCESS);
}

int set_reuse_ok(int sock)
{
        int option = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0) {
                fprintf(stderr, "proxy setsockopt error");
                return -1;
        }
        return 0;
}

int main(int argc, char **argv)
{
        server();

        return 0;
}
