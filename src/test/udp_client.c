/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
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
#include <libserval/serval.h>
#include <netinet/serval.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>

static unsigned short CLIENT_OBJECT_ID = 32769;
static unsigned short ECHO_OBJECT_ID = 16385;

static int sock;

void signal_handler(int sig)
{
        printf("signal caught! closing socket...\n");
        //close(sock);
}

int set_reuse_ok(int soc)
{
	int option = 1;
        
	if (setsockopt(soc, SOL_SOCKET, SO_REUSEADDR, 
                       &option, sizeof(option)) < 0) {
		fprintf(stderr, "proxy setsockopt error");
		return -1;
	}
	return 0;
}

int client(void) {
	struct sockaddr_sv cliaddr;
	struct sockaddr_sv srvaddr;
	int n;
	unsigned N = 512;
	char sbuf[N], rbuf[N + 1];

	bzero(&cliaddr, sizeof(cliaddr));
	cliaddr.sv_family = AF_SERVAL;
	cliaddr.sv_srvid.s_sid16[0] = htons(CLIENT_OBJECT_ID);

	bzero(&srvaddr, sizeof(srvaddr));
	srvaddr.sv_family = AF_SERVAL;
	srvaddr.sv_srvid.s_sid16[0] = htons(ECHO_OBJECT_ID);
  
	sock = socket_sv(AF_SERVAL, SOCK_DGRAM, SERVAL_PROTO_UDP);

        if (sock == -1) {
                fprintf(stderr, "socket: %s\n",
                        strerror_sv(errno));
                return -1;
        }

	set_reuse_ok(sock);

	if (bind_sv(sock, (struct sockaddr *) &cliaddr, sizeof(cliaddr)) < 0) {
		fprintf(stderr, "bind: %s\n", 
                        strerror_sv(errno));
		return -1;
	}

	if (connect_sv(sock, (struct sockaddr *)&srvaddr, sizeof(srvaddr)) < 0) {
		fprintf(stderr, "connect: %s\n",
			strerror_sv(errno));
		return -1;
	}

	printf("client: waiting on user input :>");

	while (fgets(sbuf, N, stdin) != NULL) {
		if (strlen(sbuf) == 1) {
			printf("\n\nclient: waiting on user input :>");
			continue;
		}
		if (strlen(sbuf) < N) // remove new line
			sbuf[strlen(sbuf) - 1] = '\0';

		printf("client: sending \"%s\" to object ID %s\n", 
                       sbuf, service_id_to_str(&srvaddr.sv_srvid));
                
		if (send_sv(sock, sbuf, strlen(sbuf), 0) < 0) {
			fprintf(stderr, "send failed (%s)\n", 
                                strerror_sv(errno));
			return -1;
		}
		n = recv_sv(sock, rbuf, N, 0);
		rbuf[n] = 0;

                if (n == -1) {
                        fprintf(stderr, "recv: %s\n", strerror_sv(errno));
                } else {
                        printf("Response from server: %s\n", rbuf);
                        
                        if (strcmp(sbuf, "quit") == 0)
                                break;
                }
                
                printf("client: waiting on user input :>");
	}
	if (close_sv(sock) < 0)
		fprintf(stderr, "close: %s", 
                        strerror_sv(errno));

        return 0;
}

int main(int argc, char **argv)
{
	struct sigaction action;
        int ret;

	memset(&action, 0, sizeof(struct sigaction));
        action.sa_handler = signal_handler;
        
	/* The server should shut down on these signals. */
        //sigaction(SIGTERM, &action, 0);
	//sigaction(SIGHUP, &action, 0);
	//sigaction(SIGINT, &action, 0);

	ret = client();

        printf("client done..\n");

        return ret;
}

