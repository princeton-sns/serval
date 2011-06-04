/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/serval.h>
#include <libserval/serval.h>

int main(int argc, char **argv)
{
	int sock;
	ssize_t ret;
	struct sockaddr_sv addr;

	sock = socket_sv(AF_SERVAL, SOCK_DGRAM, 0);

	if (sock == -1) { 
		fprintf(stderr, "could not create SERVAL socket: %s\n",
			strerror(errno));
		return -1;
	}

	addr.sv_family = AF_SERVAL;
	addr.sv_srvid.s_sid16[0] = htons(7); 

	ret = listen_sv(sock, 10);

	if (ret == -1) {
		printf("listen() failed correctly: %s\n",
		       strerror_sv(errno));
	} else {
		printf("listen() should have failed\n");
		return -1;
	}
	
	ret = bind_sv(sock, (struct sockaddr *)&addr, sizeof(addr));

	if (ret == -1) {
		fprintf(stderr, "bind: %s\n", strerror_sv(errno));
		close_sv(sock);
		return -1;
	}
	
	addr.sv_srvid.s_sid16[0] = htons(8);

	ret = listen_sv(sock, 10);

	if (ret == -1) {
		fprintf(stderr, "listen: %s\n", strerror_sv(errno));
	}

	close_sv(sock);

	return ret;
}
