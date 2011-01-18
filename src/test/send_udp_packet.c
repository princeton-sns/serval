/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/serval.h>
#include <libserval/serval.h>

int main(int argc, char **argv)
{
	int sock;
	unsigned long data = 8;
	ssize_t ret;
	struct sockaddr_sf addr;

	sock = socket_sf(AF_SERVAL, SOCK_DGRAM, 0);

	if (sock == -1) { 
		fprintf(stderr, "could not create SERVAL socket: %s\n",
			strerror(errno));
		return -1;
	}

	addr.sf_family = AF_SERVAL;
	addr.sf_srvid.s_sid16 = htons(7); 
	
	ret = sendto_sf(sock, &data, sizeof(data), 0, (struct sockaddr *)&addr, 
		     sizeof(struct sockaddr_sf));

	if (ret == -1) {
		fprintf(stderr, "sendto: %s\n", strerror_sf(errno));
	}

	return ret;
}
