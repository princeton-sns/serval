/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/scaffold.h>

int main(int argc, char **argv)
{
	int sock;
	unsigned long data = 8;
	ssize_t ret;
	struct sockaddr_sf addr;

	sock = socket(AF_SCAFFOLD, SOCK_DGRAM, 0);

	if (sock == -1) { 
		fprintf(stderr, "could not create SCAFFOLD socket: %s\n",
			strerror(errno));
		return -1;
	}

	addr.ssf_family = AF_SCAFFOLD;
	addr.ssf_sid.s_sid16 = htons(7); 
	
	ret = sendto(sock, &data, sizeof(data), 0, (struct sockaddr *)&addr, 
		     sizeof(struct sockaddr_sf));

	if (ret == -1) {
		fprintf(stderr, "sendto: %s\n", strerror(errno));
	}

	return ret;
}
