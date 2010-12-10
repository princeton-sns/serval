/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/scaffold.h>
#include <libscaffold/scaffold.h>

int main(int argc, char **argv)
{
	int sock;
	unsigned long data = 8;
	ssize_t ret;
	struct sockaddr_sf addr;

	sock = socket_sf(AF_SCAFFOLD, SOCK_DGRAM, 0);

	if (sock == -1) { 
		fprintf(stderr, "could not create SCAFFOLD socket: %s\n",
			strerror(errno));
		return -1;
	}

	addr.sf_family = AF_SCAFFOLD;
	addr.sf_srvid.s_sid16 = htons(7); 
	
	ret = bind_sf(sock, (struct sockaddr *)&addr, sizeof(addr));

	if (ret == -1) {
		fprintf(stderr, "bind: %s\n", strerror_sf(errno));
		close_sf(sock);
		return -1;
	}
	
	addr.sf_srvid.s_sid16 = htons(8);

	ret = sendto_sf(sock, &data, sizeof(data), 0, 
                        (struct sockaddr *)&addr, sizeof(addr));

	if (ret == -1) {
		fprintf(stderr, "sendto: %s\n", strerror_sf(errno));
	}

	close_sf(sock);

	return ret;
}
