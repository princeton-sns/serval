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
        struct {
                struct sockaddr_sv sv;
                struct sockaddr_in in;
        } addr;
	socklen_t addrlen = sizeof(addr);
	char src[18];

	sock = socket_sv(AF_SERVAL, SOCK_DGRAM, 0);

	if (sock == -1) { 
		fprintf(stderr, "could not create SERVAL socket: %s\n",
			strerror(errno));
		return -1;
	}

        memset(&addr, 0, sizeof(addr));
	addr.sv.sv_family = AF_SERVAL;
	addr.sv.sv_srvid.s_sid16[0] = htons(7); 
	addr.in.sin_family = AF_INET;

	ret = bind_sv(sock, (struct sockaddr *)&addr, sizeof(addr.sv));
	
	if (ret == -1) {
		fprintf(stderr, "bind: %s\n", strerror_sv(errno));
		return -1;
	}

	ret = recvfrom_sv(sock, &data, sizeof(data), 0, 
			  (struct sockaddr *)&addr, &addrlen);
		
	if (ret == -1) {
		fprintf(stderr, "recvfrom: %s\n", strerror_sv(errno));
		return -1;
	}

	printf("Received a %zd byte packet from \'%s\' at %s\n", ret,
               service_id_to_str(&addr.sv.sv_srvid),
               inet_ntop(AF_INET, &addr.in.sin_addr, 
                         src, sizeof(src)));

	return ret;
}
