/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/serval.h>
#include <libserval/serval.h>

int main(int argc, char **argv)
{
	int sock;
        const char *ipdst = "192.168.56.102";
	unsigned long data = 8;
	ssize_t ret = 0;
        struct {
                struct sockaddr_sv sv;
                struct sockaddr_in in;
        } addr;

        if (argc > 1) {
                ipdst = argv[1];
        }
        
	sock = socket_sv(AF_SERVAL, SOCK_DGRAM, 0);

	if (sock == -1) { 
		fprintf(stderr, "could not create SERVAL socket: %s\n",
			strerror(errno));
		goto out;
	}

        memset(&addr, 0, sizeof(addr));
	addr.sv.sv_family = AF_SERVAL;
	addr.sv.sv_srvid.s_sid16[0] = htons(6); 
	addr.in.sin_family = AF_INET;
	
        if (inet_pton(AF_INET, ipdst, &addr.in.sin_addr) != 1) {
                fprintf(stderr, "Bad advisory IP address %s\n",
                        ipdst);
                goto out;
        }
        
        printf("My serviceID is \'%s\'\n",
               service_id_to_str(&addr.sv.sv_srvid));
               
        ret = bind(sock, (struct sockaddr *)&addr, sizeof(addr.sv));

        if (ret == -1) {
		fprintf(stderr, "bind: %s\n", strerror_sv(errno));
                goto out;
        }

	addr.sv.sv_srvid.s_sid16[0] = htons(7);
        
        printf("Sending to \'%s\' %s\n",
               service_id_to_str(&addr.sv.sv_srvid),
               ipdst);

	ret = sendto_sv(sock, &data, sizeof(data), 0, 
                        (struct sockaddr *)&addr, sizeof(addr));

	if (ret == -1) {
		fprintf(stderr, "sendto: %s\n", strerror_sv(errno));
	}
out:
        close(sock);

	return ret;
}
