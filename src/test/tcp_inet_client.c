/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

int client(struct in_addr *ipaddr) {
	struct sockaddr_in inaddr;
	char buf[1024], ipstr[20];
	int ret;

	memset(&inaddr, 0, sizeof(inaddr));
	inaddr.sin_family = AF_INET;
	inaddr.sin_port = htons(5555);
	memcpy(&inaddr.sin_addr, ipaddr, sizeof(*ipaddr));
  
	sock = socket(AF_INET, SOCK_STREAM, 0);

        if (sock == -1) {
                fprintf(stderr, "socket: %s\n",
                        strerror(errno));
                return -1;
        }

	set_reuse_ok(sock);

        ret = connect(sock, (struct sockaddr *)&inaddr, sizeof(inaddr));

        if (ret == -1) {
                fprintf(stderr, "connect to %s:%u failed: %s\n",
                        inet_ntop(AF_INET, &inaddr.sin_addr, 
                                  ipstr, sizeof(ipstr)),
                        htons(inaddr.sin_port), 
                        strerror(errno));
                close(sock);
                return -1;
                        
        }

	printf("client: waiting on user input :>");

	while (fgets(buf, sizeof(buf), stdin) != NULL) {
		
		if (strlen(buf) == 1) {
			printf("\n\nclient: waiting on user input :>");
			continue;
		}
		
		if (strlen(buf) < sizeof(buf)) // remove new line
			buf[strlen(buf) - 1] = '\0';

		printf("client: sending \"%s\" to object ID %s\n", 
                       buf, inet_ntop(AF_INET, &inaddr.sin_addr, 
				      ipstr, sizeof(ipstr)));
                
		ret = send(sock, buf, strlen(buf), 0);

		if (ret == -1) {
			fprintf(stderr, "send failed (%s)\n", 
                                strerror(errno));
			break;
		}
                printf("waiting for response...\n");

                memset(buf, 0, sizeof(buf));

		ret = recv(sock, buf, sizeof(buf), 0);

                if (ret == -1) {
                        fprintf(stderr, "recv: %s\n", strerror(errno));
                } else if (ret == 0) {
                        printf("other end closed\n");
                        break;
                } else {
                        printf("Response from server: %s\n", buf);
                        
                        if (strcmp(buf, "quit") == 0)
                                break;
                }
                printf("client: waiting on user input :>");
	}
	
	close(sock);
	
        return 0;
}

int main(int argc, char **argv)
{
	struct sigaction action;
	const char *ipstr = "192.168.56.102";
	struct in_addr ipaddr;
	int ret;

	memset(&action, 0, sizeof(struct sigaction));
        action.sa_handler = signal_handler;
        
	/* The server should shut down on these signals. */
        //sigaction(SIGTERM, &action, 0);
	//sigaction(SIGHUP, &action, 0);
	//sigaction(SIGINT, &action, 0);

	if (argc > 1)
		ipstr = argv[1];

	
	if (inet_pton(AF_INET, ipstr, &ipaddr) != 1) {
		fprintf(stderr, "bad IP %s\n", ipstr);
		return -1;
	}

	ret = client(&ipaddr);

        printf("client done..\n");

        return ret;
}

