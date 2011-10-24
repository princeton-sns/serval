/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <netinet/serval.h>
#include <netinet/in.h>

void usage(const char *progname)
{
        printf("Usage: %s NUM_SOCKETS\n", progname);        
}

int main(int argc, char **argv)
{
        int *sockets;
        unsigned long num_sockets, i;
        char *ptr;
        
        if (argc < 2) {
                usage(argv[0]);
                return 0;
        }
        
        num_sockets = strtoul(argv[1], &ptr, 10);

        if (ptr[0] != '\0' && argv[1][0] != '\0') {
                usage(argv[0]);
                return 0;
        }

        sockets = malloc(sizeof(int) * num_sockets);

        if (!sockets)
                return -1;

        for (i = 0; i < num_sockets; i++) {
                sockets[i] = socket(AF_SERVAL, SOCK_STREAM, 0);

                if (!sockets[i]) {
                        num_sockets = i;
                        break;
                }
        }
        
        printf("created %lu sockets, waiting 10 seconds...\n", i);

        sleep(10);
        
        for (i = 0; i < num_sockets; i++) {
                close(sockets[i]);
        }
        
        free(sockets);
        
        return 0;
}
