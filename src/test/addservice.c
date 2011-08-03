/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <libstack/stack.h>
#include <libserval/serval.h>
#include <netinet/serval.h>
#include <netinet/in.h>

int main(int argc, char **argv)
{
	int ret = 0, delete = 0;
	struct service_id srvid;
	char *ptr;
	unsigned long sid;
	struct in_addr ipaddr, *ip = NULL;

	ret = libstack_init();

	if (ret == -1) {
		fprintf(stderr, "Could not init libstack\n");
		ret = -1;
		goto fail_libstack;
	}
	
	if (argc < 3) {
		fprintf(stderr, "Usage: %s [-d] SERVICEID IPADDR\n",
			argv[0]);
		ret = -1;
		goto out;
	}

        if (strcmp(argv[1], "-d") == 0) {
                delete = 1;
                argc--;
                argv++;
        }

	sid = strtoul(argv[1], &ptr, 10);

	if (!(*ptr == '\0' && argv[1] != '\0')) {
		fprintf(stderr, "bad service id format '%s',"
			" should be short integer string\n",
			argv[1]);
		ret = -1;
		goto out;
	}
	
	memset(&srvid, 0, sizeof(srvid));
	srvid.s_sid32[0] = ntohl(sid);
	
        if (argc == 3) {
                ret = inet_pton(AF_INET, argv[2], &ipaddr);
                
                if (ret != 1) {
                        fprintf(stderr, "bad IP address format: '%s'\n",
                                argv[2]);
                        ret = -1;
                        goto out;
                }
                ip = &ipaddr;
        }
	
        if (delete) {
                 printf("deleting service %s\n",
                        service_id_to_str(&srvid));
                
                 ret = libstack_del_service(&srvid, 
                                            SERVICE_ID_DEFAULT_PREFIX, ip);
        } else {
                printf("adding service %s:%lu\n",
                       service_id_to_str(&srvid), SERVICE_ID_DEFAULT_PREFIX);
                
                ret = libstack_add_service(&srvid, 
                                           SERVICE_ID_DEFAULT_PREFIX, &ipaddr);
        }
	if (ret < 0) {
		fprintf(stderr, "could not add/delete service\n");
	}
out:
        libstack_fini();
fail_libstack:
	
	return ret;
}
