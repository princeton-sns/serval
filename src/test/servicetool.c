/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <libservalctrl/init.h>
#include <libservalctrl/message_channel.h>
#include <libservalctrl/hostctrl.h>
#include <netinet/serval.h>
#include <netinet/in.h>
#include <libgen.h>
#include <sys/types.h>   
#include <sys/socket.h>
#include <netdb.h>

int name_to_inet_addr(const char *name, struct in_addr *ip)
{
        struct addrinfo *ai;
        struct addrinfo hints = { .ai_family = AF_INET,
                                  .ai_socktype = 0,
                                  .ai_protocol = 0, };
        int ret;

        ret = getaddrinfo(name, "0", &hints, &ai);
        
        if (ret != 0) {
                fprintf(stderr, "getaddrinfo error=%d\n", ret);
                return -1;
        }

        while (ai) {
                if (ai->ai_family == AF_INET) {
                        struct sockaddr_in *in = (struct sockaddr_in *)ai->ai_addr;
                        memcpy(ip, &in->sin_addr, sizeof(*ip));
                        ret = 1;
                        break;
                }
                ai = ai->ai_next;
        } 
        
        freeaddrinfo(ai);

        return ret;
}

enum {
        SERVICE_OP_ADD,
        SERVICE_OP_DEL,
        SERVICE_OP_MOD,
        __SERVICE_OP_MAX,
};

struct opname {
        const char *name;
        const char *long_name;
};

static const struct opname opnames[] = {
        { "add", "add" },
        { "del", "delete" },
        { "mod", "modify" }
};
        
int main(int argc, char **argv)
{
	int ret = 0, op = SERVICE_OP_ADD;
	struct service_id srvid;
	char *ptr, *prefix = NULL;
        hostctrl_t *hctl;
	struct in_addr ipaddr1, ipaddr2, *ip1 = NULL, *ip2 = NULL;
        unsigned short prefix_bits = SERVICE_ID_MAX_PREFIX_BITS;
        int i;

	if (argc < 3) {
        usage:
		fprintf(stderr, "Usage: %s add|del|mod SERVICEID[:PREFIX_BITS]"
                        " IPADDR [IPADDR]\n", basename(argv[0]));
                fprintf(stderr, "SERVICEID can be decimal or hexadecimal"
                        " (use 0x prefix).\n");
		return 0;
	}

        for (i = 0; i < __SERVICE_OP_MAX; i++) {
                if (strcmp(argv[1], opnames[i].name) == 0 ||
                    strcmp(argv[1], opnames[i].long_name) == 0) {
                        op = i;
                        break;
                }
        }

        if (i == __SERVICE_OP_MAX)
                goto usage;

        argc--;
        argv++;
        
	memset(&srvid, 0, sizeof(srvid));
        
        /* Check for hexadecimal serviceID. */
        if (strcmp(argv[0], "default") == 0) {
                /* Do nothing, serviceID already set to zero */
        } else if (argv[1][0] == '0' && argv[1][1] == 'x') {
                int len, i = 0;

                argv[1] += 2;
                ptr = argv[1];

                while (*ptr != ':' && *ptr != '\0')
                        ptr++;
                
                if (*ptr == ':') {
                        prefix = ptr + 1;
                        *ptr = '\0';
                }
               
                len = strlen(argv[1]);

                if (len > 64)
                        len = 64;

                while (len > 0) {
                        char hex32[9];
                        unsigned long id;

                        memset(hex32, '0', sizeof(hex32));
                        strncpy(hex32, argv[1] + (i * 8), len < 8 ? len : 8);
                        hex32[8] = '\0';
                        
                        id = strtoul(hex32, &ptr, 16);

                        if (!(*ptr == '\0' && hex32[0] != '\0')) {
                                fprintf(stderr, "bad service id format '%s'\n",
                                        argv[1]);
                                return -1;
                        }

                        srvid.s_sid32[i++] = ntohl(id);
                        len -= 8;
                }
        } else {
                unsigned long id = strtoul(argv[1], &ptr, 10);
                
                if (!((*ptr == '\0' || *ptr == ':') && argv[1] != '\0')) {
                        fprintf(stderr, "bad service id format '%s',"
                                " should be short integer string\n",
                                argv[1]);
                        return -1;
                }
                if (*ptr == ':')
                        prefix = ++ptr;

                srvid.s_sid32[0] = ntohl(id);
        }
        
        if (prefix) {
                prefix_bits = strtoul(prefix, &ptr, 10);
                
                if (!(*ptr == '\0' && prefix != '\0')) {
                        fprintf(stderr, "bad prefix string %s\n",
                                prefix);
                        return -1;
                }
                if (prefix_bits > SERVICE_ID_MAX_PREFIX_BITS || 
                    prefix_bits == 0)
                        prefix_bits = SERVICE_ID_MAX_PREFIX_BITS;
        }

        if (argc >= 3) {
                ret = name_to_inet_addr(argv[2], &ipaddr1);

                if (ret != 1) {
                        fprintf(stderr, "bad IP address: '%s'\n",
                                argv[2]);
                        return -1;
                }
                ip1 = &ipaddr1;
        }

        if (argc == 4) {
                ret = name_to_inet_addr(argv[3], &ipaddr2);

                if (ret != 1) {
                        fprintf(stderr, "bad IP address: '%s'\n",
                                argv[2]);
                        return -1;
                }
                ip2 = &ipaddr2;
        }
        {
                char buf[18];
                printf("%s %s:%u %s\n",
                       opnames[op].long_name,
                       service_id_to_str(&srvid), 
                       prefix_bits, 
                       inet_ntop(AF_INET, &ipaddr1, buf, 18));
        }

        libservalctrl_init();

        hctl = hostctrl_local_create(NULL, NULL, HCF_START);

	if (!hctl) {
		fprintf(stderr, "Could not init resolver\n");
		ret = -1;
		goto fail_hostctrl;
	}
	
        switch (op) {
        case SERVICE_OP_ADD:
                ret = hostctrl_service_add(hctl, &srvid, prefix_bits, 
                                           0, 0, ip1);
                break;
        case SERVICE_OP_DEL:
                ret = hostctrl_service_remove(hctl, &srvid, prefix_bits, ip1);
                break;
        case SERVICE_OP_MOD:
                ret = hostctrl_service_modify(hctl, &srvid, prefix_bits, 
                                              0, 0, ip1, ip2);
                break;
        default:
                break;
        }

	if (ret < 0) {
		fprintf(stderr, "could not %s service\n", 
                        opnames[op].long_name);
	}

        hostctrl_free(hctl);
fail_hostctrl:
        libservalctrl_fini();

	return ret;
}
