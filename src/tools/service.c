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
#include "command.h"

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

enum service_op {
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

static void service_print_usage(void)
{
        printf("service OP\n");
        printf("\tadd|del|mod SERVICEID[:PREFIX_BITS]"
               " IPADDR [IPADDR]\n");
        printf("\tSERVICEID can be decimal or hexadecimal"
               " (use 0x prefix).\n");
}
        
struct arguments {
        enum service_op op;
        struct service_id srvid;
	struct in_addr ipaddr1, ipaddr2, *ip1, *ip2;
        unsigned short prefix_bits;
};

static int service_parse_args(int argc, char **argv, void **result)
{
        static struct arguments args;
	char *ptr, *prefix = NULL;
        int i, ret;

        memset(&args, 0, sizeof(args));
        args.op = __SERVICE_OP_MAX;
        args.prefix_bits = SERVICE_ID_MAX_PREFIX_BITS;

	if (argc < 2)
                return -1;
        
        for (i = 0; i < __SERVICE_OP_MAX; i++) {
                if (strcmp(argv[0], opnames[i].name) == 0 ||
                    strcmp(argv[0], opnames[i].long_name) == 0) {
                        args.op = i;
                        break;
                }
        }

        if (args.op == __SERVICE_OP_MAX)
                return -1;

        /* Check for hexadecimal serviceID. */
        if (strcmp(argv[1], "default") == 0) {
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

                        args.srvid.s_sid32[i++] = ntohl(id);
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

                args.srvid.s_sid32[0] = ntohl(id);
        }
        
        if (prefix) {
                args.prefix_bits = strtoul(prefix, &ptr, 10);
                
                if (!(*ptr == '\0' && prefix != '\0')) {
                        fprintf(stderr, "bad prefix string %s\n",
                                prefix);
                        return -1;
                }
                if (args.prefix_bits > SERVICE_ID_MAX_PREFIX_BITS || 
                    args.prefix_bits == 0)
                        args.prefix_bits = SERVICE_ID_MAX_PREFIX_BITS;
        }

        if (argc >= 3) {
                ret = name_to_inet_addr(argv[2], &args.ipaddr1);

                if (ret != 1) {
                        fprintf(stderr, "bad IP address: '%s'\n",
                                argv[2]);
                        return -1;
                }
                args.ip1 = &args.ipaddr1;
        }

        if (argc == 4) {
                ret = name_to_inet_addr(argv[3], &args.ipaddr2);

                if (ret != 1) {
                        fprintf(stderr, "bad IP address: '%s'\n",
                                argv[2]);
                        return -1;
                }
                args.ip2 = &args.ipaddr2;
        }
        {
                char buf[18];
                printf("%s %s:%u %s\n",
                       opnames[args.op].long_name,
                       service_id_to_str(&args.srvid), 
                       args.prefix_bits, 
                       inet_ntop(AF_INET, &args.ipaddr1, buf, 18));
        }

        *result = &args;

        return 0;
}

static int service_execute(struct hostctrl *hctl, void *in_args)
{
	int ret = 0;
        struct arguments *args = (struct arguments *)in_args;

        switch (args->op) {
        case SERVICE_OP_ADD:
                ret = hostctrl_service_add(hctl, &args->srvid, args->prefix_bits, 
                                           0, 0, args->ip1);
                break;
        case SERVICE_OP_DEL:
                ret = hostctrl_service_remove(hctl, &args->srvid, args->prefix_bits, args->ip1);
                break;
        case SERVICE_OP_MOD:
                ret = hostctrl_service_modify(hctl, &args->srvid, args->prefix_bits, 
                                              0, 0, args->ip1, args->ip2);
                break;
        default:
                break;
        }

	if (ret < 0) {
		fprintf(stderr, "could not %s service\n", 
                        opnames[args->op].long_name);
	}

	return ret;
}

struct command service = {
        .type = CMD_SERVICE,
        .name = "service",
        .desc = "manipulate service table",
        .print_usage = service_print_usage,
        .parse_args = service_parse_args,
        .execute = service_execute,
};

#if defined(ENABLE_MAIN)
int main(int argc, char **argv)
{
	int ret = 0;
        hostctrl_t *hctl;
        void *args;

	if (argc < 3) {
                service.print_usage();
		return 0;
	}

        ret = service.parse_args(argc, argv, &args);

        if (ret == -1) {
                service.print_usage();
                return -1;
        }

        argc--;
        argv++;

        libservalctrl_init();

        hctl = hostctrl_local_create(NULL, NULL, HCF_START);

	if (!hctl) {
		fprintf(stderr, "Could not init resolver\n");
		ret = -1;
		goto fail_hostctrl;
	}

        ret = service.execute(hctl, args);

        hostctrl_free(hctl);
fail_hostctrl:
        libservalctrl_fini();

	return ret;
}
#endif /* ENABLE_MAIN */
