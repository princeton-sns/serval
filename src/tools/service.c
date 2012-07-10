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
        
        if (ret != 0)
                return -1;

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
        printf("service OPTIONS:\n");
        printf("\tadd|del|mod SERVICEID[:PREFIX_BITS]"
               " IPADDR [IPADDR] [priority NUM] [weight NUM]\n");
        printf("\tSERVICEID can be decimal or hexadecimal"
               " (use 0x prefix).\n");
}
        
struct arguments {
        enum service_op op;
        struct service_id srvid;
	struct in_addr ipaddr1, ipaddr2, *ip1, *ip2;
        unsigned int priority;
        unsigned int weight;
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
        args.priority = 1;
        args.weight = 0;

	if (argc < 3)
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
        
        argc--;
        argv++;

        /* Check for hexadecimal serviceID. */
        if (strcmp(argv[0], "default") == 0) {
                /* Do nothing, serviceID already set to zero */
        } else if (argv[0][0] == '0' && argv[0][1] == 'x') {
                int len;
                
                argv[0] += 2;
                ptr = argv[0];

                while (*ptr != ':' && *ptr != '\0')
                        ptr++;
                
                if (*ptr == ':') {
                        prefix = ptr + 1;
                        *ptr = '\0';
                }
               
                len = strlen(argv[0]);

                if (len > 64)
                        len = 64;
                
                if (serval_pton(argv[0], &args.srvid) == -1)
                        return -1;
        } else {
                unsigned long id = strtoul(argv[0], &ptr, 10);
                
                if (!((*ptr == '\0' || *ptr == ':') && argv[0] != '\0')) {
                        fprintf(stderr, "bad service id format '%s',"
                                " should be short integer string\n",
                                argv[0]);
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

        argc--;
        argv++;

        if (argc == 0) {
                fprintf(stderr, "No target IP in rule\n");
                return -1;
        }
        
        ret = name_to_inet_addr(argv[0], &args.ipaddr1);
        
        if (ret != 1) {
                fprintf(stderr, "Bad IP address: '%s'\n",
                        argv[0]);
                return -1;
        }

        args.ip1 = &args.ipaddr1;

        argc--;
        argv++;

        while (argc) {
                if (strcmp("priority", argv[0]) == 0) {
                        char *ptr = NULL;
                        
                        if (argc < 2) {
                                fprintf(stderr, "No priority number given\n");
                                return -1;
                        }
                        
                        args.priority = strtoul(argv[1], &ptr, 10);
                        
                        if (*ptr != '\0' || argv[1][0] == '\0') {
                                fprintf(stderr, "Bad priority %s\n",
                                        argv[1]);
                                return -1;
                        }

                        argc--;
                        argv++;
                } else if (strcmp("weight", argv[0]) == 0) {
                        char *ptr = NULL;
                        
                        if (argc < 2) {
                                fprintf(stderr, "No weight given\n");
                                return -1;
                        }
                        
                        args.weight = strtoul(argv[1], &ptr, 10);
                        
                        if (*ptr != '\0' || argv[1][0] == '\0') {
                                fprintf(stderr, "Bad weight %s\n",
                                        argv[1]);
                                return -1;
                        }

                        argc--;
                        argv++;
                } else {
                        ret = name_to_inet_addr(argv[0], &args.ipaddr2);
                        
                        if (ret != 1) {
                                fprintf(stderr, "Bad IP address: '%s'\n",
                                        argv[0]);
                                return -1;
                        }
                        args.ip2 = &args.ipaddr2;
                }
                argc--;
                argv++;
        }
        {
                char buf[18];
                printf("%s %s:%u %s priority=%u weight=%u\n",
                       opnames[args.op].long_name,
                       service_id_to_str(&args.srvid), 
                       args.prefix_bits, 
                       inet_ntop(AF_INET, &args.ipaddr1, buf, 18),
                       args.priority,
                       args.weight);
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
                ret = hostctrl_service_add(hctl, &args->srvid, 
                                           args->prefix_bits, 
                                           args->priority, 
                                           args->weight, args->ip1);
                break;
        case SERVICE_OP_DEL:
                ret = hostctrl_service_remove(hctl, &args->srvid, 
                                              args->prefix_bits, args->ip1);
                break;
        case SERVICE_OP_MOD:
                ret = hostctrl_service_modify(hctl, &args->srvid, 
                                              args->prefix_bits, 
                                              args->priority, 
                                              args->weight, 
                                              args->ip1, args->ip2);
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

static void print_usage(void)
{
        printf("service COMMAND [ OPTIONS ]\n");
        service.print_usage();
}

int main(int argc, char **argv)
{
	int ret = 0;
        hostctrl_t *hctl;
        void *args;

	if (argc < 3) {
                print_usage();
		return 0;
	}

        argc--;
        argv++;

        ret = service.parse_args(argc, argv, &args);

        if (ret == -1) {
                print_usage();
                return -1;
        }

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
