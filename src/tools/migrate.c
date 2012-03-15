/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <libserval/serval.h>
#include <libservalctrl/init.h>
#include <libservalctrl/hostctrl.h>
#include <netinet/serval.h>
#include <netinet/in.h>
#include "command.h"

enum cmd_mig_type {
        CMD_MIGRATE_FLOW,
        CMD_MIGRATE_INTERFACE,
        CMD_MIGRATE_SERVICE,
        __CMD_MIGRATE_MAX,
};

#define MAX_ARGS 3

static struct {
        const char *name;
        const char *desc;
        const char *args[MAX_ARGS];
} commands[] = {
        [CMD_MIGRATE_FLOW] = {
                .name = "flow",
                .desc = "Migrate a flow FLOW to interface IFACE",
                .args = { "FLOW", "IFACE", NULL },
        },
        [CMD_MIGRATE_INTERFACE] = {
                .name = "interface",
                .desc = "Migrate all flows on interface IFACE1 to IFACE2",
                .args = { "IFACE1", "IFACE2", NULL },
        },
        [CMD_MIGRATE_SERVICE] = {
                .name = "service",
                .desc = "Migrate all flows associated with service SERVICE to IFACE",
                .args = { "SERVICE", "IFACE2", NULL },
        }
};

static void migrate_print_usage(void) 
{
        int i;

        printf("migrate OPTIONS:\n");

        for (i = 0; i < __CMD_MIGRATE_MAX; i++) {
                printf("\t%-30s %s\n",
                       commands[i].name,
                       commands[i].desc);
        }
}

struct arguments {
        char *from_if;
	char *to_if;
        struct flow_id flow;
        struct service_id service;
        enum cmd_mig_type cmd;        
};

static int migrate_parse_args(int argc, char **argv, void **result)
{
        static struct arguments args;
        
        memset(&args, 0, sizeof(args));
        args.cmd = __CMD_MIGRATE_MAX;

        if (argc < 2)
                return -1;

        if (strcmp(argv[0], 
                   commands[CMD_MIGRATE_FLOW].name) == 0) {
                if (argc < 2) {
                        printf("Too few arguments\n");
                        return -1;
                }
                args.cmd = CMD_MIGRATE_FLOW;
                args.flow.s_id32 = htonl(atoi(argv[1]));
                args.to_if = argv[2];
                
                printf("Migrating flow %s to interface %s\n",
                       flow_id_to_str(&args.flow), args.to_if);
        } else if (strcmp(argv[0], 
                          commands[CMD_MIGRATE_INTERFACE].name) == 0) {
                if (argc < 2) {
                        printf("Too few arguments\n");
                        return -1;
                }
                args.cmd = CMD_MIGRATE_INTERFACE;
                args.from_if = argv[1];
                args.to_if = argv[2];
                
                printf("Migrating flows on interface %s to interface %s\n",
                       args.from_if, args.to_if);
        } else if (strcmp(argv[0], 
                          commands[CMD_MIGRATE_SERVICE].name) == 0) {
                if (argc < 2) {
                        printf("Too few arguments\n");
                        return -1;
                }
                args.cmd = CMD_MIGRATE_SERVICE;
                args.service.s_sid32[0] = htonl(atoi(argv[1]));
                args.to_if = argv[2];
                
                printf("Migrating flows of service %s to interface %s\n",
                       service_id_to_str(&args.service), args.to_if);
        }
        
        if (args.cmd == __CMD_MIGRATE_MAX)
                return -1;

        *result = &args;

        return 0;
}

static int migrate_execute(struct hostctrl *hctl, void *in_args)
{
	int ret = 0;
        struct arguments *args = (struct arguments *)in_args;

	switch (args->cmd) {
        case CMD_MIGRATE_FLOW:
                ret = hostctrl_flow_migrate(hctl, &args->flow, args->to_if);
                break;
        case CMD_MIGRATE_INTERFACE:
                ret = hostctrl_interface_migrate(hctl, args->from_if, args->to_if);
                break;
        case CMD_MIGRATE_SERVICE:
                ret = hostctrl_service_migrate(hctl, &args->service, args->to_if);
        default:
                break;
        }
        
	if (ret < 0) {
		fprintf(stderr, "could not migrate\n");
	}

	return ret;
}

struct command migrate = {
        .type = CMD_MIGRATE,
        .name = "migrate",
        .desc = "migrate flows",
        .parse_args = migrate_parse_args,
        .print_usage = migrate_print_usage,
        .execute = migrate_execute,
};

#if defined(ENABLE_MAIN)

static void print_usage(void)
{
        printf("migrate COMMAND [ARGS]\n");
        migrate.print_usage();
}

int main(int argc, char **argv)
{
	int ret = 0;
        struct hostctrl *hctl;
        void *args;

        if (argc < 2) {
                print_usage();
                return 0;
        }

        argc--;
        argv++;

        ret = migrate.parse_args(argc, argv, &args);
        
        if (ret == -1) {
                print_usage();
                return -1;
        }

	ret = libservalctrl_init();

	if (ret == -1) {
		fprintf(stderr, "Could not init libservalctrl\n");
		ret = -1;
		goto fail_ctrl;
	}
        
        hctl = hostctrl_local_create(NULL, NULL, HCF_START);
	
        if (!hctl) {
                ret = -1;
                goto out;
        }
        
        migrate.execute(hctl, args);
        
	if (ret < 0) {
		fprintf(stderr, "could not migrate\n");
	}

        hostctrl_free(hctl);
out:
        libservalctrl_fini();
fail_ctrl:
	return ret;
}
#endif /* ENABLE_MAIN */
