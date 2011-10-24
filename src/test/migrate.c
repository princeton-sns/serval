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

enum cmd_type {
        CMD_MIGRATE_FLOW,
        CMD_MIGRATE_INTERFACE,
        CMD_MIGRATE_SERVICE,
        __MAX_CMD_TYPE,
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

void print_usage(void) 
{
        int i;

        printf("Usage: migrate COMMAND [ ARGS ]\nCOMMANDs:\n");

        for (i = 0; i < __MAX_CMD_TYPE; i++) {
                printf("\t%-30s %s\n",
                       commands[i].name,
                       commands[i].desc);
        }
}

int main(int argc, char **argv)
{
	int ret = 0;
	char *from_if = NULL;
	char *to_if = NULL;
        struct flow_id flow;
        struct service_id service;
        enum cmd_type cmd = __MAX_CMD_TYPE;
        struct hostctrl *hc;

        memset(&flow, 0, sizeof(flow));
        memset(&service, 0, sizeof(service));

        argc--;
        argv++;
        
        if (strcmp(argv[0], 
                   commands[CMD_MIGRATE_FLOW].name) == 0) {
                if (argc < 2) {
                        printf("Too few arguments\n");
                        goto fail_usage;
                }
                cmd = CMD_MIGRATE_FLOW;
                flow.s_id32 = htonl(atoi(argv[1]));
                to_if = argv[2];
                
                printf("Migrating flow %s to interface %s\n",
                       flow_id_to_str(&flow), to_if);
        } else if (strcmp(argv[0], 
                          commands[CMD_MIGRATE_INTERFACE].name) == 0) {
                if (argc < 2) {
                        printf("Too few arguments\n");
                        goto fail_usage;
                }
                cmd = CMD_MIGRATE_INTERFACE;
                from_if = argv[1];
                to_if = argv[2];
                
                printf("Migrating flows on interface %s to interface %s\n",
                       from_if, to_if);
        } else if (strcmp(argv[0], 
                          commands[CMD_MIGRATE_SERVICE].name) == 0) {
                if (argc < 2) {
                        printf("Too few arguments\n");
                        goto fail_usage;
                }
                cmd = CMD_MIGRATE_SERVICE;
                service.s_sid32[0] = htonl(atoi(argv[1]));
                to_if = argv[2];
                
                printf("Migrating flows of service %s to interface %s\n",
                       service_id_to_str(&service), to_if);
        }
        
        if (cmd == __MAX_CMD_TYPE) {
                print_usage();
                return 0;
        }

	ret = libservalctrl_init();

	if (ret == -1) {
		fprintf(stderr, "Could not init libservalctrl\n");
		ret = -1;
		goto fail_ctrl;
	}
        
        hc = hostctrl_local_create(NULL, NULL, HCF_START);
	
        if (!hc) {
                ret = -1;
                goto out;
        }


	switch (cmd) {
        case CMD_MIGRATE_FLOW:
                ret = hostctrl_flow_migrate(hc, &flow, to_if);
                break;
        case CMD_MIGRATE_INTERFACE:
                ret = hostctrl_interface_migrate(hc, from_if, to_if);
                break;
        case CMD_MIGRATE_SERVICE:
                ret = hostctrl_service_migrate(hc, &service, to_if);
        default:
                break;
        }
        
	if (ret < 0) {
		fprintf(stderr, "could not migrate\n");
	}

        hostctrl_free(hc);
out:
        libservalctrl_fini();
fail_ctrl:
	return ret;

fail_usage:
        print_usage();
        return 0;
}
