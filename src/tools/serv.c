/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- 
 *
 * A tool for managing the Serval stack, supporting "pluggable"
 * commands.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
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
#include <libgen.h>

#include "command.h"

extern struct command service;
extern struct command migrate;

static struct command *cmdlist[] = {
	&service,
	&migrate,
	NULL
};

static void print_usage(const char *name, struct command *cmd)
{
	int i = 0;

	printf("Usage: serv CMD OPTIONS\n");
	
	if (cmd) {
                printf("CMD ");
		cmd->print_usage();
	} else {
		printf("where CMD is any of:\n");
		
		while (cmdlist[i]) {
			printf("\t%s\t\t%s\n", 
                               cmdlist[i]->name, 
                               cmdlist[i]->desc);
			i++;
		}
	}
}

int main(int argc, char **argv)
{
	int ret = 0, i = 0;
        hostctrl_t *hctl;
	const char *exename = basename(argv[0]);
	void *cmd_args;

	if (argc < 2) {
		print_usage(exename, NULL);
		return -1;
	}

	argv++;
	argc--;

	while (cmdlist[i]) {
		if (strcmp(cmdlist[i]->name, argv[0]) == 0)
			break;
		i++;
        }

	if (!cmdlist[i]) {
		printf("No command given\n");
		print_usage(exename, NULL);
		return 0;
	}

	argv++;
	argc--;
	
	ret = cmdlist[i]->parse_args(argc, argv, &cmd_args);
	
	if (ret == -1) {
		print_usage(exename, cmdlist[i]);
		return -1;
	}

        libservalctrl_init();

        hctl = hostctrl_local_create(NULL, NULL, HCF_START);

	if (!hctl) {
		fprintf(stderr, "Could not init resolver\n");
		ret = -1;
		goto fail_hostctrl;
	}
	
	ret = cmdlist[i]->execute(hctl, cmd_args);
        
	if (ret < 0) {
		fprintf(stderr, "could not execute command %s\n", 
                        cmdlist[i]->name);
	}

        hostctrl_free(hctl);
fail_hostctrl:
        libservalctrl_fini();

	return ret;
}
