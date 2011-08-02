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
	int ret = 0;
	char from_if[IFNAMSIZ] = "eth1";
	char to_if[IFNAMSIZ] = "eth0";

	ret = libstack_init();

	if (ret == -1) {
		fprintf(stderr, "Could not init libstack\n");
		ret = -1;
		goto fail_libstack;
	}

	
	ret = libstack_migrate_interface(&from_if, &to_if);

	if (ret < 0) {
		fprintf(stderr, "could not migrate\n");
	}
    libstack_fini();

fail_libstack:
	
	return ret;
}
