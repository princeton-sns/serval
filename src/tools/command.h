/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _COMMAND_H_
#define _COMMAND_H_

enum cmd_type {
	CMD_SERVICE,
	CMD_MIGRATE,
	_CMD_MAX,
};

struct command {
	enum cmd_type type;
	const char *name;
	const char *desc;
        int (*parse_args)(int argc, char **argv, void **result);
	void (*print_usage)();
	int (*execute)(struct hostctrl *hctl, void *args);
};

#endif /* _COMMAND_H_ */
