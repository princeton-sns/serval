#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include "config.h"

static int parse_bool(struct config *cfg, const char *value)
{
    if (strcmp(value, "true") == 0) {
	*((bool *)cfg->value) = true;
	return 1;
    } else if (strcmp(value, "false") == 0) {
	*((bool *)cfg->value) = false;
	return 1;
    }
    return 0;
}

static int parse_string(struct config *cfg, const char *value)
{
    strncpy(((char *)cfg->value), value, cfg->size);
    
    return 0;
}

static int parse_int(struct config *cfg, const char *value)
{
    char *endptr = NULL;

    *((int *)cfg->value) = strtol(value, &endptr, 10);
    
    if (*endptr == '\0')
	return 1;
    return 0;
}

static int parse_uint(struct config *cfg, const char *value)
{
    char *endptr = NULL;

    *((unsigned *)cfg->value) = strtoul(value, &endptr, 10);
    
    if (*endptr == '\0')
	return 1;
    return 0;
}

static int parse_ipaddr(struct config *cfg, const char *value)
{
    return inet_pton(AF_INET, value, cfg->value);
}

static int (*type_parsers[])(struct config *cfg, const char *value) = {
    [CONFIG_TYPE_BOOL] = parse_bool,
    [CONFIG_TYPE_STRING] = parse_string,
    [CONFIG_TYPE_INT] = parse_int,
    [CONFIG_TYPE_UINT] = parse_uint,
    [CONFIG_TYPE_IPADDR] = parse_ipaddr,
};

int config_read(const char *config_file, struct config *config)
{
    FILE *f;

    f = fopen(config_file, "r");

    if (!f) {
	fprintf(stderr, "could not open config file '%s' : %s\n", 
		config_file, strerror(errno));
	return -1;
    }

    while (true) {
	char name[128], value[128];
    	int ret;

	ret = fscanf(f, "%128[a-z_A-Z]=%128s\n", name, value);
	
	if (ret == EOF || ret == 0) {
	    break;
	} else if (ret == 2) {
	    unsigned i = 0;

	    while (config[i].type != CONFIG_TYPE_NULL) {
		if (strncmp(name, config[i].name, 128) == 0) {
		    type_parsers[config[i].type](&config[i], value);
		}
		i++;
	    }
	}
    }
    
    fclose(f);

    return 0;
}
