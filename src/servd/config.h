#ifndef SERVD_CONFIG_H
#define SERVD_CONFIG_H

#include <stdbool.h>

enum config_type {
    CONFIG_TYPE_BOOL,
    CONFIG_TYPE_STRING,
    CONFIG_TYPE_INT,
    CONFIG_TYPE_UINT,
    CONFIG_TYPE_IPADDR,
    CONFIG_TYPE_NULL,
};

struct config {
    enum config_type type;
    const char *name;
    void *value;
    size_t size;
};

#define null_config {				\
	.type = CONFIG_TYPE_NULL,		\
	    .name = NULL,			\
	    .value = NULL,			\
	    .size = 0,				\
	    }

int config_read(const char *config_file, struct config *config);


#endif /* SERVD_CONFIG_H */
