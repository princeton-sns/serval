/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <libservalctrl/init.h>
#include "message_channel_internal.h"

static int is_initialized = 0;

//__onload
int libservalctrl_init(void)
{
    if (!is_initialized) {
        message_channel_libinit();
        is_initialized = 1;
    }
    return 0;
}

//__onexit
void libservalctrl_fini(void)
{
    if (is_initialized) {    
        message_channel_libfini();
    }
}
