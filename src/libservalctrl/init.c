/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <libservalctrl/init.h>
#include <libservalctrl/task.h>
#include "message_channel_internal.h"

//__onload
int libservalctrl_init(void)
{
	task_libinit();
	message_channel_libinit();
    return 0;
}

//__onexit
void libservalctrl_fini(void)
{
	message_channel_libfini();
    task_libfini();
}
