/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/debug.h>
#include "timer.h"

void add_timer(struct timer_list *timer)
{
	BUG_ON(timer_pending(timer));
	mod_timer(timer, timer->expires);
}

int del_timer(struct timer_list *timer)
{
	return 0;
}

int mod_timer(struct timer_list *timer, unsigned long expires)
{
	return 0;
}

int mod_timer_pending(struct timer_list *timer, unsigned long expires)
{
	return 0;
}

int mod_timer_pinned(struct timer_list *timer, unsigned long expires)
{
	return 0;
}
