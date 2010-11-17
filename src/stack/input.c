/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <scaffold/platform.h>
#include <scaffold/skbuff.h>
#include <linux/ip.h>
#include "input.h"

int scaffold_input(struct sk_buff *skb)
{
	LOG_DBG("received scaffold packet\n");

	return INPUT_OK;
}
