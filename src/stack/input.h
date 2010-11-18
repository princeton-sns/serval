/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _INPUT_H_
#define _INPUT_H_

#if defined(__KERNEL__)
#include <linux/ip.h>
#else
#include <netinet/ip.h>
#endif

enum {
	INPUT_NO_PROT = -3,
	INPUT_NO_SOCK = -2,
	INPUT_ERROR = -1,
	INPUT_OK,
	INPUT_KEEP,
};

#define IS_INPUT_ERROR(val) (val < 0)

int scaffold_input(struct sk_buff *skb);

#endif /* _INPUT_H_ */
