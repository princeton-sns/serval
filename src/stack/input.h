/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _INPUT_H_
#define _INPUT_H_

enum {
	INPUT_ERROR = -1,
	INPUT_OK,
	INPUT_KEEP,
};

int scaffold_input(struct sk_buff *skb);

#endif /* _INPUT_H_ */
