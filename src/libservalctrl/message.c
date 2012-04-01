/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <libservalctrl/message.h>

message_t *message_alloc(const void *data, size_t len)
{
	message_t *m;

	m = malloc(sizeof(*m) + len);

	if (!m)
		return NULL;

	memset(m, 0, sizeof(*m) + len);
	
	atomic_set(&m->refcount, 1);
	m->length = len;
    m->alloc_len = len;

	if (data) 
		memcpy(m->data, data, len);
	
	return m;
}
