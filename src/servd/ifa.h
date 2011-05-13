/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _IFADDRS_H_
#define _IFADDRS_H_

int ifaddrs_find(void);
int ifaddrs_init(void);
void ifaddrs_fini(void);

#endif /* _IFADDRS_H_ */
