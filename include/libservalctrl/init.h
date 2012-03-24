/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Initialization of the libservalctrl library.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#ifndef _INIT_H
#define _INIT_H

#if defined(__GNUC__) || defined(__BIONIC__)
#define __onload __attribute__((constructor))
#define __onexit __attribute__((destructor))
#else
#error "Currently only GCC is supported!"
#endif

int libservalctrl_init(void);
void libservalctrl_fini(void);

#endif /* _INIT_H */
