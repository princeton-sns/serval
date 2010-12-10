/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _INIT_H
#define _INIT_H

#if defined(__GNUC__) || defined(__BIONIC__)
#define __onload __attribute__((constructor))
#define __onexit __attribute__((destructor))
#else
#error "Currently only GCC is supported!"
#endif

#endif /* _INIT_H */
