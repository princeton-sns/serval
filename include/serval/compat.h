#ifndef __COMPAT_H__
#define __COMPAT_H__
/*
  compat.h: place to put macros and function definitions in order to
  provide compatibility with various kernel versions. 
*/

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37))
#define route_dst(rt) (&(rt)->u.dst)
#else
#define route_dst(rt) (&(rt)->dst)
#endif /* LINUX_VERSION_CODE */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0))
#define dma_async_issue_pending(a)		\
  dma_async_memcpy_issue_pending(a)
#define dma_async_is_tx_complete(a, b, c, d)	\
  dma_async_memcpy_complete(a, b, c, d)
#endif /* LINUX_VERSION_CODE */

#endif /* __COMPAT_H__ */
