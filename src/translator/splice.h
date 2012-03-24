#ifndef __SPLICE_H_
#define __SPLICE_H_

#if !defined(__arm__)
#error "splice only defined for ARM platform"
#endif

#include <sys/types.h>

/* Flags for SPLICE and VMSPLICE.  */
# define SPLICE_F_MOVE          1       /* Move pages instead of copying.  */
# define SPLICE_F_NONBLOCK      2       /* Don't block on the pipe splicing
                                           (but we may still block on the fd
                                           we splice from/to).  */
# define SPLICE_F_MORE          4       /* Expect more data.  */
# define SPLICE_F_GIFT          8       /* Pages passed in are a gift.  */


long sys_splice(int fd_in, loff_t *off_in,
		int fd_out, loff_t *off_out,
		size_t len, unsigned int flags);

extern ssize_t splice(int __fdin, off64_t *__offin, int __fdout,
		      off64_t *__offout, size_t __len,
		      unsigned int __flags);

#endif /* __SPLICE_H_ */
