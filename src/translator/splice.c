#include "splice.h"
#include <android/api-level.h>

ssize_t splice(int __fdin, off64_t *__offin, int __fdout,
	       off64_t *__offout, size_t __len,
	       unsigned int __flags)
{
	return (ssize_t)sys_splice(__fdin, __offin, __fdout, 
				   __offout, __len, __flags);
}

/* Android API level greater than 10 does not export the
 * __set_syscall_errno function any longer. Therefore, we include our
 * own here to be compatible with all versions. This code is taken
 * straight from the Bionic library. 
*/
int __translator_set_syscall_errno(int n)
{
        /* some syscalls, mmap() for example, have valid return
        ** values that are "negative".  Since errno values are not
        ** greater than 131 on Linux, we will just consider
        ** anything significantly out of range as not-an-error
        */
    if(n > -256) {
        return __set_errno(-n) ;
    } else {
        return n;
    }
}

