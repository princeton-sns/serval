#include "splice.h"

ssize_t splice(int __fdin, off64_t *__offin, int __fdout,
	       off64_t *__offout, size_t __len,
	       unsigned int __flags)
{
	return (ssize_t)sys_splice(__fdin, __offin, __fdout, 
				   __offout, __len, __flags);
}
