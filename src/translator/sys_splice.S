#include <machine/asm.h>
#include <sys/linux-syscalls.h>

#define __NR_splice (__NR_SYSCALL_BASE + 340)

	.text
	.type sys_splice, #function
	.globl sys_splice
	.align 4
	.fnstart
	
sys_splice:
	mov     ip, sp
	.save   {r4, r5, r6, r7}
	stmfd   sp!, {r4, r5, r6, r7}
	ldmfd   ip, {r4, r5, r6}
	ldr     r7, =__NR_splice
	swi     #0
	ldmfd   sp!, {r4, r5, r6, r7}
	movs    r0, r0
	bxpl    lr
	b       __translator_set_syscall_errno
	.fnend
