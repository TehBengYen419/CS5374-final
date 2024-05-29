/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>

	.code64
	.section .text, "ax"

SYM_FUNC_START(ekcfi_tramp_ret_64)

	/* Save registers */
	pushq %rdi
	pushq %rsi
	pushq %rdx
	pushq %rcx
	pushq %r8
	pushq %r9
	pushq %r10
	pushq %r11
	pushq %rax

	/* Call ekcfi_check(caller, callee) 
	   stack: |  ra of function   |
	          | ra of ekcfi_tramp |
	*/
	movq 0x50(%rsp), %rdi
	movq 0x48(%rsp), %rsi
	movl $1, %edx
	call ekcfi_check

	/* Restore registers */
	popq %rax
	popq %r11
	popq %r10
	popq %r9
	popq %r8
	popq %rcx
	popq %rdx
	popq %rsi
	popq %rdi

	// Check is done, we reduce double return
	add $0x8, %rsp
	RET

SYM_FUNC_END(ekcfi_tramp_ret_64)
