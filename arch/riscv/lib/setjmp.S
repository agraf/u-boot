/*
 * (C) 2018 Alexander Graf <agraf@suse.de>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <config.h>
#include <linux/linkage.h>

.pushsection .text.setjmp, "ax"
ENTRY(setjmp)
	/* Preserve all callee-saved registers and the SP */
	sd s0, 0(a0)
	sd s1, 8(a0)
	sd s2, 16(a0)
	sd s3, 24(a0)
	sd s4, 32(a0)
	sd s5, 40(a0)
	sd s6, 48(a0)
	sd s7, 56(a0)
	sd s8, 64(a0)
	sd s9, 72(a0)
	sd s10, 80(a0)
	sd s11, 88(a0)
	li  a0, 0
	ret
ENDPROC(setjmp)
.popsection

.pushsection .text.longjmp, "ax"
ENTRY(longjmp)
	ld s0, 0(a0)
	ld s1, 8(a0)
	ld s2, 16(a0)
	ld s3, 24(a0)
	ld s4, 32(a0)
	ld s5, 40(a0)
	ld s6, 48(a0)
	ld s7, 56(a0)
	ld s8, 64(a0)
	ld s9, 72(a0)
	ld s10, 80(a0)
	ld s11, 88(a0)

	/* Move the return value in place, but return 1 if passed 0. */
	beq a1, zero, longjmp_1
	mv a0, a1
	ret

	longjmp_1:
	li a0, 1
	ret
ENDPROC(longjmp)
.popsection
