/*
 * (C) Copyright 2016
 * Alexander Graf <agraf@suse.de>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <common.h>
#include <linux/compiler.h>
#include <efi_loader.h>

#define ESR_EC_MASK	0xFC000000
#define ESR_EC_SHIFT	26
#define ESR_IL_MASK	0x02000000
#define ESR_IL_SHIFT	25
#define ESR_ISS_MASK	0x01FFFFFF
#define ESR_ISS_SHIFT	0

#define EC_DATA_SL	0x25

#define ISS_ISV_MASK	0x01000000
#define ISS_ISV_SHIFT	24
#define ISS_SAS_MASK	0x00C00000
#define ISS_SAS_SHIFT	22
#define ISS_SSE_MASK	0x00200000
#define ISS_SSE_SHIFT	21
#define ISS_SRT_MASK	0x000F0000
#define ISS_SRT_SHIFT	16
#define ISS_SF_MASK	0x00008000
#define ISS_SF_SHIFT	15
#define ISS_AR_MASK	0x00004000
#define ISS_AR_SHIFT	14
#define ISS_EA_MASK	0x00000200
#define ISS_EA_SHIFT	9
#define ISS_CM_MASK	0x00000100
#define ISS_CM_SHIFT	8
#define ISS_S1PTW_MASK	0x00000080
#define ISS_S1PTW_SHIFT	7
#define ISS_WNR_MASK	0x00000040
#define ISS_WNR_SHIFT	6
#define WNR_READ	0
#define WNR_WRITE	1
#define ISS_DFSC_MASK	0x0000003F
#define ISS_DFSC_SHIFT	0

#define ISV_VALID	1
#define DFSC_ALIGN	0x21

ulong read_far(void);
int do_unaligned_data(struct pt_regs *pt_regs, unsigned int esr);

static inline int32_t sextract32(uint32_t value, int start, int length)
{
	return ((int32_t)(value << (32 - length - start))) >> (32 - length);
}

static inline uint32_t extract32(uint32_t value, int start, int length)
{
	return (value >> start) & (~0U >> (32 - length));
}

static int insn_iss_ldst(uint32_t insn, int iss, int *wb_reg, ulong *wb_val)
{
	int rt = extract32(insn, 0, 5);
	int rn = extract32(insn, 5, 5);
	int idx = extract32(insn, 10, 2);
	int imm9 = sextract32(insn, 12, 9);
	int opc = extract32(insn, 22, 2);
	int size = extract32(insn, 30, 2);
	bool is_signed = false;
	bool is_store = false;
	bool is_extended = false;
	bool is_vector = extract32(insn, 26, 1);

	switch (extract32(insn, 25, 4)) {
	case 0x4:
	case 0x6:
	case 0xc:
	case 0xe:	  /* Loads and stores */
		break;
        default:
		return iss;
	}

	switch (extract32(insn, 24, 6)) {
	case 0x38: case 0x39:
	case 0x3c: case 0x3d: /* Load/store register (all forms) */
		break;
	default:
		return iss;
	}

	switch (extract32(insn, 24, 2)) {
	case 0:
		if (extract32(insn, 21, 1) != 1 &&
		    extract32(insn, 10, 2) != 2) {
			/* Write back */
			if (idx & 1) {
				ulong far = read_far();
				*wb_reg = rn;
				*wb_val = (idx & 2) ? far : far + imm9;
				break;
			}
		}
		break;
	case 1:
		break;
	default:
		return iss;
	}

	if (is_vector) {
		return iss;
	}

	is_store = (opc == 0);
	is_signed = extract32(opc, 1, 1);
	is_extended = (size < 3) && extract32(opc, 0, 1);

	iss |= ISS_ISV_MASK;
	iss |= size << ISS_SAS_SHIFT;
	iss |= (is_extended && is_signed) ? ISS_SSE_MASK : 0;
	iss |= rt << ISS_SRT_SHIFT;
	iss |= ISS_SF_MASK;
	iss |= is_store ? ISS_WNR_MASK : 0;

	return iss;
}

static void do_unaligned_access(struct pt_regs *pt_regs, int wnr, int rt,
				ulong addr, int sas, int sse)
{
	void *rr = (void*)&pt_regs->regs[rt];
	void *r = rr;
	int len = 1 << sas;

#if __BYTE_ORDER == __BIG_ENDIAN
	/* On BE registers get filled from the back */
	r = (char*)r + (8 - len);
#endif

	if (wnr == WNR_READ) {
		/* Read with zero pad */
		pt_regs->regs[rt] = 0;
		memcpy(r, (void*)addr, len);

		/* Sign extend */
		if (sse) {
			switch (sas) {
			case 0: *(long*)rr = *(char*)r; break;
			case 1: *(long*)rr = *(short*)r; break;
			case 2: *(long*)rr = *(int*)r; break;
			}
		}
	} else if (wnr == WNR_WRITE) {
		memcpy((void*)addr, r, len);
	}
}

static int do_ldst_pair(u32 insn, struct pt_regs *pt_regs)
{
	int rt = extract32(insn, 0, 5);
	int rn = extract32(insn, 5, 5);
	int rt2 = extract32(insn, 10, 5);
	int index = extract32(insn, 23, 2);
	bool is_vector = extract32(insn, 26, 1);
	bool is_load = extract32(insn, 22, 1);
	int opc = extract32(insn, 30, 2);
	ulong far = read_far();
	ulong old_far = far;
	int wnr = is_load ? WNR_READ : WNR_WRITE;

	bool is_signed = extract32(opc, 0, 1);
	bool postindex = false;
	bool wback = false;

	int size = 2 + extract32(opc, 1, 1);

	switch (extract32(insn, 25, 4)) {
	case 0x4:
	case 0x6:
	case 0xc:
	case 0xe:	  /* Loads and stores */
		break;
        default:
		return -1;
	}

	switch (extract32(insn, 24, 6)) {
	case 0x28: case 0x29:
	case 0x2c: case 0x2d: /* Load/store pair (all forms) */
		break;
	default:
		return -1;
	}

	if (is_vector)
		return -1;

	switch (index) {
	case 1: /* post-index */
		postindex = true;
		wback = true;
		break;
	case 0: /* signed offset with "non-temporal" hint. */
		postindex = false;
		break;
	case 2: /* signed offset, rn not updated */
		postindex = false;
		break;
	case 3: /* pre-index */
		postindex = false;
		wback = true;
		break;
	}

	do_unaligned_access(pt_regs, wnr, rt, far, size, is_signed);
	far += 1 << size;
	do_unaligned_access(pt_regs, wnr, rt2, far, size, is_signed);
	far += 1 << size;

	if (wback)
		pt_regs->regs[rn] = postindex ? far : old_far;

	return 0;
}

int do_unaligned_data(struct pt_regs *pt_regs, unsigned int esr)
{
	int insn = *(u32*)(void*)pt_regs->elr;
	int ec = (esr & ESR_EC_MASK) >> ESR_EC_SHIFT;
	int iss = (esr & ESR_ISS_MASK) >> ESR_ISS_SHIFT;
	int isv = (iss & ISS_ISV_MASK) >> ISS_ISV_SHIFT;
	int dfsc = (iss & ISS_DFSC_MASK) >> ISS_DFSC_SHIFT;
	int sas, sse, srt, sf, ar, cm, s1ptw, wnr;
	int wb_reg = -1;
	ulong wb_val;

	/* Check whether we have an alignment fault */
	if ((ec != EC_DATA_SL) || (dfsc != DFSC_ALIGN))
		return -1;

	/* Fix up instruction decoding */
	if (!isv) {
		iss = insn_iss_ldst(insn, iss, &wb_reg, &wb_val);
	}

	isv = (iss & ISS_ISV_MASK) >> ISS_ISV_SHIFT;
	sas = (iss & ISS_SAS_MASK) >> ISS_SAS_SHIFT;
	sse = (iss & ISS_SSE_MASK) >> ISS_SSE_SHIFT;
	srt = (iss & ISS_SRT_MASK) >> ISS_SRT_SHIFT;
	sf = (iss & ISS_SF_MASK) >> ISS_SF_SHIFT;
	ar = (iss & ISS_AR_MASK) >> ISS_AR_SHIFT;
	cm = (iss & ISS_CM_MASK) >> ISS_CM_SHIFT;
	s1ptw = (iss & ISS_S1PTW_MASK) >> ISS_S1PTW_SHIFT;
	wnr = (iss & ISS_WNR_MASK) >> ISS_WNR_SHIFT;

	/* Check whether we have an easily fixable alignment fault */
	if (isv && sf && !ar && !cm && !s1ptw) {
		ulong far = read_far();

		do_unaligned_access(pt_regs, wnr, srt, far, sas, sse);

		/* Jump across the offending instruction */
		pt_regs->elr += 4;

		/* Do writebacks if required */
		if (wb_reg != -1)
			pt_regs->regs[wb_reg] = wb_val;

		/* And return from the exception */
		return 0;
	}

	if (!do_ldst_pair(insn, pt_regs)) {
		pt_regs->elr += 4;
		return 0;
	}

	/* Couldn't fix it, panic */
	printf("Alignment handler couldn't decode insn %08x\n",
	       *(u32*)(void*)pt_regs->elr);
	return -1;
}
