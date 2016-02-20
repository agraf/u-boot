/*
 * (C) Copyright 2014 - 2015 Xilinx, Inc.
 * Michal Simek <michal.simek@xilinx.com>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <common.h>
#include <asm/arch/hardware.h>
#include <asm/arch/sys_proto.h>
#include <asm/io.h>

#define ZYNQ_SILICON_VER_MASK	0xF000
#define ZYNQ_SILICON_VER_SHIFT	12

DECLARE_GLOBAL_DATA_PTR;

static unsigned int zynqmp_get_silicon_version_secure(void)
{
	u32 ver;

	ver = readl(&csu_base->version);
	ver &= ZYNQMP_SILICON_VER_MASK;
	ver >>= ZYNQMP_SILICON_VER_SHIFT;

	return ver;
}

unsigned int zynqmp_get_silicon_version(void)
{
	if (current_el() == 3)
		return zynqmp_get_silicon_version_secure();

	gd->cpu_clk = get_tbclk();

	switch (gd->cpu_clk) {
	case 0 ... 1000000:
		return ZYNQMP_CSU_VERSION_VELOCE;
	case 50000000:
		return ZYNQMP_CSU_VERSION_QEMU;
	case 4000000:
		return ZYNQMP_CSU_VERSION_EP108;
	}

	return ZYNQMP_CSU_VERSION_SILICON;
}
