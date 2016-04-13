/*
 * Configuration settings for the Allwinner A64 (sun50i) CPU
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#ifndef __CONFIG_H
#define __CONFIG_H

/*
 * A64 specific configuration
 */

#define CONFIG_SUNXI_USB_PHYS	1

#define COUNTER_FREQUENCY	CONFIG_TIMER_CLK_FREQ
#define GICD_BASE		0x1c81000
#define GICC_BASE		0x1c82000

#define CONFIG_SUNXI_DISPLAY

//#define CONFIG_SUNXI_LOGBUFFER
#define SUNXI_DISPLAY_FRAME_BUFFER_ADDR  (CONFIG_SYS_SDRAM_BASE + 0x06400000)
#define SUNXI_DISPLAY_FRAME_BUFFER_SIZE  0x01000000


/*
* define const value
*/
#define BOOT_USB_DETECT_DELAY_TIME       (1000)

#define  FW_BURN_UDISK_MIN_SIZE              (2 * 1024)



#define BOOT_MOD_ENTER_STANDBY           (0)
#define BOOT_MOD_EXIT_STANDBY            (1)

/*
 * Include common sunxi configuration where most the settings are
 */
#include <configs/sunxi-common.h>

#endif /* __CONFIG_H */
