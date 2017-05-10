#include <common.h>
#include <asm/io.h>
#include <fdtdec.h>
#include <fpga.h>
#include <mmc.h>
#include <netdev.h>
#include <zynqpl.h>
#include <asm/arch/hardware.h>
#include <asm/arch/sys_proto.h>

#define GPIO_CTRL_BASE		0xE000A000
#define SLCR_LOCKSTA		(ZYNQ_SYS_CTRL_BASEADDR + 0x0000000C)
#define I2C_RST_CTRL		(ZYNQ_SYS_CTRL_BASEADDR + 0x00000224)

struct gpio_ctrl_s {
	u32 mask_data_0_l;
	u32 mask_data_0_m;
	u32 mask_data_1_l;
	u32 mask_data_1_m;
	u32 mask_data_2_l;
	u32 mask_data_2_m;
	u32 mask_data_3_l;
	u32 mask_data_3_m;

	u32 reserved1[8];

	u32 data_0;
	u32 data_1;
	u32 data_2;
	u32 data_3;

	u32 reserved2[4];

	u32 data_0_ro;
	u32 data_1_ro;
	u32 data_2_ro;
	u32 data_3_ro;

	u32 reserved3[101];

	u32 dirm_0;
	u32 oen_0;
	u32 int_mask_0;
	u32 int_en_0;
	u32 int_dis_0;
	u32 int_stat_0;
	u32 int_type_0;
	u32 int_pol_0;
	u32 int_any_0;

	u32 reserved4[7];

	u32 dirm_1;
	u32 oen_1;
	u32 int_mask_1;
	u32 int_en_1;
	u32 int_dis_1;
	u32 int_stat_1;
	u32 int_type_1;
    u32 int_pol_1;
    u32 int_any_1;

	u32 reserved5[7];

    u32 dirm_2;
    u32 oen_2;
    u32 int_mask_2;
    u32 int_en_2;
    u32 int_dis_2;
    u32 int_stat_2;
    u32 int_type_2;
    u32 int_pol_2;
    u32 int_any_2;

	u32 reserved6[7];

    u32 dirm_3;
    u32 oen_3;
    u32 int_mask_3;
    u32 int_en_3;
    u32 int_dis_3;
    u32 int_stat_3;
    u32 int_type_3;
    u32 int_pol_3;
    u32 int_any_3;
};

#define gpio_base	((struct gpio_ctrl_s *)GPIO_CTRL_BASE)

#define GPIO_OUTPUT_1V8_CONFIG	( (1 << 13) | /* disable rcvr */     \
								  (0 << 12) | /* disable pullup */  \
								  (1 << 9)  | /* io voltage 1.8v */ \
								  (0 << 8)  | /* slow CMOS edge */  \
								  (0 << 1)  | /* L0_SEL/L1_SEL/L2_SEL/L3_SEL set to 0 to GPIO MUX */  \
								  (0 << 0)    /* disable tri-state */ \
								)

#define GPIO_OUTPUT_3V3_CONFIG  ( (1 << 13) | /* disable rcvr */    \
                                  (0 << 12) | /* disable pullup */  \
                                  (3 << 9)  | /* io voltage 3.3v */ \
                                  (0 << 8)  | /* slow CMOS edge */  \
                                  (0 << 1)  | /* L0_SEL/L1_SEL/L2_SEL/L3_SEL set to 0 to GPIO MUX */ \
                                  (0 << 0)    /* disable tri-state */ \
								)
								
#define MAX_GPIO		54
#define GPIO_BANK0      0
#define GPIO_BANK1      1
#define GET_GPIO_BANK(gpio)		(gpio<32? GPIO_BANK0: GPIO_BANK1)
#define GET_GPIO_PIN(gpio)		(gpio % 32)

/* MIO51 */
#define MYIR_RESET_PIN	51

#define is_slcr_lock()	(readl(SLCR_LOCKSTA)&0x1)

static void gpio_set_value(u32 gpio, u32 value)
{
    u32 regval;
	u32 *reg;
	u32 pin;

	value = !!value;
	pin = GET_GPIO_PIN(gpio);

	switch (GET_GPIO_BANK(gpio)) {
		case GPIO_BANK0:
			if (pin < 16) {
				reg = &gpio_base->mask_data_0_l;
			} else {
				reg = &gpio_base->mask_data_0_m;
			}
			break;
		case GPIO_BANK1:
            if (pin < 16) {
                reg = &gpio_base->mask_data_1_l;
            } else {
                reg = &gpio_base->mask_data_1_m;
            }
			break;
		default:
			printf("Invalid GPIO BANK %d (should be in range of [0,1])\n",
				GET_GPIO_BANK(gpio));
			return;
	}

	pin %= 16;

    /* set MASK value */
    regval = (~(1 << pin)) << 16;

    /* set DATA value */
    regval |= (value << pin);

    /* Write to MASK_DATA_X_X register */
    writel(regval, reg);
}

#if 0
static u32 gpio_get_value(u32 gpio)
{
	u32 value = 0;

	if (gpio >= MAX_GPIO) {
		printf("gpio %d out of range (< %d)!\n", gpio, MAX_GPIO);
		return 0;
	}

	switch(GET_GPIO_BANK(gpio)) {
		case GPIO_BANK0:
			value = readl(&gpio_base->data_0_ro) & (1<<GET_GPIO_PIN(gpio));
			break;
		case GPIO_BANK1:
			value = readl(&gpio_base->data_1_ro) & (1<<GET_GPIO_PIN(gpio));
			break;
	}

	return !!value;
}
#endif

static void gpio_set_output(u32 gpio, u32 value)
{
	u32 bank = GET_GPIO_BANK(gpio);
	u32 pin = GET_GPIO_PIN(gpio);
	u32 *reg_dirm, *reg_oen;
	u32 slcr_locksta;
	
	if (gpio >= MAX_GPIO) {
		printf("gpio out of range (should be < %d)!\n", MAX_GPIO);
		return ;
	}

	slcr_locksta = is_slcr_lock();
	if (slcr_locksta)
		zynq_slcr_unlock();

	/* set pinmux to GPIO */
	writel(GPIO_OUTPUT_1V8_CONFIG, &slcr_base->mio_pin[gpio]);

	if (slcr_locksta)
		zynq_slcr_lock();
		
	/* set GPIO to output */
	switch (bank) {
		case GPIO_BANK0:
			reg_dirm = &gpio_base->dirm_0;
			reg_oen = &gpio_base->oen_0;
			break;
		case GPIO_BANK1:
			reg_dirm = &gpio_base->dirm_1;
            reg_oen = &gpio_base->oen_1;
			break;
	}

	writel(readl(reg_dirm) | (1 << pin), reg_dirm);
	writel(readl(reg_oen) | (1 << pin), reg_oen);
	
	/* set to required value */
	gpio_set_value(gpio, value);
}

/* 
 * Init MIO51(bank1) for reset control pin
 */
static void gpio_init(void)
{
	gpio_set_output(MYIR_RESET_PIN, 0);
}

/*
 * Reset I2C0 and I2C1 controller
 */
static void reset_i2c(void)
{
	volatile int i = 0;
	u32 slcr_locksta;

	slcr_locksta = is_slcr_lock();
	if (slcr_locksta)
		zynq_slcr_unlock();
	
	writel(0x3, I2C_RST_CTRL);
	for (i = 0; i < 100; i++);
	writel(0x0, I2C_RST_CTRL);


	if (slcr_locksta)
		zynq_slcr_lock();
}

/*
 * Z-turn (MYS-XC7Z010) board init function.
 */
void myir_init(void);
void myir_init(void)
{
	printf("%s\n", __func__);

	gpio_init();

//	printf(">> get gpio %d: %d\n", MYIR_RESET_PIN, gpio_get_value(MYIR_RESET_PIN));

	/* Reset Ethernet PHY and USB PHY here */
	gpio_set_value(MYIR_RESET_PIN, 0);
	mdelay(100);
	gpio_set_value(MYIR_RESET_PIN, 1);
	#if 0
	mdelay(50); /* bootdelay = 0Ê±,ÑÓÊ±50msÍø¿ÚÐ¾Æ¬ÓÐÊ±¸´Î»²»Õý³£ */
	#else
	mdelay(300);
	#endif

//    printf("<< get gpio %d: %d\n", MYIR_RESET_PIN, gpio_get_value(MYIR_RESET_PIN));

	/*
	 * Reset i2c controller after driving MYIR_RESET_PIN
	 * It seems to be a hardware bug of zynq.
	 */
	reset_i2c();
}

