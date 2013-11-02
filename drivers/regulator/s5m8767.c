/*
 * s5m8767.c
 *
 * Copyright (c) 2011 Samsung Electronics Co., Ltd
 *              http://www.samsung.com
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 *
 */

#include <linux/bug.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/gpio.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/regulator/driver.h>
#include <linux/regulator/machine.h>
#include <linux/mfd/s5m87xx/s5m-core.h>
#include <linux/mfd/s5m87xx/s5m-pmic.h>

// SEMCO_A31_PWDN_CONTROL
#include <plat/gpio-cfg.h>
#include <mach/regs-gpio.h>
#include <mach/gpio.h>

// Cellon add start, Ted Shi, 2012/08/09, for porting bcm4330 wifi/bt
#define BCM_BT_WIFI_32K 0x4
// Cellon add end, Ted Shi, 2012/08/09


//Cellon add start,Fengying Zhang,2012/08/16,for gps_32K support enable
#define Cellon_cp_32khz 1
//Cellon add end,Fengying Zhang,2012/08/16

//Cellon add start,Terry Huang,2012/11/02,for no sound in calling when being in system suspend
extern int tc4_get_call_flg(void);
//Cellon add end,Terry Huang ,2012/11/02

struct s5m8767_info {
	struct device *dev;
	struct s5m87xx_dev *iodev;
	int num_regulators;
	struct regulator_dev **rdev;

	int ramp_delay;
	bool buck2_ramp;
	bool buck3_ramp;
	bool buck4_ramp;

	bool buck2_gpiodvs;
	bool buck3_gpiodvs;
	bool buck4_gpiodvs;
	u8 buck2_vol[8];
	u8 buck3_vol[8];
	u8 buck4_vol[8];
	int buck_gpios[3];
	int buck_gpioindex;
};

struct s5m_voltage_desc {
	int max;
	int min;
	int step;
};

static const struct s5m_voltage_desc buck_voltage_val1 = {
	.max = 2225000,
	.min =  650000,
	.step =   6250,
};

static const struct s5m_voltage_desc buck_voltage_val2 = {
	.max = 1600000,
	.min =  600000,
	.step =   6250,
};

static const struct s5m_voltage_desc buck_voltage_val3 = {
	.max = 3000000,
	.min =  750000,
	.step =  12500,
};

static const struct s5m_voltage_desc ldo_voltage_val1 = {
	.max = 3950000,
	.min =  800000,
	.step =  50000,
};

static const struct s5m_voltage_desc ldo_voltage_val2 = {
	.max = 2375000,
	.min =  800000,
	.step =  25000,
};

static const struct s5m_voltage_desc *reg_voltage_map[] = {
	[S5M8767_LDO1] = &ldo_voltage_val2,
	[S5M8767_LDO2] = &ldo_voltage_val2,
	[S5M8767_LDO3] = &ldo_voltage_val1,
	[S5M8767_LDO4] = &ldo_voltage_val1,
	[S5M8767_LDO5] = &ldo_voltage_val1,
	[S5M8767_LDO6] = &ldo_voltage_val2,
	[S5M8767_LDO7] = &ldo_voltage_val2,
	[S5M8767_LDO8] = &ldo_voltage_val2,
	[S5M8767_LDO9] = &ldo_voltage_val1,
	[S5M8767_LDO10] = &ldo_voltage_val1,
	[S5M8767_LDO11] = &ldo_voltage_val1,
	[S5M8767_LDO12] = &ldo_voltage_val1,
	[S5M8767_LDO13] = &ldo_voltage_val1,
	[S5M8767_LDO14] = &ldo_voltage_val1,
	[S5M8767_LDO15] = &ldo_voltage_val2,
	[S5M8767_LDO16] = &ldo_voltage_val1,
	[S5M8767_LDO17] = &ldo_voltage_val1,
	[S5M8767_LDO18] = &ldo_voltage_val1,
	[S5M8767_LDO19] = &ldo_voltage_val1,
	[S5M8767_LDO20] = &ldo_voltage_val1,
	[S5M8767_LDO21] = &ldo_voltage_val1,
	[S5M8767_LDO22] = &ldo_voltage_val1,
	[S5M8767_LDO23] = &ldo_voltage_val1,
	[S5M8767_LDO24] = &ldo_voltage_val1,
	[S5M8767_LDO25] = &ldo_voltage_val1,
	[S5M8767_LDO26] = &ldo_voltage_val1,
	[S5M8767_LDO27] = &ldo_voltage_val1,
	[S5M8767_LDO28] = &ldo_voltage_val1,
	[S5M8767_BUCK1] = &buck_voltage_val1,
	[S5M8767_BUCK2] = &buck_voltage_val2,
	[S5M8767_BUCK3] = &buck_voltage_val2,
	[S5M8767_BUCK4] = &buck_voltage_val2,
	[S5M8767_BUCK5] = &buck_voltage_val1,
	[S5M8767_BUCK6] = &buck_voltage_val1,
	[S5M8767_BUCK7] = NULL,
	[S5M8767_BUCK8] = NULL,
	[S5M8767_BUCK9] = &buck_voltage_val3,
};

static inline int s5m8767_get_reg_id(struct regulator_dev *rdev)
{
	return rdev_get_id(rdev);
}

static int s5m8767_list_voltage(struct regulator_dev *rdev,
				unsigned int selector)
{
	const struct s5m_voltage_desc *desc;
	int reg_id = s5m8767_get_reg_id(rdev);
	int val;

	if (reg_id >= ARRAY_SIZE(reg_voltage_map) || reg_id < 0)
		return -EINVAL;

	desc = reg_voltage_map[reg_id];
	if (desc == NULL)
		return -EINVAL;

	val = desc->min + desc->step * selector;
	if (val > desc->max)
		return -EINVAL;

	return val;
}
static int s5m8767_get_disable_val(struct regulator_dev *rdev)
{

	int reg_id = s5m8767_get_reg_id(rdev);
	int ret = 0;
	switch (reg_id) {
	case S5M8767_LDO2:
	
	case S5M8767_LDO6:
	case S5M8767_LDO7:
	//case S5M8767_LDO9: //Robin, ldo9 is for lcd,it's better to power on/off in lcd driver..
	//case S5M8767_LDO13:
	case S5M8767_LDO11:// ... S5M8767_LDO12://zhangdong, reduce sleep current
	case S5M8767_LDO14 ... S5M8767_LDO15:
	case S5M8767_LDO17:
		 ret = 1;
		break;
        case S5M8767_LDO1:
        case S5M8767_BUCK5: 
	case S5M8767_LDO13:
	case S5M8767_LDO18:	
		ret = 3;
		break;
	case S5M8767_LDO4:
	//case S5M8767_LDO18:
	case S5M8767_LDO23:
	case S5M8767_LDO5:
		 ret = 2;		
		break;
	case S5M8767_BUCK1 ... S5M8767_BUCK4:
		ret = 1;
		break;
	case S5M8767_BUCK9:
		ret = 1;
		break;
	default:
		return ret;
	}

	return ret;

}
static int s5m8767_get_register(struct regulator_dev *rdev, int *reg)
{
	int reg_id = s5m8767_get_reg_id(rdev);

	switch (reg_id) {
	case S5M8767_LDO1 ... S5M8767_LDO2:
		*reg = S5M8767_REG_LDO1CTRL + (reg_id - S5M8767_LDO1);
		break;
	case S5M8767_LDO3 ... S5M8767_LDO28:
		*reg = S5M8767_REG_LDO3CTRL + (reg_id - S5M8767_LDO3);
		break;
	case S5M8767_BUCK1:
		*reg = S5M8767_REG_BUCK1CTRL1;
		break;
	case S5M8767_BUCK2 ... S5M8767_BUCK4:
		*reg = S5M8767_REG_BUCK2CTRL + (reg_id - S5M8767_BUCK2) * 9;
		break;
	case S5M8767_BUCK5:
		*reg = S5M8767_REG_BUCK5CTRL1;
		break;
	case S5M8767_BUCK6 ... S5M8767_BUCK9:
		*reg = S5M8767_REG_BUCK6CTRL1 + (reg_id - S5M8767_BUCK6) * 2;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int s5m8767_reg_is_enabled(struct regulator_dev *rdev)
{
	struct s5m8767_info *s5m8767 = rdev_get_drvdata(rdev);
	struct i2c_client *i2c = s5m8767->iodev->i2c;
	int ret, reg;
	int mask=0xc0, pattern=0xc0;
	u8 val;

	ret = s5m8767_get_register(rdev, &reg);
	if (ret == -EINVAL)
		return 1;
	else if (ret)
		return ret;

	ret = s5m_reg_read(i2c, reg, &val);
	if (ret)
		return ret;

	return (val & mask) == pattern;
}

static int s5m8767_reg_enable(struct regulator_dev *rdev)
{
	struct s5m8767_info *s5m8767 = rdev_get_drvdata(rdev);
	struct i2c_client *i2c = s5m8767->iodev->i2c;
	int ret, reg;
	int mask=0xc0, pattern=0xc0;

	ret = s5m8767_get_register(rdev, &reg);
	if (ret)
		return ret;

	ret = s5m8767_get_disable_val(rdev);

	if(ret == 1)
		pattern = 0x40;
	else if(ret == 2)
		pattern = 0x0;
	else if(ret == 3){
		pattern = 0x80;
//Cellon modify start,Terry Huang,2012/11/02,for no sound in calling when being in system suspend
		//pattern = 0xc0;
//Cellon add end,Terry Huang ,2012/11/02
	}
	
	return s5m_reg_update(i2c, reg, pattern, mask);
}

static int s5m8767_reg_disable(struct regulator_dev *rdev)
{
	struct s5m8767_info *s5m8767 = rdev_get_drvdata(rdev);
	struct i2c_client *i2c = s5m8767->iodev->i2c;
	int ret, reg;
	int  mask=0xc0, pattern=0xc0;
	ret = s5m8767_get_register(rdev, &reg);
	if (ret)
		return ret;
	
	ret = s5m8767_get_disable_val(rdev);

	if(ret == 2)
		ret = 0;
	
	return s5m_reg_update(i2c, reg, (~pattern) | (ret <<6), mask);
}

static int s5m8767_get_voltage_register(struct regulator_dev *rdev, int *_reg)
{
	int reg_id = s5m8767_get_reg_id(rdev);
	int reg;

	switch (reg_id) {
	case S5M8767_LDO1 ... S5M8767_LDO2:
		reg = S5M8767_REG_LDO1CTRL + (reg_id - S5M8767_LDO1);
		break;
	case S5M8767_LDO3 ... S5M8767_LDO28:
		reg = S5M8767_REG_LDO3CTRL + (reg_id - S5M8767_LDO3);
		break;
	case S5M8767_BUCK1:
		reg = S5M8767_REG_BUCK1CTRL2;
		break;
	case S5M8767_BUCK2:
		reg = S5M8767_REG_BUCK2DVS1;
		break;
	case S5M8767_BUCK3:
		reg = S5M8767_REG_BUCK3DVS1;
		break;
	case S5M8767_BUCK4:
		reg = S5M8767_REG_BUCK4DVS1;
		break;
	case S5M8767_BUCK5:
		reg = S5M8767_REG_BUCK5CTRL2;
		break;
	case S5M8767_BUCK6 ... S5M8767_BUCK9:
		reg = S5M8767_REG_BUCK6CTRL2 + (reg_id - S5M8767_BUCK6) * 2;
		break;
	default:
		return -EINVAL;
	}

	*_reg = reg;

	return 0;
}

static int s5m8767_get_voltage(struct regulator_dev *rdev)
{
	struct s5m8767_info *s5m8767 = rdev_get_drvdata(rdev);
	struct i2c_client *i2c = s5m8767->iodev->i2c;
	int reg, mask=0xff, ret;
	int reg_id = s5m8767_get_reg_id(rdev);
	u8 val;

	ret = s5m8767_get_voltage_register(rdev, &reg);
	if (ret)
		return ret;

	switch (reg_id) {
	case S5M8767_LDO1 ... S5M8767_LDO28:
		mask = 0x3f;
		break;
	case S5M8767_BUCK2:
		if(s5m8767->buck2_gpiodvs)
			reg += s5m8767->buck_gpioindex;
		break;
	case S5M8767_BUCK3:
		if(s5m8767->buck3_gpiodvs)
			reg += s5m8767->buck_gpioindex;
		break;
	case S5M8767_BUCK4:
		if(s5m8767->buck4_gpiodvs)
			reg += s5m8767->buck_gpioindex;
		break;
	}

	ret = s5m_reg_read(i2c, reg, &val);
	if (ret)
		return ret;

	val &= mask;

	if (rdev->desc && rdev->desc->ops && rdev->desc->ops->list_voltage)
		return rdev->desc->ops->list_voltage(rdev, val);

	return s5m8767_list_voltage(rdev, val);
}

static inline int s5m8767_convert_voltage(
		const struct s5m_voltage_desc *desc,
		int min_vol, int max_vol)
{
	int i = 0, j = 0;

	if (desc == NULL)
		return -EINVAL;

	if (max_vol < desc->min || min_vol > desc->max)
		return -EINVAL;

	j = (min_vol - desc->min) / desc->step;

	if (desc->min + desc->step * i > max_vol)
		return -EINVAL;

	return j;
}

static int s5m8767_set_voltage(struct regulator_dev *rdev,
				int min_uV, int max_uV, unsigned *selector)
{
	struct s5m8767_info *s5m8767 = rdev_get_drvdata(rdev);
	struct i2c_client *i2c = s5m8767->iodev->i2c;
	int min_vol = min_uV, max_vol = max_uV;
	const struct s5m_voltage_desc *desc;
	int reg_id = s5m8767_get_reg_id(rdev);
	int reg, mask, ret;
	int i;
	u8 val;

	switch (reg_id) {
	case S5M8767_LDO1 ... S5M8767_LDO28:
		mask = 0x3f;
		break;
	case S5M8767_BUCK1 ... S5M8767_BUCK6:
		mask = 0xff;
		break;
	case S5M8767_BUCK7 ... S5M8767_BUCK8:
		return -EINVAL;
	case S5M8767_BUCK9:
		mask = 0xff;
		break;
	default:
		return -EINVAL;
	}

	desc = reg_voltage_map[reg_id];

	i = s5m8767_convert_voltage(desc, min_vol, max_vol);
	if (i < 0)
		return i;

	ret = s5m8767_get_voltage_register(rdev, &reg);
	if (ret)
		return ret;

	s5m_reg_read(i2c, reg, &val);
	val = val & mask;

	ret = s5m_reg_update(i2c, reg, i, mask);
	*selector = i;

	if (val < i){
		udelay(DIV_ROUND_UP(desc->step * (i - val),
			s5m8767->ramp_delay));
	}
	return ret;
}

static inline void s5m8767_set_high(struct s5m8767_info *s5m8767)
{
	int temp_index = s5m8767->buck_gpioindex;

	gpio_set_value(s5m8767->buck_gpios[0], (temp_index >> 2) & 0x1);
	gpio_set_value(s5m8767->buck_gpios[1], (temp_index >> 1) & 0x1);
	gpio_set_value(s5m8767->buck_gpios[2], temp_index & 0x1);
}

static inline void s5m8767_set_low(struct s5m8767_info *s5m8767)
{
	int temp_index = s5m8767->buck_gpioindex;

	gpio_set_value(s5m8767->buck_gpios[2], temp_index & 0x1);
	gpio_set_value(s5m8767->buck_gpios[1], (temp_index >> 1) & 0x1);
	gpio_set_value(s5m8767->buck_gpios[0], (temp_index >> 2) & 0x1);
}

static int s5m8767_set_voltage_buck(struct regulator_dev *rdev,
				    int min_uV, int max_uV, unsigned *selector)
{
	struct s5m8767_info *s5m8767 = rdev_get_drvdata(rdev);
	int reg_id = s5m8767_get_reg_id(rdev);
	const struct s5m_voltage_desc *desc;
	int new_val, old_val, i = 0;
	int min_vol = min_uV, max_vol = max_uV;

	if (reg_id < S5M8767_BUCK1 || reg_id > S5M8767_BUCK6)
		return -EINVAL;

	switch (reg_id) {
	case S5M8767_BUCK1:
		return s5m8767_set_voltage(rdev, min_uV, max_uV, selector);
	case S5M8767_BUCK2 ... S5M8767_BUCK4:
		break;
	case S5M8767_BUCK5 ... S5M8767_BUCK6:
		return s5m8767_set_voltage(rdev, min_uV, max_uV, selector);
	case S5M8767_BUCK9:
		return s5m8767_set_voltage(rdev, min_uV, max_uV, selector);
	}

	desc = reg_voltage_map[reg_id];
	new_val = s5m8767_convert_voltage(desc, min_vol, max_vol);
	if (new_val < 0)
		return new_val;

	switch (reg_id) {
	case S5M8767_BUCK2:
		if(s5m8767->buck2_gpiodvs){
			while ( s5m8767->buck2_vol[i] != new_val )
				i++;
		}
		else
			return s5m8767_set_voltage(rdev, min_uV, max_uV, selector);
		break;
	case S5M8767_BUCK3:
		if(s5m8767->buck3_gpiodvs){
			while ( s5m8767->buck3_vol[i] != new_val )
				i++;
		} else
			return s5m8767_set_voltage(rdev, min_uV, max_uV, selector);
		break;
	case S5M8767_BUCK4:
		if(s5m8767->buck3_gpiodvs){
			while ( s5m8767->buck4_vol[i] != new_val )
				i++;
		} else
			return s5m8767_set_voltage(rdev, min_uV, max_uV, selector);
		break;
	}

	old_val = s5m8767->buck_gpioindex;
	s5m8767->buck_gpioindex = i;

	if ( i > old_val)
		s5m8767_set_high(s5m8767);
	else
		s5m8767_set_low(s5m8767);

	*selector = new_val;
	return 0;
}

static int s5m8767_reg_enable_suspend(struct regulator_dev *rdev)
{
#if 0
//Cellon add start,Terry Huang,2012/11/02,for no sound in calling when being in system suspend
	struct s5m8767_info *s5m8767 = rdev_get_drvdata(rdev);
	struct i2c_client *i2c = s5m8767->iodev->i2c;
	int mask = 0xc0, pattern = 0xc0;
	int ret, reg;
	int reg_id = s5m8767_get_reg_id(rdev);
	u8 tmp;

	ret = s5m8767_get_register(rdev, &reg);
	if (ret)
		return ret;

	printk("+++ %s: id %d, reg 0x%x\n", \
			__func__, reg_id, reg);
	if (reg_id == S5M8767_LDO13) {
		s5m_reg_read(i2c, reg, &tmp);
		printk("ldo 13 reg 0x%x\n", tmp);
		
		if (tc4_get_call_flg() == 1)
			return s5m_reg_write(i2c, reg, 0xd4);
		else
			return s5m_reg_write(i2c, reg, 0x94);
	}
//Cellon add end,Terry Huang ,2012/11/02
#endif
	return 0;
}

static int s5m8767_reg_disable_suspend(struct regulator_dev *rdev)
{
	struct s5m8767_info *s5m8767 = rdev_get_drvdata(rdev);
	struct i2c_client *i2c = s5m8767->iodev->i2c;
	int ret, reg;
	int  mask=0, pattern=0;
	int reg_id = s5m8767_get_reg_id(rdev);
	switch (reg_id) {
	case S5M8767_LDO1 ... S5M8767_LDO28:
		mask = 0xc0;
		pattern = 0xc0;
		break;
	case S5M8767_BUCK1 ... S5M8767_BUCK9:
		mask = 0xc0;
		pattern = 0xc0;
		break;
	}

	ret = s5m8767_get_register(rdev, &reg);
	if (ret)
		return ret;

	ret = s5m8767_get_disable_val(rdev);

	if(ret == 2)
		ret = 0;
	return s5m_reg_update(i2c, reg, (~pattern) | (ret <<6), mask);
}

static struct regulator_ops s5m8767_ldo_ops = {
	.list_voltage		= s5m8767_list_voltage,
	.is_enabled		= s5m8767_reg_is_enabled,
	.enable			= s5m8767_reg_enable,
	.disable		= s5m8767_reg_disable,
	.get_voltage		= s5m8767_get_voltage,
	.set_voltage		= s5m8767_set_voltage,
	.set_suspend_enable	= s5m8767_reg_enable_suspend,
	.set_suspend_disable	= s5m8767_reg_disable_suspend,
};

static struct regulator_ops s5m8767_buck_ops = {
	.list_voltage		= s5m8767_list_voltage,
	.is_enabled		= s5m8767_reg_is_enabled,
	.enable			= s5m8767_reg_enable,
	.disable		= s5m8767_reg_disable,
	.get_voltage		= s5m8767_get_voltage,
	.set_voltage		= s5m8767_set_voltage_buck,
	.set_suspend_enable	= s5m8767_reg_enable_suspend,
	.set_suspend_disable	= s5m8767_reg_disable_suspend,
};

static struct regulator_ops s5m8767_others_ops = {
	.is_enabled		= s5m8767_reg_is_enabled,
	.enable			= s5m8767_reg_enable,
	.disable		= s5m8767_reg_disable,
	.set_suspend_enable	= s5m8767_reg_enable_suspend,
	.set_suspend_disable	= s5m8767_reg_disable_suspend,
};

#define regulator_desc_ldo(num)		{	\
	.name		= "LDO"#num,		\
	.id		= S5M8767_LDO##num,	\
	.ops		= &s5m8767_ldo_ops,	\
	.type		= REGULATOR_VOLTAGE,	\
	.owner		= THIS_MODULE,		\
}
#define regulator_desc_buck(num)	{	\
	.name		= "BUCK"#num,		\
	.id		= S5M8767_BUCK##num,	\
	.ops		= &s5m8767_buck_ops,	\
	.type		= REGULATOR_VOLTAGE,	\
	.owner		= THIS_MODULE,		\
}

static struct regulator_desc regulators[] = {
	regulator_desc_ldo(1),
	regulator_desc_ldo(2),
	regulator_desc_ldo(3),
	regulator_desc_ldo(4),
	regulator_desc_ldo(5),
	regulator_desc_ldo(6),
	regulator_desc_ldo(7),
	regulator_desc_ldo(8),
	regulator_desc_ldo(9),
	regulator_desc_ldo(10),
	regulator_desc_ldo(11),
	regulator_desc_ldo(12),
	regulator_desc_ldo(13),
	regulator_desc_ldo(14),
	regulator_desc_ldo(15),
	regulator_desc_ldo(16),
	regulator_desc_ldo(17),
	regulator_desc_ldo(18),
	regulator_desc_ldo(19),
	regulator_desc_ldo(20),
	regulator_desc_ldo(21),
	regulator_desc_ldo(22),
	regulator_desc_ldo(23),
	regulator_desc_ldo(24),
	regulator_desc_ldo(25),
	regulator_desc_ldo(26),
	regulator_desc_ldo(27),
	regulator_desc_ldo(28),
	regulator_desc_buck(1),
	regulator_desc_buck(2),
	regulator_desc_buck(3),
	regulator_desc_buck(4),
	regulator_desc_buck(5),
	regulator_desc_buck(6),
	regulator_desc_buck(7),
	regulator_desc_buck(8),
	regulator_desc_buck(9),
	{
		.name	= "EN32KHz AP",
		.id	= S5M8767_AP_EN32KHZ,
		.ops	= &s5m8767_others_ops,
		.type	= REGULATOR_VOLTAGE,
		.owner	= THIS_MODULE,
	}, {
		.name	= "EN32KHz CP",
		.id	= S5M8767_CP_EN32KHZ,
		.ops	= &s5m8767_others_ops,
		.type	= REGULATOR_VOLTAGE,
		.owner	= THIS_MODULE,
	},
};

static __devinit int s5m8767_pmic_probe(struct platform_device *pdev)
{
	struct s5m87xx_dev *iodev = dev_get_drvdata(pdev->dev.parent);
	struct s5m_platform_data *pdata = dev_get_platdata(iodev->dev);
	struct regulator_dev **rdev;
	struct s5m8767_info *s5m8767;
	struct i2c_client *i2c;
	int i, ret, size, reg;
	u8 val;

	// dg.baek@samsung.com
	printk("+s5m8767_pmic_probe()\r\n");
	
	if (!pdata) {
		dev_err(pdev->dev.parent, "Platform data not supplied\n");
		return -ENODEV;
	}

	s5m8767 = kzalloc(sizeof(struct s5m8767_info), GFP_KERNEL);
	if (!s5m8767)
		return -ENOMEM;

	size = sizeof(struct regulator_dev *) * pdata->num_regulators;
	s5m8767->rdev = kzalloc(size, GFP_KERNEL);
	if (!s5m8767->rdev) {
		kfree(s5m8767);
		return -ENOMEM;
	}

	rdev = s5m8767->rdev;
	s5m8767->dev = &pdev->dev;
	s5m8767->iodev = iodev;
	s5m8767->num_regulators = pdata->num_regulators;
	platform_set_drvdata(pdev, s5m8767);
	i2c = s5m8767->iodev->i2c;

	s5m8767->buck_gpioindex = pdata->buck_default_idx;
	s5m8767->buck2_gpiodvs = pdata->buck2_gpiodvs;
	s5m8767->buck3_gpiodvs = pdata->buck3_gpiodvs;
	s5m8767->buck4_gpiodvs = pdata->buck4_gpiodvs;
	s5m8767->buck_gpios[0] = pdata->buck_gpios[0];
	s5m8767->buck_gpios[1] = pdata->buck_gpios[1];
	s5m8767->buck_gpios[2] = pdata->buck_gpios[2];
	s5m8767->ramp_delay = pdata->buck_ramp_delay;
	s5m8767->buck2_ramp = pdata->buck2_ramp_enable;
	s5m8767->buck3_ramp = pdata->buck3_ramp_enable;
	s5m8767->buck4_ramp = pdata->buck4_ramp_enable;

	for (i = 0; i < 8; i++) {
		if (s5m8767->buck2_gpiodvs) {
			s5m8767->buck2_vol[i] =
				s5m8767_convert_voltage(
						&buck_voltage_val2,
						pdata->buck2_voltage[i],
						pdata->buck2_voltage[i] +
						buck_voltage_val2.step);
		}

		if (s5m8767->buck3_gpiodvs) {
			s5m8767->buck3_vol[i] =
				s5m8767_convert_voltage(
						&buck_voltage_val2,
						pdata->buck3_voltage[i],
						pdata->buck3_voltage[i] +
						buck_voltage_val2.step);
		}

		if (s5m8767->buck4_gpiodvs) {
			s5m8767->buck4_vol[i] =
				s5m8767_convert_voltage(
						&buck_voltage_val2,
						pdata->buck4_voltage[i],
						pdata->buck4_voltage[i] +
						buck_voltage_val2.step);
		}
	}

	if(pdata->buck2_gpiodvs || pdata->buck3_gpiodvs ||
		pdata->buck4_gpiodvs) {
		if (gpio_is_valid(pdata->buck_gpios[0]) &&
			gpio_is_valid(pdata->buck_gpios[1]) &&
			gpio_is_valid(pdata->buck_gpios[2])) {
			ret = gpio_request(pdata->buck_gpios[0],
						"S5M8767 SET1");
			if (ret == -EBUSY)
				dev_warn(&pdev->dev, "Duplicated gpio request"
					" for SET1\n");

			ret = gpio_request(pdata->buck_gpios[1],
						"S5M8767 SET2");
			if (ret == -EBUSY)
				dev_warn(&pdev->dev, "Duplicated gpio request"
					" for SET2\n");

			ret = gpio_request(pdata->buck_gpios[2],
						"S5M8767 SET3");
			if (ret == -EBUSY)
				dev_warn(&pdev->dev, "Duplicated gpio request"
						" for SET3\n");
			/* SET1 GPIO */
			gpio_direction_output(pdata->buck_gpios[0],
					(s5m8767->buck_gpioindex >> 2) & 0x1);
			/* SET2 GPIO */
			gpio_direction_output(pdata->buck_gpios[1],
					(s5m8767->buck_gpioindex >> 1) & 0x1);
			/* SET3 GPIO */
			gpio_direction_output(pdata->buck_gpios[2],
					(s5m8767->buck_gpioindex >> 0) & 0x1);
			ret = 0;
		} else {
			dev_err(&pdev->dev, "GPIO NOT VALID\n");
			ret = -EINVAL;
			goto err_alloc;
		}
	}

	if(pdata->buck2_gpiodvs){
		if(pdata->buck3_gpiodvs||pdata->buck4_gpiodvs){
			dev_err(&pdev->dev, "S5M8767 GPIO DVS NOT VALID\n");
			ret = -EINVAL;
			goto err_alloc;
		}
	}

	if(pdata->buck3_gpiodvs){
		if(pdata->buck2_gpiodvs||pdata->buck4_gpiodvs){
			dev_err(&pdev->dev, "S5M8767 GPIO DVS NOT VALID\n");
			ret = -EINVAL;
			goto err_alloc;
		}
	}

	if(pdata->buck4_gpiodvs){
		if(pdata->buck2_gpiodvs||pdata->buck3_gpiodvs){
			dev_err(&pdev->dev, "S5M8767 GPIO DVS NOT VALID\n");
			ret = -EINVAL;
			goto err_alloc;
		}
	}

	s5m_reg_update(i2c, S5M8767_REG_BUCK2CTRL, (pdata->buck2_gpiodvs) ?
			(1 << 1) : (0 << 1), 1 << 1);
	s5m_reg_update(i2c, S5M8767_REG_BUCK3CTRL, (pdata->buck3_gpiodvs) ?
			(1 << 1) : (0 << 1), 1 << 1);
	s5m_reg_update(i2c, S5M8767_REG_BUCK4CTRL, (pdata->buck4_gpiodvs) ?
			(1 << 1) : (0 << 1), 1 << 1);

	/* Initialize GPIO DVS registers */
	for (i = 0; i < 8; i++) {
		if (s5m8767->buck2_gpiodvs) {
			s5m_reg_write(i2c, S5M8767_REG_BUCK2DVS1 + i,
					   s5m8767->buck2_vol[i]);
		}

		if (s5m8767->buck3_gpiodvs) {
			s5m_reg_write(i2c, S5M8767_REG_BUCK3DVS1 + i,
					   s5m8767->buck3_vol[i]);
		}

		if (s5m8767->buck4_gpiodvs) {
			s5m_reg_write(i2c, S5M8767_REG_BUCK4DVS1 + i,
					   s5m8767->buck4_vol[i]);
		}
	}
	//Cellon add start,Fengying Zhang,2012/08/16,for gps_32K support enable
	#ifdef Cellon_cp_32khz
       s5m_reg_update(i2c, S5M8767_REG_CTRL1,0x2,0x2);
	s5m_reg_read (i2c, S5M8767_REG_CTRL1, &ret);
	 printk("*******s5m8767 enable gps_32k success!%d*******\n",&ret);
	 #endif
	//Cellon add end,Fengying Zhang,2012/08/16


     /*Cellon add start, Devin Yuan, 2012/10/11, for off-mode alarm*/
     ret = s5m_reg_read(i2c, S5M8767_REG_INT3M, &val);
     printk("S5M8767_REG_INT3M first=%x, ret =%d\n",val,ret);
	 
 	 #ifdef S5M8767_OFF_ALARM
     val &= 0xf9;
     s5m_reg_write(i2c, S5M8767_REG_INT3M,val);
     ret = s5m_reg_read(i2c, S5M8767_REG_INT3M, &val);
     printk("S5M8767_REG_INT3M second=%x, ret =%d\n",val,ret);
	 /*Cellon add end, Devin Yuan, 2012/10/11, for off-mode alarm*/
	 #endif

  /*Cellon add start, zhaojin, 2012/11/14, for PMIC interrupt*/
	reg = S5M8767_REG_INT1M;
	ret = s5m_reg_read(i2c, reg, &val);
	//printk("S5M8767_REG_INT1 first=%x, ret =%d\n",val,ret);
	val &= 0xC4;
	s5m_reg_write(i2c, S5M8767_REG_INT1M,val);
	ret = s5m_reg_read(i2c, reg, &val);
	//printk("S5M8767_REG_INT1 second=%x, ret =%d\n",val,ret);
  /*Cellon add end, zhaojin, 2012/11/14, for PMIC interrupt*/

	s5m_reg_update(i2c, S5M8767_REG_BUCK2CTRL, 0x78, 0xff);
	s5m_reg_update(i2c, S5M8767_REG_BUCK3CTRL, 0x58, 0xff);
	s5m_reg_update(i2c, S5M8767_REG_BUCK4CTRL, 0x78, 0xff);

	reg = S5M8767_REG_LDO7CTRL;

	do{
		ret = s5m_reg_read(i2c, reg, &val);
		if (ret)
			return ret;

		s5m_reg_update(i2c, reg, ((val & 0x3f) | 0x40), 0xff);
		reg++;
		if (( reg == S5M8767_REG_LDO9CTRL) || ( reg == S5M8767_REG_LDO11CTRL)
		|| ( reg == S5M8767_REG_LDO13CTRL) || ( reg == S5M8767_REG_LDO17CTRL))
			reg++;
	} while ( reg <= S5M8767_REG_LDO16CTRL);

	if (s5m8767->buck2_ramp)
		s5m_reg_update(i2c, S5M8767_REG_DVSRAMP, 0x08, 0x08);

	if (s5m8767->buck3_ramp)
		s5m_reg_update(i2c, S5M8767_REG_DVSRAMP, 0x04, 0x04);

	if (s5m8767->buck4_ramp)
		s5m_reg_update(i2c, S5M8767_REG_DVSRAMP, 0x02, 0x02);

	if (s5m8767->buck2_ramp || s5m8767->buck3_ramp
		|| s5m8767->buck4_ramp) {
		if (s5m8767->ramp_delay < 10)
			s5m_reg_update(i2c, S5M8767_REG_DVSRAMP,
					0x40, 0xf0);
		else if (s5m8767->ramp_delay == 10)
			s5m_reg_update(i2c, S5M8767_REG_DVSRAMP,
					0x90, 0xf0);
		else if (s5m8767->ramp_delay == 25)
			s5m_reg_update(i2c, S5M8767_REG_DVSRAMP,
					0xd0, 0xf0);
		else if (s5m8767->ramp_delay == 50)
			s5m_reg_update(i2c, S5M8767_REG_DVSRAMP,
					0xe0, 0xf0);
		else if (s5m8767->ramp_delay == 100)
			s5m_reg_update(i2c, S5M8767_REG_DVSRAMP,
					0xf0, 0xf0);
		else
			s5m_reg_update(i2c, S5M8767_REG_DVSRAMP,
					0x90, 0xf0);
	}

	for (i = 0; i < pdata->num_regulators; i++) {
		const struct s5m_voltage_desc *desc;
		int id = pdata->regulators[i].id;

		desc = reg_voltage_map[id];
		if (desc)
			regulators[id].n_voltages =
				(desc->max - desc->min) / desc->step + 1;

		rdev[i] = regulator_register(&regulators[id], s5m8767->dev,
				pdata->regulators[i].initdata, s5m8767);
		if (IS_ERR(rdev[i])) {
			ret = PTR_ERR(rdev[i]);
			dev_err(s5m8767->dev, "regulator init failed for %d\n",
					id);
			rdev[i] = NULL;
			goto err;
		}
	}
#ifdef CONFIG_AAT3635_P0
	reg = S5M8767_REG_INT1M;
	ret = s5m_reg_read(i2c, reg, &val);
	printk("S5M8767_REG_INT1 first=%x, ret =%d\n",val,ret);
	val &= 0xCF;
	s5m_reg_write(i2c, S5M8767_REG_INT1M,val);
	ret = s5m_reg_read(i2c, reg, &val);
	printk("S5M8767_REG_INT1 second=%x, ret =%d\n",val,ret);
#endif	
/* //Robin, only for test..
	//BUCK1, PWREN
	reg = S5M8767_REG_BUCK1CTRL1;
	ret = s5m_reg_read(i2c, reg, &val);
	val &= ~0xc0;
	val |= 1<<6;
	s5m_reg_write(i2c, reg, val);

	//BUCK9, PWREN
	reg = S5M8767_REG_BUCK9CTRL1;
	ret = s5m_reg_read(i2c, reg, &val);
	val &= ~0xc0;
	val |= 1<<6;
	s5m_reg_write(i2c, reg, val);

	//LDO2, PWREN
	reg = S5M8767_REG_LDO2_1CTRL;
	ret = s5m_reg_read(i2c, reg, &val);
	val &= ~0xc0;
	val |= 1<<6;
	s5m_reg_write(i2c, reg, val);

	//LDO4, PWREN
	reg = S5M8767_REG_LDO4CTRL;
	ret = s5m_reg_read(i2c, reg, &val);
	val &= ~0xc0;
	//val |= 1<<6;
	s5m_reg_write(i2c, reg, val);
	//LDO9,PWREN
	reg = S5M8767_REG_LDO9CTRL;
	ret = s5m_reg_read(i2c, reg, &val);
	val &= ~0xc0;
	val |= 1<<6;
	s5m_reg_write(i2c, reg, val);
	
	//LDO18
	reg = S5M8767_REG_LDO18CTRL;
	ret = s5m_reg_read(i2c, reg, &val);
	val &= ~0xc0;
	//val |= 1<<6;
	s5m_reg_write(i2c, reg, val);
	
	//LDO23
	reg = S5M8767_REG_LDO23CTRL;
	ret = s5m_reg_read(i2c, reg, &val);
	val &= ~0xc0;
	//val |= 1<<6;
	s5m_reg_write(i2c, reg, val);

	//LDO6
	reg = S5M8767_REG_LDO6CTRL;
	ret = s5m_reg_read(i2c, reg, &val);
	val &= ~0xc0;
	val |= 1<<6;
	s5m_reg_write(i2c, reg, val);

	//LDO7
	reg = S5M8767_REG_LDO7CTRL;
	ret = s5m_reg_read(i2c, reg, &val);
	val &= ~0xc0;
	val |= 1<<6;
	s5m_reg_write(i2c, reg, val);
	*/

	// dg.baek@samsung.com
	// START_SEMCO_A31 WiFi/BT
	#if 0
	printk("[S5M8767A] LDO24 for VDD33_A31 and LDO26 for VDD18_A31 is enabled\r\n");

	//LDO24
	reg = S5M8767_REG_LDO24CTRL;
	ret = s5m_reg_read(i2c, reg, &val);
	val &= ~0xc0;
	val |= 1<<6;
	s5m_reg_write(i2c, reg, val);

	//LDO26
	reg = S5M8767_REG_LDO26CTRL;
	ret = s5m_reg_read(i2c, reg, &val);
	val &= ~0xc0;
	val |= 1<<6;
	s5m_reg_write(i2c, reg, val);

	printk("[SEMCO_A31] WIFI_PWDN(GPZ5) is set to High\r\n");
	s3c_gpio_setpull(EXYNOS4_GPZ(5), S3C_GPIO_PULL_UP);
	gpio_set_value(EXYNOS4_GPZ(5), 0);
	s3c_gpio_cfgpin(EXYNOS4_GPZ(5), S3C_GPIO_SFN(1));
	mdelay(300);
	#endif
	
	for(reg = S5M8767_REG_BUCK1CTRL1;reg <= S5M8767_REG_LDO28CTRL;reg++)
	{
		//ret = s5m_reg_read(i2c, reg, &val);
		//printk("addr[0x%x]=0x%x\n",reg,val);
	}
// Cellon add start, Ted Shi, 2012/08/09, for porting bcm4330 wifi/bt
	s5m_reg_update(i2c, S5M8767_REG_CTRL1, BCM_BT_WIFI_32K, BCM_BT_WIFI_32K);
	s5m_reg_read(i2c,S5M8767_REG_CTRL1,&val);
	printk("(ted.shi)%s: read reg 0xa value %x \n",__func__,val);
// Cellon add end, Ted Shi, 2012/08/09	
	// dg.baek@samsung.com


        reg = S5M8767_REG_LDO5CTRL;
        ret = s5m_reg_read(i2c, reg, &val);
        val &= ~0xc0;
        s5m_reg_write(i2c, reg, val);

		/* wenpin.cui: ldo 13 always kept 150 driven strength */
	 s5m_reg_write(i2c, S5M8767_REG_LDO13CTRL, 0xd4);
//add by D.Z cellon
	 s5m_reg_write(i2c, S5M8767_REG_LDO18CTRL, 0xec);
//add end

	printk("-s5m8767_pmic_probe()\r\n");	
	return 0;
err:
	for (i = 0; i < s5m8767->num_regulators; i++)
		if (rdev[i])
			regulator_unregister(rdev[i]);
err_alloc:
	kfree(s5m8767->rdev);
	kfree(s5m8767);

	return ret;
}

static int __devexit s5m8767_pmic_remove(struct platform_device *pdev)
{
	struct s5m8767_info *s5m8767 = platform_get_drvdata(pdev);
	struct regulator_dev **rdev = s5m8767->rdev;
	int i;

	for (i = 0; i < s5m8767->num_regulators; i++)
		if (rdev[i])
			regulator_unregister(rdev[i]);

	kfree(s5m8767->rdev);
	kfree(s5m8767);

	return 0;
}

static const struct platform_device_id s5m8767_pmic_id[] = {
	{ "s5m8767-pmic", 0},
	{ },
};
MODULE_DEVICE_TABLE(platform, s5m8767_pmic_id);

static struct platform_driver s5m8767_pmic_driver = {
	.driver = {
		.name = "s5m8767-pmic",
		.owner = THIS_MODULE,
	},
	.probe = s5m8767_pmic_probe,
	.remove = __devexit_p(s5m8767_pmic_remove),
	.id_table = s5m8767_pmic_id,
};

static int __init s5m8767_pmic_init(void)
{
	return platform_driver_register(&s5m8767_pmic_driver);
}
subsys_initcall(s5m8767_pmic_init);

static void __exit s5m8767_pmic_exit(void)
{
	platform_driver_unregister(&s5m8767_pmic_driver);
}
module_exit(s5m8767_pmic_exit);

/* Module information */
MODULE_AUTHOR("Sangbeom Kim <sbkim73@samsung.com>");
MODULE_DESCRIPTION("SAMSUNG S5M8767 Regulator Driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:s5m8767-pmic");
