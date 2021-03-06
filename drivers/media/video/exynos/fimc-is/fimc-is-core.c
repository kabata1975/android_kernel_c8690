/*
 * Samsung Exynos4 SoC series FIMC-IS slave interface driver
 *
 * main platform driver interface
 *
 * Copyright (c) 2011 Samsung Electronics Co., Ltd
 * Contact: Younghwan Joo, <yhwan.joo@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/clk.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/memory.h>
#include <linux/regulator/consumer.h>
#include <linux/pm_runtime.h>
#include <linux/pm_qos_params.h>

#include <linux/videodev2.h>
#include <linux/videodev2_samsung.h>
#include <media/v4l2-subdev.h>
#include <media/v4l2-device.h>
#include <media/v4l2-ioctl.h>
#include <media/v4l2-mem2mem.h>

#include <linux/cma.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <linux/firmware.h>
#include <linux/dma-mapping.h>
#include <media/videobuf2-core.h>
#include <mach/cpufreq.h>

#include "fimc-is-core.h"
#include "fimc-is-regs.h"
#include "fimc-is-param.h"
#include "fimc-is-cmd.h"
#include "fimc-is-err.h"
#include <linux/gpio.h>
#include <plat/gpio-cfg.h>


#define GPIO_CAM_RST_3H7 EXYNOS4_GPL0(1)
#define GPIO_CAM_PWDN_VCM_3H7 EXYNOS4_GPX3(3)
#define GPIO_CAM_FLASH_3H7 EXYNOS4212_GPM3(6)
#define GPIO_CAM_TORCH_3H7 EXYNOS4212_GPM3(7)


#define GPIO_CAM_MCLK    EXYNOS4212_GPJ1(3)


#if defined(M0)
struct device *s5k6a3_dev; /*sys/class/camera/front*/
#endif

//limeng 0611:launch C-AF until T-AF lost focus
static struct work_struct fimc_is_af_wq; 
extern struct v4l2_subdev  *fimc_is_sd;
extern int fimc_is_v4l2_af_mode(struct fimc_is_dev *dev, int value);
//static int af_lost_count;


static struct pm_qos_request_list bus_qos_pm_qos_req;
struct fimc_is_dev *to_fimc_is_dev(struct v4l2_subdev *sdev)
{
	return container_of(sdev, struct fimc_is_dev, sd);
}

static void fimc_is_irq_handler_general(struct fimc_is_dev *dev)
{
	/* Read ISSR10 ~ ISSR15 */
	dev->i2h_cmd.cmd = readl(dev->regs + ISSR10);

	switch (dev->i2h_cmd.cmd) {
	case IHC_GET_SENSOR_NUMBER:
		dbg("IHC_GET_SENSOR_NUMBER\n");
		fimc_is_hw_get_param(dev, 1);
			dbg("ISP - FW version - %d\n", dev->i2h_cmd.arg[0]);
		dev->fw.ver = dev->i2h_cmd.arg[0];
		fimc_is_hw_wait_intmsr0_intmsd0(dev);
		fimc_is_hw_set_sensor_num(dev);
		break;
	case IHC_SET_SHOT_MARK:
		fimc_is_hw_get_param(dev, 3);
		break;
	case IHC_SET_FACE_MARK:
		fimc_is_hw_get_param(dev, 2);
		break;
	case IHC_FRAME_DONE:
		fimc_is_hw_get_param(dev, 2);
		break;
	case IHC_NOT_READY:
		break;
	case IHC_AA_DONE:
		fimc_is_hw_get_param(dev, 3);
		break;
#if CONFIG_MACH_STUTTGART
	case IHC_FLASH_READY:
		fimc_is_hw_get_param(dev, 2);
		break;
	case IHC_ISP_ADJUST_DONE:
		fimc_is_hw_get_param(dev, 4);
		break;
	case IHC_ISP_ISO_DONE:
		fimc_is_hw_get_param(dev, 4);
		break;
#endif
	case ISR_DONE:
		fimc_is_hw_get_param(dev, 3);
		break;
	case ISR_NDONE:
		fimc_is_hw_get_param(dev, 4);
		break;
	}

	/* Just clear the interrupt pending bits. */
	fimc_is_fw_clear_irq1(dev, INTR_GENERAL);

	switch (dev->i2h_cmd.cmd) {
	case IHC_GET_SENSOR_NUMBER:
		fimc_is_hw_set_intgr0_gd0(dev);
		set_bit(IS_ST_FW_LOADED, &dev->state);
		break;
	case IHC_SET_SHOT_MARK:
		break;
	case IHC_SET_FACE_MARK:
		dev->fd_header.count = dev->i2h_cmd.arg[0];
		dev->fd_header.index = dev->i2h_cmd.arg[1];
		{
			if (dev->faceinfo_array->number < MAX_FRAME_COUNT) {
				int i = 0;
				u32 idx;
				dev->faceinfo_array->faceinfo[dev->faceinfo_array->write].count = dev->fd_header.count;
				while (i < dev->fd_header.count) {
					idx = (dev->fd_header.index + i) % MAX_FACE_COUNT;
					dev->faceinfo_array->faceinfo[dev->faceinfo_array->write].face[i] = dev->is_p_region->face[idx];
					i++;
				}
				dev->faceinfo_array->write = (dev->faceinfo_array->write + 1) % MAX_FRAME_COUNT;
				dev->faceinfo_array->number++;
			} else {
				printk ("\n \t\t .... faceinfo lost .... \n");
			}
		}
		break;
	case IHC_FRAME_DONE:
		break;
	case IHC_AA_DONE:
		//printk("AA_DONE - %d, %d, %d\n", dev->i2h_cmd.arg[0],
			//dev->i2h_cmd.arg[1], dev->i2h_cmd.arg[2]);		
		switch (dev->i2h_cmd.arg[0]) {
		/* SEARCH: Occurs when search is requested at continuous AF */
		case 2:
			dev->af.af_lost_state = FIMC_IS_AF_SEARCH;
			wake_up(&dev->aflost_queue);

			if(dev->af.mode == IS_FOCUS_MODE_TOUCH){
				schedule_work(&fimc_is_af_wq);
			}
				
			break;
		/* INFOCUS: Occurs when focus is found. */
		case 3:
			if (dev->af.af_state == FIMC_IS_AF_RUNNING)
				dev->af.af_state = FIMC_IS_AF_LOCK;
			dev->af.af_lock_state = 0x2;
			dev->af.af_lost_state = FIMC_IS_AF_INFOCUS;
			wake_up(&dev->aflost_queue);
			break;
		/* OUTOFFOCUS: Occurs when focus is not found. */
		case 4:
			if (dev->af.af_state == FIMC_IS_AF_RUNNING)
				dev->af.af_state = FIMC_IS_AF_LOCK;
			dev->af.af_lock_state = 0x1;
			dev->af.af_lost_state = FIMC_IS_AF_OUTOFFOCUS;
			wake_up(&dev->aflost_queue);
			break;
		}
		break;
#if CONFIG_MACH_STUTTGART
	case IHC_FLASH_READY:
		set_bit(IS_ST_FLASH_READY, &dev->state);
		dev->flash.led_on = dev->i2h_cmd.arg[1];
		dbg("IS_ST_FLASH_READY : flash_on : %d", dev->flash.led_on);
		break;

      case IHC_ISP_ADJUST_DONE:
	  	{
			/*
			u32 uParam1;    <==ISP_AdjustCommandEnum  value... Contrast or Saturation or.. etc
			u32 uParam2;    <== Actually control value (e.g.  -4 ~ +4,  -128~+128)
			u32 uParam3;    <==frame counter when a5 received ISP Adjust command.
 			u32 uParam4;    <== frame counter applied Adjust command.
			*/
		  	struct is_adjust_info *infor = NULL;
		  	switch (dev->i2h_cmd.arg[0]) {
				case ISP_ADJUST_COMMAND_MANUAL_ALL:
				case ISP_ADJUST_COMMAND_AUTO:
					memset(&dev->adjust, 0, sizeof(struct is_adjust));
					break;
				case ISP_ADJUST_COMMAND_MANUAL_CONTRAST:
				case ISP_ADJUST_COMMAND_MANUAL_SATURATION:
				case ISP_ADJUST_COMMAND_MANUAL_SHARPNESS:
					break;
				case ISP_ADJUST_COMMAND_MANUAL_EXPOSURE:
					infor = &dev->adjust.exposure;
					break;
				case ISP_ADJUST_COMMAND_MANUAL_BRIGHTNESS:
				case ISP_ADJUST_COMMAND_MANUAL_HUE:
				case ISP_ADJUST_COMMAND_MANUAL_HOTPIXEL:
				case ISP_ADJUST_COMMAND_MANUAL_SHADING:
					break;
				default:
					break;
			}
			if (infor) {
			  	infor->command = dev->i2h_cmd.arg[0];
				infor->frame_start =  dev->i2h_cmd.arg[2];
				infor->frame_end =  dev->i2h_cmd.arg[3];

				if (infor->frame_end < 5)
					infor->old_value = infor->value = 0;

				infor->old_value = infor->value;
				infor->value =  dev->i2h_cmd.arg[1];
			}
      		}
	  	//printk("====>[MMKIM]IHC_ISP_ADJUST_DONE(%d, %d, %d, %d)\n", 
		//	dev->i2h_cmd.arg[0],dev->i2h_cmd.arg[1],dev->i2h_cmd.arg[2],dev->i2h_cmd.arg[3]);
		break;

	case IHC_ISP_ISO_DONE : 	
	  	//printk("====>[MMKIM]IHC_ISP_ISO_DONE(%d, %d, %d, %d)\n", 
		//	dev->i2h_cmd.arg[0],dev->i2h_cmd.arg[1],dev->i2h_cmd.arg[2],dev->i2h_cmd.arg[3]);
		break;		
#endif
	case IHC_NOT_READY:
		err("Init Sequnce Error- IS will be turned off!!");
		break;
	case ISR_DONE:
		dbg("ISR_DONE - %d\n", dev->i2h_cmd.arg[0]);
		switch (dev->i2h_cmd.arg[0]) {
		case HIC_PREVIEW_STILL:
		case HIC_PREVIEW_VIDEO:
		case HIC_CAPTURE_STILL:
		case HIC_CAPTURE_VIDEO:
			set_bit(IS_ST_CHANGE_MODE, &dev->state);
			/* Get CAC margin */
			dev->sensor.offset_x = dev->i2h_cmd.arg[1];
			dev->sensor.offset_y = dev->i2h_cmd.arg[2];
			break;
		case HIC_STREAM_ON:
			clear_bit(IS_ST_STREAM_OFF, &dev->state);
			set_bit(IS_ST_STREAM_ON, &dev->state);
			break;
		case HIC_STREAM_OFF:
			clear_bit(IS_ST_STREAM_ON, &dev->state);
			set_bit(IS_ST_STREAM_OFF, &dev->state);
			break;
		case HIC_SET_PARAMETER:
			dev->p_region_index1 = 0;
			dev->p_region_index2 = 0;
			atomic_set(&dev->p_region_num, 0);
			set_bit(IS_ST_BLOCK_CMD_CLEARED, &dev->state);

			if (dev->af.af_state == FIMC_IS_AF_SETCONFIG)
				dev->af.af_state = FIMC_IS_AF_RUNNING;
			else if (dev->af.af_state == FIMC_IS_AF_ABORT)
				dev->af.af_state = FIMC_IS_AF_IDLE;
			break;
		case HIC_GET_PARAMETER:
			break;
		case HIC_SET_TUNE:
			break;
		case HIC_GET_STATUS:
			break;
		case HIC_OPEN_SENSOR:
			set_bit(IS_ST_OPEN_SENSOR, &dev->state);
			printk(KERN_INFO "FIMC-IS Lane= %d, Settle line= %d\n",
				dev->i2h_cmd.arg[2], dev->i2h_cmd.arg[1]);
			break;
		case HIC_CLOSE_SENSOR:
			clear_bit(IS_ST_OPEN_SENSOR, &dev->state);
			dev->sensor.id = 0;
			break;
		case HIC_MSG_TEST:
			dbg("Config MSG level was done\n");
			break;
		case HIC_POWER_DOWN:
			set_bit(IS_PWR_SUB_IP_POWER_OFF, &dev->power);
			break;
		case HIC_GET_SET_FILE_ADDR:
			dev->setfile.base = dev->i2h_cmd.arg[1];
			set_bit(IS_ST_SETFILE_LOADED, &dev->state);
			break;
		case HIC_LOAD_SET_FILE:
			set_bit(IS_ST_SETFILE_LOADED, &dev->state);
			break;
		}
		break;
	case ISR_NDONE:
		err("ISR_NDONE - %d: 0x%08x\n", dev->i2h_cmd.arg[0],
			dev->i2h_cmd.arg[1]);
		fimc_is_print_err_number(dev->i2h_cmd.arg[1]);
		switch (dev->i2h_cmd.arg[1]) {
		case IS_ERROR_SET_PARAMETER:
			fimc_is_mem_cache_inv((void *)dev->is_p_region,
				IS_PARAM_SIZE);
			fimc_is_param_err_checker(dev);
			break;
		}
	}
}

static void fimc_is_irq_handler_isp(struct fimc_is_dev *dev)
{
#if defined(CONFIG_VIDEO_EXYNOS_FIMC_IS_BAYER)
	int buf_index;
#endif
	/* INTR_FRAME_DONE_ISP */
	dev->i2h_cmd.arg[0] = readl(dev->regs + ISSR20);
	dev->i2h_cmd.arg[1] = readl(dev->regs + ISSR21);
	fimc_is_fw_clear_irq1(dev, INTR_FRAME_DONE_ISP);
#if defined(CONFIG_VIDEO_EXYNOS_FIMC_IS_BAYER)
	buf_index = (dev->i2h_cmd.arg[1] - 1)
				% dev->video[FIMC_IS_VIDEO_NUM_BAYER].num_buf;
	vb2_buffer_done(dev->video[FIMC_IS_VIDEO_NUM_BAYER].vbq.bufs[buf_index],
			VB2_BUF_STATE_DONE);
#endif
}

static irqreturn_t fimc_is_irq_handler1(int irq, void *dev_id)
{
	struct fimc_is_dev *dev = dev_id;
	unsigned int intr_status;

	intr_status = readl(dev->regs + INTSR1);

	/* INTR_GENERAL */
	if (intr_status & BIT0)
		fimc_is_irq_handler_general(dev);
	else if (intr_status & BIT1)
		fimc_is_irq_handler_isp(dev);
	wake_up(&dev->irq_queue1);
	return IRQ_HANDLED;
}

static void fimc_is_af_interrupt(struct work_struct *work)
{
	struct fimc_is_dev *dev = to_fimc_is_dev(fimc_is_sd);
	int ret = 0;
	int count = 0;

	if(dev->af.mode == IS_FOCUS_MODE_TOUCH){	
		dev->af.af_lost_count++;
		if(dev->af.af_lost_count == 2){
		dev->af.mode = IS_FOCUS_MODE_CONTINUOUS;
		ret = fimc_is_v4l2_af_mode(dev,FOCUS_MODE_CONTINOUS);
		dev->af.af_lost_count = 0;
		}
	}
}


#if defined(M0)
static ssize_t s5k6a3_camera_front_camtype_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	char type[] = "SLSI_S5K6A3_FIMC_IS";

	return sprintf(buf, "%s\n", type);
}

static ssize_t s5k6a3_camera_front_camfw_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	char type[] = "S5K6A3";
	return sprintf(buf, "%s %s\n", type, type);

}

static DEVICE_ATTR(front_camtype, S_IRUGO,
		s5k6a3_camera_front_camtype_show, NULL);
static DEVICE_ATTR(front_camfw, S_IRUGO, s5k6a3_camera_front_camfw_show, NULL);
#endif

static int fimc_is_probe(struct platform_device *pdev)
{
	struct exynos4_platform_fimc_is *pdata;
	struct resource *mem_res;
	struct resource *regs_res;
	struct fimc_is_dev *dev;
#if defined(CONFIG_VIDEO_EXYNOS_FIMC_IS_BAYER)
	struct v4l2_device *v4l2_dev;
	struct vb2_queue *isp_q;
#endif
	int ret = -ENODEV;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		dev_err(&pdev->dev, "Not enough memory for FIMC-IS device.\n");
		return -ENOMEM;
	}

	dev->faceinfo_array = kzalloc(sizeof(*(dev->faceinfo_array)), GFP_KERNEL);
	if (!dev->faceinfo_array) {
		kfree(dev);
		dev_err(&pdev->dev, "Not enough memory for FIMC-IS device.\n");
		return -ENOMEM;
	}
	dev->faceinfo_array->faceinfo = kzalloc(sizeof(*(dev->faceinfo_array->faceinfo)) * MAX_FRAME_COUNT, GFP_KERNEL);
	if (!dev->faceinfo_array->faceinfo) {
		kfree(dev->faceinfo_array);
		kfree(dev);
		dev_err(&pdev->dev, "Not enough memory for FIMC-IS device.\n");
		return -ENOMEM;
	}

	mutex_init(&dev->lock);
	spin_lock_init(&dev->slock);
	init_waitqueue_head(&dev->irq_queue1);
	init_waitqueue_head(&dev->aflost_queue);
	INIT_WORK(&fimc_is_af_wq,fimc_is_af_interrupt);

	dev->pdev = pdev;
	if (!dev->pdev) {
		dev_err(&pdev->dev, "No platform data specified\n");
		goto p_err_info;
	}

	pdata = pdev->dev.platform_data;
	if (!pdata) {
		dev_err(&pdev->dev, "Platform data not set\n");
		goto p_err_info;
	}
	dev->pdata = pdata;
	/*
	 * I/O remap
	*/
	mem_res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!mem_res) {
		dev_err(&pdev->dev, "Failed to get io memory region\n");
		ret = -ENOENT;
		goto p_err_info;
	}

	regs_res = request_mem_region(mem_res->start,
		resource_size(mem_res), pdev->name);
	if (!regs_res) {
		dev_err(&pdev->dev, "Failed to request io memory region\n");
		ret = -ENOENT;
		goto p_err_info;
	}
	dev->regs_res = regs_res;

	dev->regs = ioremap(mem_res->start, resource_size(mem_res));
	if (!dev->regs) {
		dev_err(&pdev->dev, "Failed to remap io region\n");
		ret = -ENXIO;
		goto p_err_req_region;
	}

	/*
	 * initialize IRQ , FIMC-IS IRQ : ISP[0] -> SPI[90] , ISP[1] -> SPI[95]
	*/
	dev->irq1 = platform_get_irq(pdev, 0);
	if (dev->irq1 < 0) {
		ret = dev->irq1;
		dev_err(&pdev->dev, "Failed to get irq\n");
		goto p_err_get_irq;
	}

	ret = request_irq(dev->irq1, fimc_is_irq_handler1,
		IRQF_DISABLED, dev_name(&pdev->dev), dev);
	if (ret) {
		dev_err(&pdev->dev, "failed to allocate irq (%d)\n", ret);
		goto p_err_req_irq;
	}

#if defined(CONFIG_VIDEO_EXYNOS_FIMC_IS_BAYER)
	/* Init v4l2 device (ISP) */
#if defined(CONFIG_VIDEOBUF2_CMA_PHYS)
	dev->vb2 = &fimc_is_vb2_cma;
#elif defined(CONFIG_VIDEOBUF2_ION)
	dev->vb2 = &fimc_is_vb2_ion;
#endif

	/* Init and register V4L2 device */
	v4l2_dev = &dev->video[FIMC_IS_VIDEO_NUM_BAYER].v4l2_dev;
	if (!v4l2_dev->name[0])
		snprintf(v4l2_dev->name, sizeof(v4l2_dev->name),
			 "%s.isp", dev_name(&dev->pdev->dev));
	ret = v4l2_device_register(NULL, v4l2_dev);

	snprintf(dev->video[FIMC_IS_VIDEO_NUM_BAYER].vd.name,
			sizeof(dev->video[FIMC_IS_VIDEO_NUM_BAYER].vd.name),
			"%s", "exynos4-fimc-is-bayer");
	dev->video[FIMC_IS_VIDEO_NUM_BAYER].vd.fops		=
						&fimc_is_isp_video_fops;
	dev->video[FIMC_IS_VIDEO_NUM_BAYER].vd.ioctl_ops	=
						&fimc_is_isp_video_ioctl_ops;
	dev->video[FIMC_IS_VIDEO_NUM_BAYER].vd.minor		= -1;
	dev->video[FIMC_IS_VIDEO_NUM_BAYER].vd.release		=
						video_device_release;
	dev->video[FIMC_IS_VIDEO_NUM_BAYER].vd.lock		=
						&dev->lock;
	video_set_drvdata(&dev->video[FIMC_IS_VIDEO_NUM_BAYER].vd, dev);
	dev->video[FIMC_IS_VIDEO_NUM_BAYER].dev = dev;

	isp_q = &dev->video[FIMC_IS_VIDEO_NUM_BAYER].vbq;
	memset(isp_q, 0, sizeof(*isp_q));
	isp_q->type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	isp_q->io_modes = VB2_MMAP | VB2_USERPTR;
	isp_q->drv_priv = &dev->video[FIMC_IS_VIDEO_NUM_BAYER];
	isp_q->ops = &fimc_is_isp_qops;
	isp_q->mem_ops = dev->vb2->ops;

	vb2_queue_init(isp_q);

	ret = video_register_device(&dev->video[FIMC_IS_VIDEO_NUM_BAYER].vd,
							VFL_TYPE_GRABBER, 30);
	if (ret) {
		v4l2_err(v4l2_dev, "Failed to register video device\n");
		goto err_vd_reg;
	}

	printk(KERN_INFO "FIMC-IS Video node :: ISP %d minor : %d\n",
		dev->video[FIMC_IS_VIDEO_NUM_BAYER].vd.num,
		dev->video[FIMC_IS_VIDEO_NUM_BAYER].vd.minor);
#endif
	/*
	 * initialize memory manager
	*/
	ret = fimc_is_init_mem_mgr(dev);
	if (ret) {
		dev_err(&pdev->dev,
			"failed to fimc_is_init_mem_mgr (%d)\n", ret);
		goto p_err_init_mem;
	}
	dbg("Parameter region = 0x%08x\n", (unsigned int)dev->is_p_region);

	/*
	 * Get related clock for FIMC-IS
	*/
	if (dev->pdata->clk_get) {
		dev->pdata->clk_get(pdev);
	} else {
		err("#### failed to Get Clock####\n");
		goto p_err_init_mem;
	}

	/*
	 * Get regulator for FIMC-IS
	*/
#ifdef CONFIG_REGULATOR	
	//printk("### regulator_get 1.2V 1.8V 2.8V for 3H7 sensor in %s###",__FUNCTION__);
	dev->r_vdd18_cam = regulator_get(NULL, "vdd12_5m");//cellon McNex buck6//PC4 buck6//r_vdd18_cam means vdd core 1.2V //s3 vdd_ldo17
	if (IS_ERR(dev->r_vdd18_cam)) {
		pr_err("failed to get resource %s\n", "vdd12_5m");
		goto p_err_init_mem;
	}

	dev->r_vddio18_cam = regulator_get(NULL, "vddioperi_18");//cellon McNex LDO13 //PC4 ldo25//s3 vdd_ldo18
	if (IS_ERR(dev->r_vddio18_cam)) {
		pr_err("failed to get resource %s\n", "vddioperi_18");
		regulator_put(dev->r_vdd18_cam);
		goto p_err_init_mem;
	}
/*	//lisw  cellon McNex use the same ldo with cam 2.8V
	dev->r_vdd28_af_cam = regulator_get(NULL, "vdd28_af");//PC4 ldo21//gproject ldo19
	if (IS_ERR(dev->r_vdd28_af_cam)) {
		pr_err("failed to get resource %s\n", "vdd28_af");
		regulator_put(dev->r_vddio18_cam);
		regulator_put(dev->r_vdd18_cam);
		goto p_err_init_mem;
	}
*/	
	dev->r_vadd28_cam = regulator_get(NULL, "vdd33_a31");//cellon McNex LDO24 //PC4 ldo20//camera analog 2.8V //Gproject ldo27 could not output2.8V
	if (IS_ERR(dev->r_vadd28_cam)) {
		pr_err("failed to get resource %s\n", "vdd33_a31");
		regulator_put(dev->r_vdd28_af_cam);
		regulator_put(dev->r_vddio18_cam);
		regulator_put(dev->r_vdd18_cam);
		goto p_err_init_mem;
	}

	dev->r_vdd18_mipi_tv= regulator_get(NULL, "vdd18_mipi");
    if (IS_ERR(dev->r_vdd18_mipi_tv)) {
        pr_err("failed to get resource %s\n", __func__, "vdd18_mipi");
        //regulator_put(dev->r_vdd28_af_cam);
        regulator_put(dev->r_vddio18_cam);
        regulator_put(dev->r_vdd18_cam);
        regulator_put(dev->r_vadd28_cam);
        goto p_err_init_mem;
     }

     dev->r_vdd10_mipi_tv= regulator_get(NULL, "vdd10_mipi");
     if (IS_ERR(dev->r_vdd10_mipi_tv)) {
        printk("failed to get resource %s\n", __func__, "vdd10_mipi");
        //regulator_put(dev->r_vdd28_af_cam);
        regulator_put(dev->r_vddio18_cam);
        regulator_put(dev->r_vdd18_cam);
        regulator_put(dev->r_vadd28_cam);
        regulator_put(dev->r_vdd18_mipi_tv);
        goto p_err_init_mem;
     }

//	regulator_disable(dev->r_vdd18_cam);
//	regulator_disable(dev->r_vddio18_cam);
//	regulator_disable(dev->r_vdd28_af_cam);
//  regulator_disable(dev->r_vadd28_cam);
//  regulator_enable(dev->r_vdd18_mipi_tv);
//  regulator_enable(dev->r_vdd10_mipi_tv);

#endif
	
	/* Init v4l2 sub device */
	v4l2_subdev_init(&dev->sd, &fimc_is_subdev_ops);
	dev->sd.owner = THIS_MODULE;
	strcpy(dev->sd.name, MODULE_NAME);
	v4l2_set_subdevdata(&dev->sd, pdev);

	platform_set_drvdata(pdev, &dev->sd);

	pm_runtime_enable(&pdev->dev);

#if defined(CONFIG_BUSFREQ_OPP) || defined(CONFIG_BUSFREQ_LOCK_WRAPPER)
	/* To lock bus frequency in OPP mode */
	dev->bus_dev = dev_get("exynos-busfreq");
#endif
	dev->power = 0;
	dev->state = 0;
	dev->sensor_num = FIMC_IS_SENSOR_NUM;
	dev->sensor.id = 0;
	dev->p_region_index1 = 0;
	dev->p_region_index2 = 0;
	dev->sensor.offset_x = 16;
	dev->sensor.offset_y = 12;
	dev->sensor.framerate_update = false;
	atomic_set(&dev->p_region_num, 0);
	set_bit(IS_ST_IDLE, &dev->state);
	set_bit(IS_PWR_ST_POWEROFF, &dev->power);
	dev->af.af_state = FIMC_IS_AF_IDLE;
	dev->af.mode = IS_FOCUS_MODE_IDLE;
	dev->low_power_mode = false;
	dev->fw.state = 0;
	dev->setfile.state = 0;
	dev->af.af_lost_state = 0;
#if defined(M0)
	s5k6a3_dev = device_create(camera_class, NULL, 0, NULL, "front");
	if (IS_ERR(s5k6a3_dev)) {
		printk(KERN_ERR "failed to create device!\n");
	} else {
		if (device_create_file(s5k6a3_dev, &dev_attr_front_camtype)
				< 0) {
			printk(KERN_ERR "failed to create device file, %s\n",
				dev_attr_front_camtype.attr.name);
		}
		if (device_create_file(s5k6a3_dev, &dev_attr_front_camfw) < 0) {
			printk(KERN_ERR "failed to create device file, %s\n",
				dev_attr_front_camfw.attr.name);
		}
	}
#endif
	printk(KERN_INFO "FIMC-IS probe completed\n");
	return 0;

p_err_init_mem:
	free_irq(dev->irq1, dev);
#if defined(CONFIG_VIDEO_EXYNOS_FIMC_IS_BAYER)
err_vd_reg:
	video_device_release(&dev->video[FIMC_IS_VIDEO_NUM_BAYER].vd);
#endif
p_err_req_irq:
p_err_get_irq:
	iounmap(dev->regs);
p_err_req_region:
	release_mem_region(regs_res->start, resource_size(regs_res));
p_err_info:
	dev_err(&dev->pdev->dev, "failed to install\n");
	kfree(dev);
	return ret;
}

static int fimc_is_remove(struct platform_device *pdev)
{
	struct v4l2_subdev *sd = platform_get_drvdata(pdev);
	struct fimc_is_dev *dev = to_fimc_is_dev(sd);

	if (dev->pdata->clk_put)
		dev->pdata->clk_put(pdev);
	else
		err("#### failed to Put Clock####\n");

#ifdef CONFIG_REGULATOR	
	if (dev->r_vdd18_cam)
		regulator_put(dev->r_vdd18_cam);

	if (dev->r_vddio18_cam)
		regulator_put(dev->r_vddio18_cam);

	if (dev->r_vdd28_af_cam) 
		regulator_put(dev->r_vdd28_af_cam);

	if (dev->r_vadd28_cam)
		regulator_put(dev->r_vadd28_cam);

	if (dev->r_vdd18_mipi_tv)
        regulator_put(dev->r_vdd18_mipi_tv);

    if (dev->r_vdd10_mipi_tv)
        regulator_put(dev->r_vdd10_mipi_tv);
#endif

#if defined(CONFIG_VIDEOBUF2_ION)
	fimc_is_mem_init_mem_cleanup(dev->alloc_ctx);
#endif
	kfree(dev);
	return 0;
}

static int fimc_is_suspend(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct v4l2_subdev *sd = platform_get_drvdata(pdev);
	struct fimc_is_dev *is_dev = to_fimc_is_dev(sd);
	int ret = 0;

	printk(KERN_INFO "FIMC-IS suspend\n");
	if (!test_bit(IS_ST_INIT_DONE, &is_dev->state)) {
		printk(KERN_INFO "FIMC-IS suspend end\n");
		return 0;
	}
	/* If stream was not stopped, stop streaming */
	if (!test_bit(IS_ST_STREAM_OFF, &is_dev->state)) {
		err("Not stream off state\n");
		clear_bit(IS_ST_STREAM_OFF, &is_dev->state);
		fimc_is_hw_set_stream(is_dev, false);
		ret = wait_event_timeout(is_dev->irq_queue1,
				test_bit(IS_ST_STREAM_OFF, &is_dev->state),
				(HZ));
		if (!ret) {
			err("wait timeout : Stream off\n");
			fimc_is_hw_set_low_poweroff(is_dev, true);
		}
	}
	/* If the power is not off state, turn off the power */
	if (!test_bit(IS_PWR_ST_POWEROFF, &is_dev->power)) {
		err("Not power off state\n");
		if (!test_bit(IS_PWR_SUB_IP_POWER_OFF, &is_dev->power)) {
			fimc_is_hw_subip_poweroff(is_dev);
			ret = wait_event_timeout(is_dev->irq_queue1,
				test_bit(IS_PWR_SUB_IP_POWER_OFF,
				&is_dev->power), FIMC_IS_SHUTDOWN_TIMEOUT);
			if (!ret) {
				err("wait timeout : %s\n", __func__);
				fimc_is_hw_set_low_poweroff(is_dev, true);
			}
		}
		fimc_is_hw_a5_power(is_dev, 0);
		pm_runtime_put_sync(dev);

		is_dev->sensor.id = 0;
		is_dev->p_region_index1 = 0;
		is_dev->p_region_index2 = 0;
		atomic_set(&is_dev->p_region_num, 0);
		is_dev->state = 0;
		set_bit(IS_ST_IDLE, &is_dev->state);
		is_dev->power = 0;
		is_dev->af.af_state = FIMC_IS_AF_IDLE;
		set_bit(IS_PWR_ST_POWEROFF, &is_dev->power);
	}
	printk(KERN_INFO "FIMC-IS suspend end\n");
	return 0;
}

static int fimc_is_resume(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct v4l2_subdev *sd = platform_get_drvdata(pdev);
	struct fimc_is_dev *is_dev = to_fimc_is_dev(sd);

	//printk(KERN_INFO "FIMC-IS resume\n");
	mutex_lock(&is_dev->lock);
	mutex_unlock(&is_dev->lock);
	//printk(KERN_INFO "FIMC-IS resume end\n");
	return 0;
}

static int fimc_is_runtime_suspend(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct v4l2_subdev *sd = platform_get_drvdata(pdev);
	struct fimc_is_dev *is_dev = to_fimc_is_dev(sd);

	printk("FIMC-IS runtime suspend\n");

	//printk("-----direct return 0 FIMC-IS runtime suspend\n");
	//return 0;	
	if (is_dev->pdata->clk_off) {
		is_dev->pdata->clk_off(pdev);
	} else {
		printk(KERN_ERR "#### failed to Clock OFF ####\n");
		return -EINVAL;
	}
#if defined(CONFIG_BUSFREQ_OPP) || defined(CONFIG_BUSFREQ_LOCK_WRAPPER)
	/* Unlock bus frequency */
//	pm_qos_remove_request(&bus_qos_pm_qos_req);
	dev_unlock(is_dev->bus_dev, dev);
#endif
#ifdef CONFIG_EXYNOS4_CPUFREQ
	exynos_cpufreq_lock_free(DVFS_LOCK_ID_CAM);
#endif

#if defined(CONFIG_VIDEOBUF2_ION)
	if (is_dev->alloc_ctx)
		fimc_is_mem_suspend(is_dev->alloc_ctx);
#endif
	mutex_lock(&is_dev->lock);
	clear_bit(IS_PWR_ST_POWERON, &is_dev->power);
	set_bit(IS_PWR_ST_POWEROFF, &is_dev->power);
	mutex_unlock(&is_dev->lock);
#ifdef CONFIG_REGULATOR	
	//printk("---power down sensor in %s",__FUNCTION__);

	if (gpio_request(GPIO_CAM_RST_3H7, "GPF1_5") < 0)
		printk("failed gpio_request(GPM1_5) for camera control\n");
	
	gpio_direction_output(GPIO_CAM_RST_3H7, 0);	
	gpio_free(GPIO_CAM_RST_3H7);

	regulator_disable(is_dev->r_vdd18_cam);
	regulator_disable(is_dev->r_vddio18_cam);
//lisw	regulator_disable(is_dev->r_vdd28_af_cam);
	regulator_disable(is_dev->r_vadd28_cam);
    regulator_disable(is_dev->r_vdd18_mipi_tv);
    regulator_disable(is_dev->r_vdd10_mipi_tv);
#endif

	printk("FIMC-IS runtime suspend end\n");
	return 0;
}

static int fimc_is_runtime_resume(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct v4l2_subdev *sd = platform_get_drvdata(pdev);
	struct fimc_is_dev *is_dev = to_fimc_is_dev(sd);

	printk("FIMC-IS runtime resume\n");
#ifdef CONFIG_REGULATOR	
	//printk("---power up sensor in %s",__FUNCTION__);
	s3c_gpio_cfgpin(GPIO_CAM_MCLK, S3C_GPIO_SFN(2));//MCLK

	int ret = gpio_request(EXYNOS4212_GPM4(0), "GPM4_0");//IIC clock
	if (ret)
		printk(KERN_ERR "#### failed to request GPM4_0 ####\n");
	s3c_gpio_cfgpin(EXYNOS4212_GPM4(0), (0x2<<0));
	s3c_gpio_setpull(EXYNOS4212_GPM4(0), S3C_GPIO_PULL_NONE);
	gpio_free(EXYNOS4212_GPM4(0));

	ret = gpio_request(EXYNOS4212_GPM4(1), "GPM4_1");//IIC data
	if (ret)
		printk(KERN_ERR "#### failed to request GPM4_1 ####\n");
	s3c_gpio_cfgpin(EXYNOS4212_GPM4(1), (0x2<<4));
	s3c_gpio_setpull(EXYNOS4212_GPM4(1), S3C_GPIO_PULL_NONE);
	gpio_free(EXYNOS4212_GPM4(1));
//lisw added GPM3_6 GPM3_7 CAM_GPIO config for flash torch function/////
	//printk("----!!!!config flash torch GPIO camera flash control\n");

if (gpio_request(GPIO_CAM_FLASH_3H7, "GPM3_6") < 0)//flash CAM_GPIO8
	printk("failed gpio_request(GPIO_CAM_FLASH_3H7) for camera control\n");
s3c_gpio_cfgpin(GPIO_CAM_FLASH_3H7, (0x2<<24));

	s3c_gpio_setpull(GPIO_CAM_FLASH_3H7, S3C_GPIO_PULL_NONE);
	gpio_free(GPIO_CAM_FLASH_3H7);	

mdelay(1);

if (gpio_request(GPIO_CAM_TORCH_3H7, "GPM3_7") < 0)//torch CAM_GPIO9
	printk("failed gpio_request(GPIO_CAM_TORCH_3H7) for camera control\n");
s3c_gpio_cfgpin(GPIO_CAM_TORCH_3H7, (0x2<<28));

s3c_gpio_setpull(GPIO_CAM_TORCH_3H7, S3C_GPIO_PULL_NONE);
gpio_free(GPIO_CAM_TORCH_3H7); 


mdelay(1);


////////end//////////////////////////////////////////////


	
	if (gpio_request(GPIO_CAM_PWDN_VCM_3H7, "GPX3_3") < 0)//MCNex 3h7 pwdn vcm
		printk("failed gpio_request(GPIO_CAM_PWDN_VCM_3H7) for camera control\n");
	gpio_direction_output(GPIO_CAM_PWDN_VCM_3H7, 1);
	s3c_gpio_setpull(GPIO_CAM_PWDN_VCM_3H7, S3C_GPIO_PULL_NONE);	
	
	mdelay(1);

	if (gpio_request(GPIO_CAM_RST_3H7, "GPL0_1") < 0)//3h7 reset
		printk("failed gpio_request(GPIO_CAM_RST_3H7) for camera control\n");
	gpio_direction_output(GPIO_CAM_RST_3H7, 0);
	s3c_gpio_setpull(GPIO_CAM_RST_3H7, S3C_GPIO_PULL_NONE);	
	
	mdelay(1);

	regulator_enable(is_dev->r_vdd18_cam);
	regulator_enable(is_dev->r_vddio18_cam);
//lisw use the same LDO as cam_2.8V	regulator_enable(is_dev->r_vdd28_af_cam);
	regulator_enable(is_dev->r_vadd28_cam);
    regulator_enable(is_dev->r_vdd18_mipi_tv);
    regulator_enable(is_dev->r_vdd10_mipi_tv);

	mdelay(1);
	// RSTN high
	gpio_direction_output(GPIO_CAM_RST_3H7, 1);	
	mdelay(1);
	gpio_free(GPIO_CAM_PWDN_VCM_3H7);
	gpio_free(GPIO_CAM_RST_3H7);
#endif

	if (is_dev->pdata->clk_cfg) {
		is_dev->pdata->clk_cfg(pdev);
	} else {
		printk(KERN_ERR "#### failed to Clock CONFIG ####\n");
		return -EINVAL;
	}
	if (is_dev->pdata->clk_on) {
		is_dev->pdata->clk_on(pdev);
	} else {
		printk(KERN_ERR "#### failed to Clock On ####\n");
		return -EINVAL;
	}
	is_dev->frame_count = 0;
#if defined(CONFIG_VIDEOBUF2_ION)
	if (is_dev->alloc_ctx)
		fimc_is_mem_resume(is_dev->alloc_ctx);
#endif

#if defined(CONFIG_BUSFREQ_OPP) || defined(CONFIG_BUSFREQ_LOCK_WRAPPER)
		/* lock bus frequency */
	dev_lock(is_dev->bus_dev, dev, BUS_LOCK_FREQ_L0);
//	pm_qos_add_request(&bus_qos_pm_qos_req, PM_QOS_BUS_QOS, 1);
#endif
#ifdef CONFIG_EXYNOS4_CPUFREQ
	if (exynos_cpufreq_lock(DVFS_LOCK_ID_CAM, L7)) {
		printk(KERN_ERR "ISP: failed to cpufreq lock for L0");
	}
#endif

	mutex_lock(&is_dev->lock);
	clear_bit(IS_PWR_ST_POWEROFF, &is_dev->power);
	clear_bit(IS_PWR_SUB_IP_POWER_OFF, &is_dev->power);
	set_bit(IS_PWR_ST_POWERON, &is_dev->power);
	mutex_unlock(&is_dev->lock);
	printk("FIMC-IS runtime resume end\n");
	return 0;
}

static const struct dev_pm_ops fimc_is_pm_ops = {
	.suspend	 = fimc_is_suspend,
	.resume		 = fimc_is_resume,
	.runtime_suspend = fimc_is_runtime_suspend,
	.runtime_resume	 = fimc_is_runtime_resume,
};

static struct platform_driver fimc_is_driver = {
	.probe		= fimc_is_probe,
	.remove		= fimc_is_remove,
	.driver		= {
		.name	= MODULE_NAME,
		.owner	= THIS_MODULE,
		.pm	= &fimc_is_pm_ops,
	},
};

static int __init fimc_is_init(void)
{
	int ret;
	ret = platform_driver_register(&fimc_is_driver);
	if (ret)
		err("platform_driver_register failed: %d\n", ret);
	return ret;
}

static void __exit fimc_is_exit(void)
{
	platform_driver_unregister(&fimc_is_driver);
}

module_init(fimc_is_init);
module_exit(fimc_is_exit);

MODULE_AUTHOR("Younghwan Joo, <yhwan.joo@samsung.com>");
MODULE_DESCRIPTION("Exynos4 series FIMC-IS slave driver");
MODULE_LICENSE("GPL");
