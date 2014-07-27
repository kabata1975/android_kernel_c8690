/*
 * SDIO access interface for drivers - linux specific (pci only)
 *
 * Copyright (C) 1999-2014, Broadcom Corporation
 * 
 *      Unless you and Broadcom execute a separate written software license
 * agreement governing use of this software, this software is licensed to you
 * under the terms of the GNU General Public License version 2 (the "GPL"),
 * available at http://www.broadcom.com/licenses/GPLv2.php, with the
 * following added to such license:
 * 
 *      As a special exception, the copyright holders of this software give you
 * permission to link this software with independent modules, and to copy and
 * distribute the resulting executable under terms of your choice, provided that
 * you also meet, for each linked independent module, the terms and conditions of
 * the license of that module.  An independent module is a module which is not
 * derived from this software.  The special exception does not apply to any
 * modifications of the software.
 * 
 *      Notwithstanding the above, under no circumstances may you combine this
 * software in any way with any other Broadcom software provided under a license
 * other than the GPL, without Broadcom's express prior written consent.
 *
<<<<<<< HEAD
 * $Id: bcmsdh_linux.c 373359 2012-12-07 06:36:37Z $
=======
 * $Id: bcmsdh_linux.c 455573 2014-02-14 17:49:31Z $
>>>>>>> 90123ab... Update Wi-Fi drivers to 1.141.44 (coming from N5100 kernel drop)
 */

/**
 * @file bcmsdh_linux.c
 */

#define __UNDEF_NO_VERSION__

#include <typedefs.h>
#include <linuxver.h>
#include <linux/pci.h>
#include <linux/completion.h>

#include <osl.h>
#include <pcicfg.h>
#include <bcmdefs.h>
#include <bcmdevs.h>
<<<<<<< HEAD

#if defined(OOB_INTR_ONLY)
=======
>>>>>>> 90123ab... Update Wi-Fi drivers to 1.141.44 (coming from N5100 kernel drop)
#include <linux/irq.h>
extern void dhdsdio_isr(void * args);
#include <bcmutils.h>
#include <dngl_stats.h>
#include <dhd.h>
<<<<<<< HEAD
#endif 


/**
 * SDIO Host Controller info
 */
typedef struct bcmsdh_hc bcmsdh_hc_t;

struct bcmsdh_hc {
	bcmsdh_hc_t *next;
#ifdef BCMPLATFORM_BUS
	struct device *dev;			/* platform device handle */
#else
	struct pci_dev *dev;		/* pci device handle */
#endif /* BCMPLATFORM_BUS */
	osl_t *osh;
	void *regs;			/* SDIO Host Controller address */
	bcmsdh_info_t *sdh;		/* SDIO Host Controller handle */
	void *ch;
	unsigned int oob_irq;
	unsigned long oob_flags; /* OOB Host specifiction as edge and etc */
	bool oob_irq_registered;
	bool oob_irq_enable_flag;
#if defined(OOB_INTR_ONLY)
	spinlock_t irq_lock;
#endif 
};
static bcmsdh_hc_t *sdhcinfo = NULL;
=======
#include <dhd_linux.h>
>>>>>>> 90123ab... Update Wi-Fi drivers to 1.141.44 (coming from N5100 kernel drop)

/* driver info, initialized when bcmsdh_register is called */
static bcmsdh_driver_t drvinfo = {NULL, NULL, NULL, NULL};

typedef enum {
	DHD_INTR_INVALID = 0,
	DHD_INTR_INBAND,
	DHD_INTR_HWOOB,
	DHD_INTR_SWOOB
} DHD_HOST_INTR_TYPE;

/* the BCMSDH module comprises the generic part (bcmsdh.c) and OS specific layer (e.g.
 * bcmsdh_linux.c). Put all OS specific variables (e.g. irq number and flags) here rather
 * than in the common structure bcmsdh_info. bcmsdh_info only keeps a handle (os_ctx) to this
 * structure.
 */
typedef struct bcmsdh_os_info {
	DHD_HOST_INTR_TYPE	intr_type;
	int			oob_irq_num;	/* valid when hardware or software oob in use */
	unsigned long		oob_irq_flags;	/* valid when hardware or software oob in use */
	bool			oob_irq_registered;
	bool			oob_irq_enabled;
	bool			oob_irq_wake_enabled;
	spinlock_t		oob_irq_spinlock;
	bcmsdh_cb_fn_t		oob_irq_handler;
	void			*oob_irq_handler_context;
	void			*context;	/* context returned from upper layer */
	void			*sdioh;		/* handle to lower layer (sdioh) */
	void			*dev;		/* handle to the underlying device */
	bool			dev_wake_enabled;
} bcmsdh_os_info_t;

/* debugging macros */
#define SDLX_MSG(x)

/**
 * Checks to see if vendor and device IDs match a supported SDIO Host Controller.
 */
bool
bcmsdh_chipmatch(uint16 vendor, uint16 device)
{
	/* Add other vendors and devices as required */

#ifdef BCMSDIOH_STD
	/* Check for Arasan host controller */
	if (vendor == VENDOR_SI_IMAGE) {
		return (TRUE);
	}
	/* Check for BRCM 27XX Standard host controller */
	if (device == BCM27XX_SDIOH_ID && vendor == VENDOR_BROADCOM) {
		return (TRUE);
	}
	/* Check for BRCM Standard host controller */
	if (device == SDIOH_FPGA_ID && vendor == VENDOR_BROADCOM) {
		return (TRUE);
	}
	/* Check for TI PCIxx21 Standard host controller */
	if (device == PCIXX21_SDIOH_ID && vendor == VENDOR_TI) {
		return (TRUE);
	}
	if (device == PCIXX21_SDIOH0_ID && vendor == VENDOR_TI) {
		return (TRUE);
	}
	/* Ricoh R5C822 Standard SDIO Host */
	if (device == R5C822_SDIOH_ID && vendor == VENDOR_RICOH) {
		return (TRUE);
	}
	/* JMicron Standard SDIO Host */
	if (device == JMICRON_SDIOH_ID && vendor == VENDOR_JMICRON) {
		return (TRUE);
	}

#endif /* BCMSDIOH_STD */
#ifdef BCMSDIOH_SPI
	/* This is the PciSpiHost. */
	if (device == SPIH_FPGA_ID && vendor == VENDOR_BROADCOM) {
		printf("Found PCI SPI Host Controller\n");
		return (TRUE);
	}

#endif /* BCMSDIOH_SPI */

	return (FALSE);
}

<<<<<<< HEAD
#if defined(BCMPLATFORM_BUS)
#if defined(BCMLXSDMMC)
/* forward declarations */
int bcmsdh_probe(struct device *dev);
int bcmsdh_remove(struct device *dev);

EXPORT_SYMBOL(bcmsdh_probe);
EXPORT_SYMBOL(bcmsdh_remove);

#else
/* forward declarations */
static int __devinit bcmsdh_probe(struct device *dev);
static int __devexit bcmsdh_remove(struct device *dev);
#endif 

#if !defined(BCMLXSDMMC)
static
#endif 
int bcmsdh_probe(struct device *dev)
{
	osl_t *osh = NULL;
	bcmsdh_hc_t *sdhc = NULL;
	ulong regs = 0;
	bcmsdh_info_t *sdh = NULL;
#if !defined(BCMLXSDMMC) && defined(BCMPLATFORM_BUS)
	struct platform_device *pdev;
	struct resource *r;
#endif 
	int irq = 0;
	uint32 vendevid;
	unsigned long irq_flags = 0;

#if !defined(BCMLXSDMMC) && defined(BCMPLATFORM_BUS)
	pdev = to_platform_device(dev);
	r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	irq = platform_get_irq(pdev, 0);
	if (!r || irq == NO_IRQ)
		return -ENXIO;
#endif 

#if defined(OOB_INTR_ONLY)
#ifdef HW_OOB
	irq_flags =
		IORESOURCE_IRQ | IORESOURCE_IRQ_HIGHLEVEL | IORESOURCE_IRQ_SHAREABLE;
#else
	 irq_flags = IRQF_TRIGGER_FALLING;
#endif /* HW_OOB */

	/* Get customer specific OOB IRQ parametres: IRQ number as IRQ type */
	irq = dhd_customer_oob_irq_map(&irq_flags);
#if	defined(CONFIG_ARCH_RHEA) || defined(CONFIG_ARCH_CAPRI)
	/* Do not disable this IRQ during suspend */
	irq_flags |= IRQF_NO_SUSPEND;
#endif /* defined(CONFIG_ARCH_RHEA) || defined(CONFIG_ARCH_CAPRI) */
	if  (irq < 0) {
		SDLX_MSG(("%s: Host irq is not defined\n", __FUNCTION__));
		return 1;
	}
#endif 
	/* allocate SDIO Host Controller state info */
	if (!(osh = osl_attach(dev, PCI_BUS, FALSE))) {
		SDLX_MSG(("%s: osl_attach failed\n", __FUNCTION__));
=======
void* bcmsdh_probe(osl_t *osh, void *dev, void *sdioh, void *adapter_info, uint bus_type,
	uint bus_num, uint slot_num)
{
	ulong regs;
	bcmsdh_info_t *bcmsdh;
	uint32 vendevid;
	bcmsdh_os_info_t *bcmsdh_osinfo = NULL;

	bcmsdh = bcmsdh_attach(osh, sdioh, &regs);
	if (bcmsdh == NULL) {
		SDLX_MSG(("%s: bcmsdh_attach failed\n", __FUNCTION__));
>>>>>>> 90123ab... Update Wi-Fi drivers to 1.141.44 (coming from N5100 kernel drop)
		goto err;
	}
	bcmsdh_osinfo = MALLOC(osh, sizeof(bcmsdh_os_info_t));
	if (bcmsdh_osinfo == NULL) {
		SDLX_MSG(("%s: failed to allocate bcmsdh_os_info_t\n", __FUNCTION__));
		goto err;
	}
	bzero((char *)bcmsdh_osinfo, sizeof(bcmsdh_os_info_t));
	bcmsdh->os_cxt = bcmsdh_osinfo;
	bcmsdh_osinfo->sdioh = sdioh;
	bcmsdh_osinfo->dev = dev;
	osl_set_bus_handle(osh, bcmsdh);

#if !defined(CONFIG_HAS_WAKELOCK) && (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36))
	if (dev && device_init_wakeup(dev, true) == 0)
		bcmsdh_osinfo->dev_wake_enabled = TRUE;
#endif /* !defined(CONFIG_HAS_WAKELOCK) && (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36)) */

<<<<<<< HEAD
#if defined(BCMLXSDMMC)
	if (!(sdh = bcmsdh_attach(osh, (void *)0,
	                          (void **)&regs, irq))) {
		SDLX_MSG(("%s: bcmsdh_attach failed\n", __FUNCTION__));
		goto err;
	}
#else
	if (!(sdh = bcmsdh_attach(osh, (void *)r->start,
	                          (void **)&regs, irq))) {
		SDLX_MSG(("%s: bcmsdh_attach failed\n", __FUNCTION__));
		goto err;
	}
#endif 
	sdhc->sdh = sdh;
	sdhc->oob_irq = irq;
	sdhc->oob_flags = irq_flags;
	sdhc->oob_irq_registered = FALSE;	/* to make sure.. */
	sdhc->oob_irq_enable_flag = FALSE;
#if defined(OOB_INTR_ONLY)
	spin_lock_init(&sdhc->irq_lock);
#endif 

	/* chain SDIO Host Controller info together */
	sdhc->next = sdhcinfo;
	sdhcinfo = sdhc;
=======
#if defined(OOB_INTR_ONLY)
	spin_lock_init(&bcmsdh_osinfo->oob_irq_spinlock);
	/* Get customer specific OOB IRQ parametres: IRQ number as IRQ type */
	bcmsdh_osinfo->oob_irq_num = wifi_platform_get_irq_number(adapter_info,
		&bcmsdh_osinfo->oob_irq_flags);
	if  (bcmsdh_osinfo->oob_irq_num < 0) {
		SDLX_MSG(("%s: Host OOB irq is not defined\n", __FUNCTION__));
		goto err;
	}
#endif /* defined(BCMLXSDMMC) */
>>>>>>> 90123ab... Update Wi-Fi drivers to 1.141.44 (coming from N5100 kernel drop)


	/* Read the vendor/device ID from the CIS */
	vendevid = bcmsdh_query_device(bcmsdh);
	/* try to attach to the target device */
	bcmsdh_osinfo->context = drvinfo.probe((vendevid >> 16), (vendevid & 0xFFFF), bus_num,
		slot_num, 0, bus_type, (void *)regs, osh, bcmsdh);
	if (bcmsdh_osinfo->context == NULL) {
		SDLX_MSG(("%s: device attach failed\n", __FUNCTION__));
		goto err;
	}

	return bcmsdh;

	/* error handling */
err:
<<<<<<< HEAD
	if (sdhc) {
		if (sdhc->sdh)
			bcmsdh_detach(sdhc->osh, sdhc->sdh);
		MFREE(osh, sdhc, sizeof(bcmsdh_hc_t));
	}
	if (osh)
		osl_detach(osh);
	return -ENODEV;
}

#if !defined(BCMLXSDMMC)
static
#endif 
int bcmsdh_remove(struct device *dev)
{
	bcmsdh_hc_t *sdhc, *prev;
	osl_t *osh;

	sdhc = sdhcinfo;
	drvinfo.detach(sdhc->ch);
	bcmsdh_detach(sdhc->osh, sdhc->sdh);

	/* find the SDIO Host Controller state for this pdev and take it out from the list */
	for (sdhc = sdhcinfo, prev = NULL; sdhc; sdhc = sdhc->next) {
		if (sdhc->dev == (void *)dev) {
			if (prev)
				prev->next = sdhc->next;
			else
				sdhcinfo = NULL;
			break;
		}
		prev = sdhc;
	}
	if (!sdhc) {
		SDLX_MSG(("%s: failed\n", __FUNCTION__));
		return 0;
	}

	/* release SDIO Host Controller info */
	osh = sdhc->osh;
	MFREE(osh, sdhc, sizeof(bcmsdh_hc_t));
	osl_detach(osh);

#if !defined(BCMLXSDMMC) || defined(OOB_INTR_ONLY)
	dev_set_drvdata(dev, NULL);
#endif 
=======
	if (bcmsdh != NULL)
		bcmsdh_detach(osh, bcmsdh);
	if (bcmsdh_osinfo != NULL)
		MFREE(osh, bcmsdh_osinfo, sizeof(bcmsdh_os_info_t));
	return NULL;
}

int bcmsdh_remove(bcmsdh_info_t *bcmsdh)
{
	bcmsdh_os_info_t *bcmsdh_osinfo = bcmsdh->os_cxt;

#if !defined(CONFIG_HAS_WAKELOCK) && (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36))
	if (bcmsdh_osinfo->dev)
		device_init_wakeup(bcmsdh_osinfo->dev, false);
	bcmsdh_osinfo->dev_wake_enabled = FALSE;
#endif /* !defined(CONFIG_HAS_WAKELOCK) && (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36)) */

	drvinfo.remove(bcmsdh_osinfo->context);
	MFREE(bcmsdh->osh, bcmsdh->os_cxt, sizeof(bcmsdh_os_info_t));
	bcmsdh_detach(bcmsdh->osh, bcmsdh);
>>>>>>> 90123ab... Update Wi-Fi drivers to 1.141.44 (coming from N5100 kernel drop)

	return 0;
}

int bcmsdh_suspend(bcmsdh_info_t *bcmsdh)
{
	bcmsdh_os_info_t *bcmsdh_osinfo = bcmsdh->os_cxt;

	if (drvinfo.suspend && drvinfo.suspend(bcmsdh_osinfo->context))
		return -EBUSY;
	return 0;
}

int bcmsdh_resume(bcmsdh_info_t *bcmsdh)
{
	bcmsdh_os_info_t *bcmsdh_osinfo = bcmsdh->os_cxt;

	if (drvinfo.resume)
		return drvinfo.resume(bcmsdh_osinfo->context);
	return 0;
}
<<<<<<< HEAD
#endif /* BCMLXSDMMC */
#endif /* BCMPLATFORM_BUS */

extern int sdio_function_init(void);
=======
>>>>>>> 90123ab... Update Wi-Fi drivers to 1.141.44 (coming from N5100 kernel drop)

extern int bcmsdh_register_client_driver(void);
extern void bcmsdh_unregister_client_driver(void);
extern int sdio_func_reg_notify(void* semaphore);
extern void sdio_func_unreg_notify(void);

#if defined(BCMLXSDMMC)
int bcmsdh_reg_sdio_notify(void* semaphore)
{
	return sdio_func_reg_notify(semaphore);
}

void bcmsdh_unreg_sdio_notify(void)
{
	sdio_func_unreg_notify();
}
#endif /* defined(BCMLXSDMMC) */

int
bcmsdh_register(bcmsdh_driver_t *driver)
{
	int error = 0;

	drvinfo = *driver;
	SDLX_MSG(("%s: register client driver\n", __FUNCTION__));
	error = bcmsdh_register_client_driver();
	if (error)
		SDLX_MSG(("%s: failed %d\n", __FUNCTION__, error));

<<<<<<< HEAD
#if defined(BCMPLATFORM_BUS)
	SDLX_MSG(("Linux Kernel SDIO/MMC Driver\n"));
	error = sdio_function_init();
=======
>>>>>>> 90123ab... Update Wi-Fi drivers to 1.141.44 (coming from N5100 kernel drop)
	return error;
}

void
bcmsdh_unregister(void)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0))
		if (bcmsdh_pci_driver.node.next == NULL)
			return;
#endif

	bcmsdh_unregister_client_driver();
}

<<<<<<< HEAD
extern void sdio_function_cleanup(void);
=======
void bcmsdh_dev_pm_stay_awake(bcmsdh_info_t *bcmsdh)
{
#if !defined(CONFIG_HAS_WAKELOCK) && (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36))
	bcmsdh_os_info_t *bcmsdh_osinfo = bcmsdh->os_cxt;
	pm_stay_awake(bcmsdh_osinfo->dev);
#endif /* !defined(CONFIG_HAS_WAKELOCK) && (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36)) */
}
>>>>>>> 90123ab... Update Wi-Fi drivers to 1.141.44 (coming from N5100 kernel drop)

void bcmsdh_dev_relax(bcmsdh_info_t *bcmsdh)
{
#if !defined(CONFIG_HAS_WAKELOCK) && (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36))
	bcmsdh_os_info_t *bcmsdh_osinfo = bcmsdh->os_cxt;
	pm_relax(bcmsdh_osinfo->dev);
#endif /* !defined(CONFIG_HAS_WAKELOCK) && (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 36)) */
}

<<<<<<< HEAD
#if defined(BCMLXSDMMC)
	sdio_function_cleanup();
#endif /* BCMLXSDMMC */
=======
bool bcmsdh_dev_pm_enabled(bcmsdh_info_t *bcmsdh)
{
	bcmsdh_os_info_t *bcmsdh_osinfo = bcmsdh->os_cxt;
>>>>>>> 90123ab... Update Wi-Fi drivers to 1.141.44 (coming from N5100 kernel drop)

	return bcmsdh_osinfo->dev_wake_enabled;
}

<<<<<<< HEAD
#if defined(OOB_INTR_ONLY)
void bcmsdh_oob_intr_set(bool enable)
=======
#if defined(OOB_INTR_ONLY) || defined(BCMSPI_ANDROID)
void bcmsdh_oob_intr_set(bcmsdh_info_t *bcmsdh, bool enable)
>>>>>>> 90123ab... Update Wi-Fi drivers to 1.141.44 (coming from N5100 kernel drop)
{
	unsigned long flags;
	bcmsdh_os_info_t *bcmsdh_osinfo;

	if (!bcmsdh)
		return;

	bcmsdh_osinfo = bcmsdh->os_cxt;
	spin_lock_irqsave(&bcmsdh_osinfo->oob_irq_spinlock, flags);
	if (bcmsdh_osinfo->oob_irq_enabled != enable) {
		if (enable)
			enable_irq(bcmsdh_osinfo->oob_irq_num);
		else
			disable_irq_nosync(bcmsdh_osinfo->oob_irq_num);
		bcmsdh_osinfo->oob_irq_enabled = enable;
	}
	spin_unlock_irqrestore(&bcmsdh_osinfo->oob_irq_spinlock, flags);
}

static irqreturn_t wlan_oob_irq(int irq, void *dev_id)
{
	bcmsdh_info_t *bcmsdh = (bcmsdh_info_t *)dev_id;
	bcmsdh_os_info_t *bcmsdh_osinfo = bcmsdh->os_cxt;

<<<<<<< HEAD
	bcmsdh_oob_intr_set(0);

	if (dhdp == NULL) {
		SDLX_MSG(("Out of band GPIO interrupt fired way too early\n"));
		return IRQ_HANDLED;
	}

	dhdsdio_isr((void *)dhdp->bus);
=======
#ifndef BCMSPI_ANDROID
	bcmsdh_oob_intr_set(bcmsdh, FALSE);
#endif /* !BCMSPI_ANDROID */
	bcmsdh_osinfo->oob_irq_handler(bcmsdh_osinfo->oob_irq_handler_context);
>>>>>>> 90123ab... Update Wi-Fi drivers to 1.141.44 (coming from N5100 kernel drop)

	return IRQ_HANDLED;
}

int bcmsdh_oob_intr_register(bcmsdh_info_t *bcmsdh, bcmsdh_cb_fn_t oob_irq_handler,
	void* oob_irq_handler_context)
{
	int err = 0;
	bcmsdh_os_info_t *bcmsdh_osinfo = bcmsdh->os_cxt;

	SDLX_MSG(("%s: Enter\n", __FUNCTION__));
	if (bcmsdh_osinfo->oob_irq_registered) {
		SDLX_MSG(("%s: irq is already registered\n", __FUNCTION__));
		return -EBUSY;
	}
	SDLX_MSG(("%s OOB irq=%d flags=%X \n", __FUNCTION__,
		(int)bcmsdh_osinfo->oob_irq_num, (int)bcmsdh_osinfo->oob_irq_flags));
	bcmsdh_osinfo->oob_irq_handler = oob_irq_handler;
	bcmsdh_osinfo->oob_irq_handler_context = oob_irq_handler_context;
	err = request_irq(bcmsdh_osinfo->oob_irq_num, wlan_oob_irq,
		bcmsdh_osinfo->oob_irq_flags, "bcmsdh_sdmmc", bcmsdh);
	if (err) {
		SDLX_MSG(("%s: request_irq failed with %d\n", __FUNCTION__, err));
		return err;
	}

#if defined(CONFIG_ARCH_RHEA) || defined(CONFIG_ARCH_CAPRI)
	if (device_may_wakeup(bcmsdh_osinfo->dev)) {
#endif /* CONFIG_ARCH_RHEA || CONFIG_ARCH_CAPRI */
		err = enable_irq_wake(bcmsdh_osinfo->oob_irq_num);
		if (!err)
			bcmsdh_osinfo->oob_irq_wake_enabled = TRUE;
#if defined(CONFIG_ARCH_RHEA) || defined(CONFIG_ARCH_CAPRI)
	}
#endif /* CONFIG_ARCH_RHEA || CONFIG_ARCH_CAPRI */
	bcmsdh_osinfo->oob_irq_enabled = TRUE;
	bcmsdh_osinfo->oob_irq_registered = TRUE;
	return err;
}

void bcmsdh_oob_intr_unregister(bcmsdh_info_t *bcmsdh)
{
	int err = 0;
	bcmsdh_os_info_t *bcmsdh_osinfo = bcmsdh->os_cxt;

	SDLX_MSG(("%s: Enter\n", __FUNCTION__));
	if (!bcmsdh_osinfo->oob_irq_registered) {
		SDLX_MSG(("%s: irq is not registered\n", __FUNCTION__));
		return;
	}
	if (bcmsdh_osinfo->oob_irq_wake_enabled) {
#if defined(CONFIG_ARCH_RHEA) || defined(CONFIG_ARCH_CAPRI)
<<<<<<< HEAD
			if (device_may_wakeup(sdhcinfo->dev))
#endif
				enable_irq_wake(sdhcinfo->oob_irq);
		} else {
#if defined(CONFIG_ARCH_RHEA) || defined(CONFIG_ARCH_CAPRI)
			if (device_may_wakeup(sdhcinfo->dev))
#endif
				disable_irq_wake(sdhcinfo->oob_irq);
			disable_irq(sdhcinfo->oob_irq);
=======
		if (device_may_wakeup(bcmsdh_osinfo->dev)) {
#endif /* CONFIG_ARCH_RHEA || CONFIG_ARCH_CAPRI */
			err = disable_irq_wake(bcmsdh_osinfo->oob_irq_num);
			if (!err)
				bcmsdh_osinfo->oob_irq_wake_enabled = FALSE;
#if defined(CONFIG_ARCH_RHEA) || defined(CONFIG_ARCH_CAPRI)
>>>>>>> 90123ab... Update Wi-Fi drivers to 1.141.44 (coming from N5100 kernel drop)
		}
#endif /* CONFIG_ARCH_RHEA || CONFIG_ARCH_CAPRI */
	}
	if (bcmsdh_osinfo->oob_irq_enabled) {
		disable_irq(bcmsdh_osinfo->oob_irq_num);
		bcmsdh_osinfo->oob_irq_enabled = FALSE;
	}
	free_irq(bcmsdh_osinfo->oob_irq_num, bcmsdh);
	bcmsdh_osinfo->oob_irq_registered = FALSE;
}
#endif 

/* Module parameters specific to each host-controller driver */

extern uint sd_msglevel;	/* Debug message level */
module_param(sd_msglevel, uint, 0);

extern uint sd_power;	/* 0 = SD Power OFF, 1 = SD Power ON. */
module_param(sd_power, uint, 0);

extern uint sd_clock;	/* SD Clock Control, 0 = SD Clock OFF, 1 = SD Clock ON */
module_param(sd_clock, uint, 0);

extern uint sd_divisor;	/* Divisor (-1 means external clock) */
module_param(sd_divisor, uint, 0);

extern uint sd_sdmode;	/* Default is SD4, 0=SPI, 1=SD1, 2=SD4 */
module_param(sd_sdmode, uint, 0);

extern uint sd_hiok;	/* Ok to use hi-speed mode */
module_param(sd_hiok, uint, 0);

extern uint sd_f2_blocksize;
module_param(sd_f2_blocksize, int, 0);

#ifdef BCMSDIOH_STD
extern int sd_uhsimode;
module_param(sd_uhsimode, int, 0);
extern uint sd_tuning_period;
module_param(sd_tuning_period, uint, 0);
extern int sd_delay_value;
module_param(sd_delay_value, uint, 0);

/* SDIO Drive Strength for UHSI mode specific to SDIO3.0 */
extern char dhd_sdiod_uhsi_ds_override[2];
module_param_string(dhd_sdiod_uhsi_ds_override, dhd_sdiod_uhsi_ds_override, 2, 0);

#endif

#ifdef BCMSDH_MODULE
EXPORT_SYMBOL(bcmsdh_attach);
EXPORT_SYMBOL(bcmsdh_detach);
EXPORT_SYMBOL(bcmsdh_intr_query);
EXPORT_SYMBOL(bcmsdh_intr_enable);
EXPORT_SYMBOL(bcmsdh_intr_disable);
EXPORT_SYMBOL(bcmsdh_intr_reg);
EXPORT_SYMBOL(bcmsdh_intr_dereg);

#if defined(DHD_DEBUG)
EXPORT_SYMBOL(bcmsdh_intr_pending);
#endif

EXPORT_SYMBOL(bcmsdh_devremove_reg);
EXPORT_SYMBOL(bcmsdh_cfg_read);
EXPORT_SYMBOL(bcmsdh_cfg_write);
EXPORT_SYMBOL(bcmsdh_cis_read);
EXPORT_SYMBOL(bcmsdh_reg_read);
EXPORT_SYMBOL(bcmsdh_reg_write);
EXPORT_SYMBOL(bcmsdh_regfail);
EXPORT_SYMBOL(bcmsdh_send_buf);
EXPORT_SYMBOL(bcmsdh_recv_buf);

EXPORT_SYMBOL(bcmsdh_rwdata);
EXPORT_SYMBOL(bcmsdh_abort);
EXPORT_SYMBOL(bcmsdh_query_device);
EXPORT_SYMBOL(bcmsdh_query_iofnum);
EXPORT_SYMBOL(bcmsdh_iovar_op);
EXPORT_SYMBOL(bcmsdh_register);
EXPORT_SYMBOL(bcmsdh_unregister);
EXPORT_SYMBOL(bcmsdh_chipmatch);
EXPORT_SYMBOL(bcmsdh_reset);
EXPORT_SYMBOL(bcmsdh_waitlockfree);

EXPORT_SYMBOL(bcmsdh_get_dstatus);
EXPORT_SYMBOL(bcmsdh_cfg_read_word);
EXPORT_SYMBOL(bcmsdh_cfg_write_word);
EXPORT_SYMBOL(bcmsdh_cur_sbwad);
EXPORT_SYMBOL(bcmsdh_chipinfo);

#endif /* BCMSDH_MODULE */
