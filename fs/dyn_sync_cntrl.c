/*
 * Author: Paul Reioux aka Faux123 <reioux@gmail.com>
 *
<<<<<<< HEAD
 * Copyright 2013 Paul Reioux
=======
>>>>>>> c1e362e... fs/dyn_sync_cntrl: dynamic sync control
 * Copyright 2012 Paul Reioux
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/earlysuspend.h>
#include <linux/mutex.h>
<<<<<<< HEAD
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/writeback.h>

#define DYN_FSYNC_VERSION_MAJOR 1
#define DYN_FSYNC_VERSION_MINOR 2

/*
 * fsync_mutex protects dyn_fsync_active during early suspend / late resume
 * transitions
 */
static DEFINE_MUTEX(fsync_mutex);

bool early_suspend_active __read_mostly = false;
bool dyn_fsync_active __read_mostly = true;

static ssize_t dyn_fsync_active_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
=======

#include <linux/writeback.h>

#define DYN_FSYNC_VERSION 1

/*
 * fsync_mutex protects dyn_fsync_active during early suspend / lat resume transitions
 */
static DEFINE_MUTEX(fsync_mutex);

bool early_suspend_active = false;
static bool dyn_fsync_active = true;

static ssize_t dyn_fsync_active_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
>>>>>>> c1e362e... fs/dyn_sync_cntrl: dynamic sync control
{
	return sprintf(buf, "%u\n", (dyn_fsync_active ? 1 : 0));
}

<<<<<<< HEAD
static ssize_t dyn_fsync_active_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
=======
static ssize_t dyn_fsync_active_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
>>>>>>> c1e362e... fs/dyn_sync_cntrl: dynamic sync control
{
	unsigned int data;

	if(sscanf(buf, "%u\n", &data) == 1) {
		if (data == 1) {
			pr_info("%s: dynamic fsync enabled\n", __FUNCTION__);
			dyn_fsync_active = true;
		}
		else if (data == 0) {
			pr_info("%s: dyanamic fsync disabled\n", __FUNCTION__);
			dyn_fsync_active = false;
		}
		else
			pr_info("%s: bad value: %u\n", __FUNCTION__, data);
	} else
		pr_info("%s: unknown input!\n", __FUNCTION__);

	return count;
}

<<<<<<< HEAD
static ssize_t dyn_fsync_version_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "version: %u.%u by faux123\n",
		DYN_FSYNC_VERSION_MAJOR,
		DYN_FSYNC_VERSION_MINOR);
}

static ssize_t dyn_fsync_earlysuspend_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
=======
static ssize_t dyn_fsync_version_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "version: %u\n", DYN_FSYNC_VERSION);
}

static ssize_t dyn_fsync_earlysuspend_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
>>>>>>> c1e362e... fs/dyn_sync_cntrl: dynamic sync control
{
	return sprintf(buf, "early suspend active: %u\n", early_suspend_active);
}

<<<<<<< HEAD
static struct kobj_attribute dyn_fsync_active_attribute =
	__ATTR(Dyn_fsync_active, 0666,
		dyn_fsync_active_show,
		dyn_fsync_active_store);

static struct kobj_attribute dyn_fsync_version_attribute =
	__ATTR(Dyn_fsync_version, 0444, dyn_fsync_version_show, NULL);

static struct kobj_attribute dyn_fsync_earlysuspend_attribute =
	__ATTR(Dyn_fsync_earlysuspend, 0444, dyn_fsync_earlysuspend_show, NULL);
=======
static struct kobj_attribute dyn_fsync_active_attribute = 
	__ATTR(Dyn_fsync_active, 0666, dyn_fsync_active_show, dyn_fsync_active_store);

static struct kobj_attribute dyn_fsync_version_attribute = 
	__ATTR(Dyn_fsync_version, 0444 , dyn_fsync_version_show, NULL);

static struct kobj_attribute dyn_fsync_earlysuspend_attribute = 
	__ATTR(Dyn_fsync_earlysuspend, 0444 , dyn_fsync_earlysuspend_show, NULL);
>>>>>>> c1e362e... fs/dyn_sync_cntrl: dynamic sync control

static struct attribute *dyn_fsync_active_attrs[] =
	{
		&dyn_fsync_active_attribute.attr,
		&dyn_fsync_version_attribute.attr,
		&dyn_fsync_earlysuspend_attribute.attr,
		NULL,
	};

static struct attribute_group dyn_fsync_active_attr_group =
	{
		.attrs = dyn_fsync_active_attrs,
	};

static struct kobject *dyn_fsync_kobj;

<<<<<<< HEAD
static void dyn_fsync_force_flush(void)
{
	/* flush all outstanding buffers */
	wakeup_flusher_threads(0);
	sync_filesystems(0);
	sync_filesystems(1);
}

=======
>>>>>>> c1e362e... fs/dyn_sync_cntrl: dynamic sync control
static void dyn_fsync_early_suspend(struct early_suspend *h)
{
	mutex_lock(&fsync_mutex);
	if (dyn_fsync_active) {
		early_suspend_active = true;
<<<<<<< HEAD
		dyn_fsync_force_flush();
=======
#if 1
		/* flush all outstanding buffers */
		wakeup_flusher_threads(0);
		sync_filesystems(0);
		sync_filesystems(1);
#endif
>>>>>>> c1e362e... fs/dyn_sync_cntrl: dynamic sync control
	}
	mutex_unlock(&fsync_mutex);
}

static void dyn_fsync_late_resume(struct early_suspend *h)
{
	mutex_lock(&fsync_mutex);
	early_suspend_active = false;
	mutex_unlock(&fsync_mutex);
}

<<<<<<< HEAD
static struct early_suspend dyn_fsync_early_suspend_handler =
=======
static struct early_suspend dyn_fsync_early_suspend_handler = 
>>>>>>> c1e362e... fs/dyn_sync_cntrl: dynamic sync control
	{
		.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN,
		.suspend = dyn_fsync_early_suspend,
		.resume = dyn_fsync_late_resume,
	};

<<<<<<< HEAD
static int dyn_fsync_panic_event(struct notifier_block *this,
		unsigned long event, void *ptr)
{
	early_suspend_active = true;
	dyn_fsync_force_flush();
	//pr_warn("dyn fsync: panic: force flush!\n");

	return NOTIFY_DONE;
}

static struct notifier_block dyn_fsync_panic_block = {
	.notifier_call  = dyn_fsync_panic_event,
	.priority       = INT_MAX,
};

static int dyn_fsync_notify_sys(struct notifier_block *this, unsigned long code,
				void *unused)
{
	if (code == SYS_DOWN || code == SYS_HALT) {
		early_suspend_active = true;
		dyn_fsync_force_flush();
		//pr_warn("dyn fsync: reboot: force flush!\n");
	}
	return NOTIFY_DONE;
}

static struct notifier_block dyn_fsync_notifier = {
	.notifier_call = dyn_fsync_notify_sys,
};

=======
>>>>>>> c1e362e... fs/dyn_sync_cntrl: dynamic sync control
static int dyn_fsync_init(void)
{
	int sysfs_result;

	register_early_suspend(&dyn_fsync_early_suspend_handler);
<<<<<<< HEAD
	register_reboot_notifier(&dyn_fsync_notifier);
	atomic_notifier_chain_register(&panic_notifier_list,
		&dyn_fsync_panic_block);
=======
>>>>>>> c1e362e... fs/dyn_sync_cntrl: dynamic sync control

	dyn_fsync_kobj = kobject_create_and_add("dyn_fsync", kernel_kobj);
	if (!dyn_fsync_kobj) {
		pr_err("%s dyn_fsync kobject create failed!\n", __FUNCTION__);
		return -ENOMEM;
        }

<<<<<<< HEAD
	sysfs_result = sysfs_create_group(dyn_fsync_kobj,
			&dyn_fsync_active_attr_group);
=======
	sysfs_result = sysfs_create_group(dyn_fsync_kobj, &dyn_fsync_active_attr_group);
>>>>>>> c1e362e... fs/dyn_sync_cntrl: dynamic sync control

        if (sysfs_result) {
		pr_info("%s dyn_fsync sysfs create failed!\n", __FUNCTION__);
		kobject_put(dyn_fsync_kobj);
	}
	return sysfs_result;
}

static void dyn_fsync_exit(void)
{
	unregister_early_suspend(&dyn_fsync_early_suspend_handler);
<<<<<<< HEAD
	unregister_reboot_notifier(&dyn_fsync_notifier);
	atomic_notifier_chain_unregister(&panic_notifier_list,
		&dyn_fsync_panic_block);
=======
>>>>>>> c1e362e... fs/dyn_sync_cntrl: dynamic sync control

	if (dyn_fsync_kobj != NULL)
		kobject_put(dyn_fsync_kobj);
}

module_init(dyn_fsync_init);
module_exit(dyn_fsync_exit);
<<<<<<< HEAD
=======

>>>>>>> c1e362e... fs/dyn_sync_cntrl: dynamic sync control
