/*
 * Linux cfg80211 driver - Dongle Host Driver (DHD) related
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
 * $Id: wl_cfg80211.c,v 1.1.4.1.2.14 2011/02/09 01:40:07 Exp $
 */

#include <linux/vmalloc.h>
#include <net/rtnetlink.h>

#include <bcmutils.h>
#include <wldev_common.h>
#include <wl_cfg80211.h>
#include <brcm_nl80211.h>
#include <dhd_cfg80211.h>

#ifdef PKT_FILTER_SUPPORT
#include <dngl_stats.h>
#include <dhd.h>
#endif

extern struct bcm_cfg80211 *g_bcm_cfg;

#ifdef PKT_FILTER_SUPPORT
extern uint dhd_pkt_filter_enable;
extern uint dhd_master_mode;
extern void dhd_pktfilter_offload_enable(dhd_pub_t * dhd, char *arg, int enable, int master_mode);
#endif

static int dhd_dongle_up = FALSE;

#include <dngl_stats.h>
#include <dhd.h>
#include <dhdioctl.h>
#include <wlioctl.h>
#include <dhd_cfg80211.h>

static s32 wl_dongle_up(struct net_device *ndev, u32 up);

/**
 * Function implementations
 */

s32 dhd_cfg80211_init(struct bcm_cfg80211 *cfg)
{
	dhd_dongle_up = FALSE;
	return 0;
}

s32 dhd_cfg80211_deinit(struct bcm_cfg80211 *cfg)
{
	dhd_dongle_up = FALSE;
	return 0;
}

s32 dhd_cfg80211_down(struct bcm_cfg80211 *cfg)
{
	dhd_dongle_up = FALSE;
	return 0;
}

s32 dhd_cfg80211_set_p2p_info(struct bcm_cfg80211 *cfg, int val)
{
	dhd_pub_t *dhd =  (dhd_pub_t *)(cfg->pub);
	dhd->op_mode |= val;
	WL_ERR(("Set : op_mode=0x%04x\n", dhd->op_mode));
#ifdef ARP_OFFLOAD_SUPPORT
	if (dhd->arp_version == 1) {
		/* IF P2P is enabled, disable arpoe */
		dhd_arp_offload_set(dhd, 0);
		dhd_arp_offload_enable(dhd, false);
	}
#endif /* ARP_OFFLOAD_SUPPORT */

	return 0;
}

s32 dhd_cfg80211_clean_p2p_info(struct bcm_cfg80211 *cfg)
{
	dhd_pub_t *dhd =  (dhd_pub_t *)(cfg->pub);
	dhd->op_mode &= ~(DHD_FLAG_P2P_GC_MODE | DHD_FLAG_P2P_GO_MODE);
	WL_ERR(("Clean : op_mode=0x%04x\n", dhd->op_mode));

#ifdef ARP_OFFLOAD_SUPPORT
	if (dhd->arp_version == 1) {
		/* IF P2P is disabled, enable arpoe back for STA mode. */
		dhd_arp_offload_set(dhd, dhd_arp_mode);
		dhd_arp_offload_enable(dhd, true);
	}
#endif /* ARP_OFFLOAD_SUPPORT */

	return 0;
}

struct net_device* wl_cfg80211_allocate_if(struct bcm_cfg80211 *cfg, int ifidx, char *name,
	uint8 *mac, uint8 bssidx)
{
	return dhd_allocate_if(cfg->pub, ifidx, name, mac, bssidx, FALSE);
}

int wl_cfg80211_register_if(struct bcm_cfg80211 *cfg, int ifidx, struct net_device* ndev)
{
	return dhd_register_if(cfg->pub, ifidx, FALSE);
}

int wl_cfg80211_remove_if(struct bcm_cfg80211 *cfg, int ifidx, struct net_device* ndev)
{
	return dhd_remove_if(cfg->pub, ifidx, FALSE);
}

static s32 wl_dongle_up(struct net_device *ndev, u32 up)
{
	s32 err = 0;

	err = wldev_ioctl(ndev, WLC_UP, &up, sizeof(up), true);
	if (unlikely(err)) {
		WL_ERR(("WLC_UP error (%d)\n", err));
	}
	return err;
}

s32 dhd_config_dongle(struct bcm_cfg80211 *cfg)
{
#ifndef DHD_SDALIGN
#define DHD_SDALIGN	32
#endif
	struct net_device *ndev;
	s32 err = 0;

	WL_TRACE(("In\n"));
	if (dhd_dongle_up) {
		WL_ERR(("Dongle is already up\n"));
		return err;
	}

	ndev = bcmcfg_to_prmry_ndev(cfg);

	err = wl_dongle_up(ndev, 0);
	if (unlikely(err)) {
		WL_ERR(("wl_dongle_up failed\n"));
		goto default_conf_out;
	}
	dhd_dongle_up = true;

default_conf_out:

	return err;

}

#ifdef CONFIG_NL80211_TESTMODE
int dhd_cfg80211_testmode_cmd(struct wiphy *wiphy, void *data, int len)
{
<<<<<<< HEAD
	int ioc_res = 0;
	bool res = FALSE;
	int sco_id_cnt = 0;
	int param27;
	int i;

	for (i = 0; i < 12; i++) {

		ioc_res = dev_wlc_intvar_get_reg(dev, "btc_params", 27, &param27);

		WL_TRACE(("%s, sample[%d], btc params: 27:%x\n",
			__FUNCTION__, i, param27));

		if (ioc_res < 0) {
			WL_ERR(("%s ioc read btc params error\n", __FUNCTION__));
			break;
		}

		if ((param27 & 0x6) == 2) { /* count both sco & esco  */
			sco_id_cnt++;
		}

		if (sco_id_cnt > 2) {
			WL_TRACE(("%s, sco/esco detected, pkt id_cnt:%d  samples:%d\n",
				__FUNCTION__, sco_id_cnt, i));
			res = TRUE;
			break;
		}

		msleep(5);
=======
	struct sk_buff *reply;
	struct bcm_cfg80211 *cfg;
	dhd_pub_t *dhd;
	struct bcm_nlmsg_hdr *nlioc = data;
	dhd_ioctl_t ioc = { 0 };
	int err = 0;
	void *buf = NULL, *cur;
	u16 buflen;
	u16 maxmsglen = PAGE_SIZE - 0x100;
	bool newbuf = false;

	WL_TRACE(("entry: cmd = %d\n", nlioc->cmd));
	cfg = wiphy_priv(wiphy);
	dhd = cfg->pub;

	DHD_OS_WAKE_LOCK(dhd);

	/* send to dongle only if we are not waiting for reload already */
	if (dhd->hang_was_sent) {
		WL_ERR(("HANG was sent up earlier\n"));
		DHD_OS_WAKE_LOCK_CTRL_TIMEOUT_ENABLE(dhd, DHD_EVENT_TIMEOUT_MS);
		DHD_OS_WAKE_UNLOCK(dhd);
		return OSL_ERROR(BCME_DONGLE_DOWN);
>>>>>>> 90123ab... Update Wi-Fi drivers to 1.141.44 (coming from N5100 kernel drop)
	}

	len -= sizeof(struct bcm_nlmsg_hdr);

	if (nlioc->len > 0) {
		if (nlioc->len <= len) {
			buf = (void *)nlioc + nlioc->offset;
			*(char *)(buf + nlioc->len) = '\0';
		} else {
			if (nlioc->len > DHD_IOCTL_MAXLEN)
				nlioc->len = DHD_IOCTL_MAXLEN;
			buf = vzalloc(nlioc->len);
			if (!buf)
				return -ENOMEM;
			newbuf = true;
			memcpy(buf, (void *)nlioc + nlioc->offset, len);
			*(char *)(buf + len) = '\0';
		}
	}

	ioc.cmd = nlioc->cmd;
	ioc.len = nlioc->len;
	ioc.set = nlioc->set;
	ioc.driver = nlioc->magic;
	err = dhd_ioctl_process(dhd, 0, &ioc, buf);
	if (err) {
		WL_TRACE(("dhd_ioctl_process return err %d\n", err));
		err = OSL_ERROR(err);
		goto done;
	}

	cur = buf;
	while (nlioc->len > 0) {
		buflen = nlioc->len > maxmsglen ? maxmsglen : nlioc->len;
		nlioc->len -= buflen;
		reply = cfg80211_testmode_alloc_reply_skb(wiphy, buflen+4);
		if (!reply) {
			WL_ERR(("Failed to allocate reply msg\n"));
			err = -ENOMEM;
			break;
<<<<<<< HEAD

		default:
			WL_ERR(("%s error g_status=%d !!!\n", __FUNCTION__,
				btcx_inf->bt_state));
			if (btcx_inf->dev)
				wl_cfg80211_bt_setflag(btcx_inf->dev, FALSE);
			btcx_inf->bt_state = BT_DHCP_IDLE;
			btcx_inf->timer_on = 0;
			break;
	}

	net_os_wake_unlock(btcx_inf->dev);
}

int wl_cfg80211_btcoex_init(struct wl_priv *wl)
{
	struct btcoex_info *btco_inf = NULL;

	btco_inf = kmalloc(sizeof(struct btcoex_info), GFP_KERNEL);
	if (!btco_inf)
		return -ENOMEM;

	btco_inf->bt_state = BT_DHCP_IDLE;
	btco_inf->ts_dhcp_start = 0;
	btco_inf->ts_dhcp_ok = 0;
	/* Set up timer for BT  */
	btco_inf->timer_ms = 10;
	init_timer(&btco_inf->timer);
	btco_inf->timer.data = (ulong)btco_inf;
	btco_inf->timer.function = wl_cfg80211_bt_timerfunc;

	btco_inf->dev = wl->wdev->netdev;

	INIT_WORK(&btco_inf->work, wl_cfg80211_bt_handler);

	wl->btcoex_info = btco_inf;
	return 0;
}

void wl_cfg80211_btcoex_deinit(struct wl_priv *wl)
{
	if (!wl->btcoex_info)
		return;

	if (wl->btcoex_info->timer_on) {
		wl->btcoex_info->timer_on = 0;
		del_timer_sync(&wl->btcoex_info->timer);
	}

	cancel_work_sync(&wl->btcoex_info->work);

	kfree(wl->btcoex_info);
	wl->btcoex_info = NULL;
}
#endif 

int wl_cfg80211_set_btcoex_dhcp(struct net_device *dev, char *command)
{

	struct wl_priv *wl = wlcfg_drv_priv;
	char powermode_val = 0;
	char buf_reg66va_dhcp_on[8] = { 66, 00, 00, 00, 0x10, 0x27, 0x00, 0x00 };
	char buf_reg41va_dhcp_on[8] = { 41, 00, 00, 00, 0x33, 0x00, 0x00, 0x00 };
	char buf_reg68va_dhcp_on[8] = { 68, 00, 00, 00, 0x90, 0x01, 0x00, 0x00 };

	uint32 regaddr;
	static uint32 saved_reg66;
	static uint32 saved_reg41;
	static uint32 saved_reg68;
	static bool saved_status = FALSE;

#ifdef COEX_DHCP
	char buf_flag7_default[8] =   { 7, 00, 00, 00, 0x0, 0x00, 0x00, 0x00};
	struct btcoex_info *btco_inf = wl->btcoex_info;
#endif /* COEX_DHCP */

#ifdef PKT_FILTER_SUPPORT
	dhd_pub_t *dhd =  (dhd_pub_t *)(wl->pub);
#endif

	/* Figure out powermode 1 or o command */
	strncpy((char *)&powermode_val, command + strlen("BTCOEXMODE") +1, 1);

	if (strnicmp((char *)&powermode_val, "1", strlen("1")) == 0) {
		WL_TRACE_HW4(("%s: DHCP session starts\n", __FUNCTION__));

#if defined(DHCP_SCAN_SUPPRESS)
		/* Suppress scan during the DHCP */
		wl_cfg80211_scan_suppress(dev, 1);
#endif /* OEM_ANDROID */

#ifdef PKT_FILTER_SUPPORT
		dhd->dhcp_in_progress = 1;

		if (dhd->early_suspended) {
			WL_TRACE_HW4(("DHCP in progressing , disable packet filter!!!\n"));
			dhd_enable_packet_filter(0, dhd);
=======
>>>>>>> 90123ab... Update Wi-Fi drivers to 1.141.44 (coming from N5100 kernel drop)
		}

<<<<<<< HEAD
		/* Retrieve and saved orig regs value */
		if ((saved_status == FALSE) &&
			(!dev_wlc_intvar_get_reg(dev, "btc_params", 66,  &saved_reg66)) &&
			(!dev_wlc_intvar_get_reg(dev, "btc_params", 41,  &saved_reg41)) &&
			(!dev_wlc_intvar_get_reg(dev, "btc_params", 68,  &saved_reg68)))   {
				saved_status = TRUE;
				WL_TRACE(("Saved 0x%x 0x%x 0x%x\n",
					saved_reg66, saved_reg41, saved_reg68));

				/* Disable PM mode during dhpc session */

				/* Disable PM mode during dhpc session */
#ifdef COEX_DHCP
				/* Start  BT timer only for SCO connection */
				if (btcoex_is_sco_active(dev)) {
					/* btc_params 66 */
					dev_wlc_bufvar_set(dev, "btc_params",
						(char *)&buf_reg66va_dhcp_on[0],
						sizeof(buf_reg66va_dhcp_on));
					/* btc_params 41 0x33 */
					dev_wlc_bufvar_set(dev, "btc_params",
						(char *)&buf_reg41va_dhcp_on[0],
						sizeof(buf_reg41va_dhcp_on));
					/* btc_params 68 0x190 */
					dev_wlc_bufvar_set(dev, "btc_params",
						(char *)&buf_reg68va_dhcp_on[0],
						sizeof(buf_reg68va_dhcp_on));
					saved_status = TRUE;

					btco_inf->bt_state = BT_DHCP_START;
					btco_inf->timer_on = 1;
					mod_timer(&btco_inf->timer, btco_inf->timer.expires);
					WL_TRACE(("%s enable BT DHCP Timer\n",
					__FUNCTION__));
				}
#endif /* COEX_DHCP */
		}
		else if (saved_status == TRUE) {
			WL_ERR(("%s was called w/o DHCP OFF. Continue\n", __FUNCTION__));
		}
	}
	else if (strnicmp((char *)&powermode_val, "2", strlen("2")) == 0) {


#ifdef PKT_FILTER_SUPPORT
		dhd->dhcp_in_progress = 0;
		WL_TRACE_HW4(("%s: DHCP is complete \n", __FUNCTION__));

#if defined(DHCP_SCAN_SUPPRESS)
		/* Since DHCP is complete, enable the scan back */
		wl_cfg80211_scan_suppress(dev, 0);
#endif /* OEM_ANDROID */

		/* Enable packet filtering */
		if (dhd->early_suspended) {
			WL_TRACE_HW4(("DHCP is complete , enable packet filter!!!\n"));
			dhd_enable_packet_filter(1, dhd);
		}
#endif /* PKT_FILTER_SUPPORT */

		/* Restoring PM mode */

#ifdef COEX_DHCP
		/* Stop any bt timer because DHCP session is done */
		WL_TRACE(("%s disable BT DHCP Timer\n", __FUNCTION__));
		if (btco_inf->timer_on) {
			btco_inf->timer_on = 0;
			del_timer_sync(&btco_inf->timer);

			if (btco_inf->bt_state != BT_DHCP_IDLE) {
			/* need to restore original btc flags & extra btc params */
				WL_TRACE(("%s bt->bt_state:%d\n",
					__FUNCTION__, btco_inf->bt_state));
				/* wake up btcoex thread to restore btlags+params  */
				schedule_work(&btco_inf->work);
			}
=======
		if (nla_put(reply, BCM_NLATTR_DATA, buflen, cur) ||
			nla_put_u16(reply, BCM_NLATTR_LEN, buflen)) {
			kfree_skb(reply);
			err = -ENOBUFS;
			break;
>>>>>>> 90123ab... Update Wi-Fi drivers to 1.141.44 (coming from N5100 kernel drop)
		}

		do {
			err = cfg80211_testmode_reply(reply);
		} while (err == -EAGAIN);
		if (err) {
			WL_ERR(("testmode reply failed:%d\n", err));
			break;
		}
		cur += buflen;
	}

done:
	if (newbuf)
		vfree(buf);
	DHD_OS_WAKE_UNLOCK(dhd);
	return err;
}
#endif /* CONFIG_NL80211_TESTMODE */
