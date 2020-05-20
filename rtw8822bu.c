// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#include <linux/module.h>
#include <linux/usb.h>
#include "rtw8822bu.h"

static const struct usb_device_id rtw_8822bu_id_table[] = {
	{ RTK_USB_DEVICE_AND_INTERFACE(RTW_USB_VENDOR_ID_REALTEK,
				       RTW_USB_PRODUCT_ID_REALTEK_8812B,
				       0xff, 0xff, 0xff,
				       rtw8822b_hw_spec) },
	{ RTK_USB_DEVICE_AND_INTERFACE(RTW_USB_VENDOR_ID_REALTEK,
				       RTW_USB_PRODUCT_ID_REALTEK_8822B,
				       0xff, 0xff, 0xff,
				       rtw8822b_hw_spec) },
	{},
};
MODULE_DEVICE_TABLE(usb, rtw_8822bu_id_table);

static struct usb_driver rtw_8822bu_driver = {
	.name = "rtw_8822bu",
	.id_table = rtw_8822bu_id_table,
	.probe = rtw_usb_probe,
	.disconnect = rtw_usb_disconnect,
};
module_usb_driver(rtw_8822bu_driver);

MODULE_AUTHOR("Realtek Corporation");
MODULE_DESCRIPTION("Realtek 802.11ac wireless 8822bu driver");
MODULE_LICENSE("Dual BSD/GPL");
