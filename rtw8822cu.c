// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#include <linux/module.h>
#include <linux/usb.h>
#include "rtw8822cu.h"

static const struct usb_device_id rtw_8822cu_id_table[] = {
	{ RTK_USB_DEVICE_AND_INTERFACE(RTW_USB_VENDOR_ID_REALTEK,
				       RTW_USB_PRODUCT_ID_REALTEK_8822C,
				       0xff, 0xff, 0xff,
				       rtw8822c_hw_spec) },
	{ RTK_USB_DEVICE_AND_INTERFACE(RTW_USB_VENDOR_ID_REALTEK,
				       0xb82b,
				       0xff, 0xff, 0xff,
				       rtw8822c_hw_spec) },
	{ RTK_USB_DEVICE_AND_INTERFACE(RTW_USB_VENDOR_ID_REALTEK,
				       0xb820,
				       0xff, 0xff, 0xff,
				       rtw8822c_hw_spec) },
	{ RTK_USB_DEVICE_AND_INTERFACE(RTW_USB_VENDOR_ID_REALTEK,
				       0xC821,
				       0xff, 0xff, 0xff,
				       rtw8822c_hw_spec) },
	{ RTK_USB_DEVICE_AND_INTERFACE(RTW_USB_VENDOR_ID_REALTEK,
				       0xC820,
				       0xff, 0xff, 0xff,
				       rtw8822c_hw_spec) },
	{ RTK_USB_DEVICE_AND_INTERFACE(RTW_USB_VENDOR_ID_REALTEK,
				       0xC82A,
				       0xff, 0xff, 0xff,
				       rtw8822c_hw_spec) },
	{ RTK_USB_DEVICE_AND_INTERFACE(RTW_USB_VENDOR_ID_REALTEK,
				       0xC82B,
				       0xff, 0xff, 0xff,
				       rtw8822c_hw_spec) },
	{},
};
MODULE_DEVICE_TABLE(usb, rtw_8822cu_id_table);

static struct usb_driver rtw_8822cu_driver = {
	.name = "rtw_8822cu",
	.id_table = rtw_8822cu_id_table,
	.probe = rtw_usb_probe,
	.disconnect = rtw_usb_disconnect,
};
module_usb_driver(rtw_8822cu_driver);

MODULE_AUTHOR("Realtek Corporation");
MODULE_DESCRIPTION("Realtek 802.11ac wireless 8822cu driver");
MODULE_LICENSE("Dual BSD/GPL");