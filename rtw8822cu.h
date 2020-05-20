/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#ifndef __RTW_8822CU_H_
#define __RTW_8822CU_H_

/* USB Vendor/Product IDs */
#define RTW_USB_VENDOR_ID_REALTEK		0x0bda
#define RTW_USB_PRODUCT_ID_REALTEK_8822C	0xC82C

#define RTK_USB_DEVICE(vend, dev, hw_config)	\
	USB_DEVICE(vend, dev),			\
	.driver_info = (kernel_ulong_t)&(hw_config),

#define RTK_USB_DEVICE_AND_INTERFACE(vend, dev, cl, sc, pr, hw_config)	\
	USB_DEVICE_AND_INTERFACE_INFO(vend, dev, cl, sc, pr),		\
	.driver_info = (kernel_ulong_t)&(hw_config),

extern const struct dev_pm_ops rtw_pm_ops;
extern struct rtw_chip_info rtw8822c_hw_spec;
int rtw_usb_probe(struct usb_interface *intf, const struct usb_device_id *id);
void rtw_usb_disconnect(struct usb_interface *intf);

#endif
