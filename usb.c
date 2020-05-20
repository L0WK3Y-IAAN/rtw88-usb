// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2018-2019  Realtek Corporation
 */

#include <linux/module.h>
#include <linux/usb.h>
#include <linux/mutex.h>
#include "main.h"
#include "usb.h"
#include "reg.h"
#include "tx.h"
#include "rx.h"
#include "fw.h"
#include "ps.h"
#include "debug.h"

#define USB_MSG_TIMEOUT	3000 /* (ms) */

static inline void rtw_usb_fill_tx_checksum(struct rtw_usb *rtwusb,
					    struct sk_buff *skb, int agg_num)
{
	struct rtw_dev *rtwdev = rtwusb->rtwdev;
	struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_tx_pkt_info pkt_info;

	SET_TX_DESC_DMA_TXAGG_NUM(skb->data, agg_num);
	pkt_info.pkt_offset = GET_TX_DESC_PKT_OFFSET(skb->data);
	chip->ops->fill_txdesc_checksum(rtwdev, &pkt_info, skb->data);
}

static u8 rtw_usb_read8(struct rtw_dev *rtwdev, u32 addr)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	int len;
	u8 data;

	mutex_lock(&rtwusb->usb_buf_mutex);
	len = usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
			      RTW_USB_CMD_REQ, RTW_USB_CMD_READ,
			      addr, 0, &rtwusb->usb_buf.val8, sizeof(u8),
			      RTW_USB_CONTROL_MSG_TIMEOUT);
	data = rtwusb->usb_buf.val8;
	mutex_unlock(&rtwusb->usb_buf_mutex);

	return data;
}

static u16 rtw_usb_read16(struct rtw_dev *rtwdev, u32 addr)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	int len;
	u16 data;

	mutex_lock(&rtwusb->usb_buf_mutex);
	len = usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
			      RTW_USB_CMD_REQ, RTW_USB_CMD_READ,
			      addr, 0, &rtwusb->usb_buf.val16, sizeof(u16),
			      RTW_USB_CONTROL_MSG_TIMEOUT);
	data = le16_to_cpu(rtwusb->usb_buf.val16);
	mutex_unlock(&rtwusb->usb_buf_mutex);

	return data;
}

static u32 rtw_usb_read32(struct rtw_dev *rtwdev, u32 addr)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	int len;
	u32 data;

	mutex_lock(&rtwusb->usb_buf_mutex);
	len = usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
			      RTW_USB_CMD_REQ, RTW_USB_CMD_READ,
			      addr, 0, &rtwusb->usb_buf.val32, sizeof(u32),
			      RTW_USB_CONTROL_MSG_TIMEOUT);
	data = le32_to_cpu(rtwusb->usb_buf.val32);
	mutex_unlock(&rtwusb->usb_buf_mutex);

	return data;
}

static void rtw_usb_write8(struct rtw_dev *rtwdev, u32 addr, u8 val)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	int ret;

	mutex_lock(&rtwusb->usb_buf_mutex);
	rtwusb->usb_buf.val8 = val;
	ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			      RTW_USB_CMD_REQ, RTW_USB_CMD_WRITE,
			      addr, 0, &rtwusb->usb_buf.val8, sizeof(u8),
			      RTW_USB_CONTROL_MSG_TIMEOUT);

	mutex_unlock(&rtwusb->usb_buf_mutex);
}

static void rtw_usb_write16(struct rtw_dev *rtwdev, u32 addr, u16 val)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	int ret;

	mutex_lock(&rtwusb->usb_buf_mutex);
	rtwusb->usb_buf.val16 = cpu_to_le16(val);
	ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			      RTW_USB_CMD_REQ, RTW_USB_CMD_WRITE,
			      addr, 0, &rtwusb->usb_buf.val16, sizeof(u16),
			      RTW_USB_CONTROL_MSG_TIMEOUT);
	mutex_unlock(&rtwusb->usb_buf_mutex);
}

static void rtw_usb_write32(struct rtw_dev *rtwdev, u32 addr, u32 val)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct usb_device *udev = rtwusb->udev;
	int ret;

	mutex_lock(&rtwusb->usb_buf_mutex);
	rtwusb->usb_buf.val32 = cpu_to_le32(val);
	ret = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
			      RTW_USB_CMD_REQ, RTW_USB_CMD_WRITE,
			      addr, 0, &rtwusb->usb_buf.val32, sizeof(u32),
			      RTW_USB_CONTROL_MSG_TIMEOUT);
	mutex_unlock(&rtwusb->usb_buf_mutex);
}

static int rtw_usb_parse(struct rtw_dev *rtwdev,
			 struct usb_interface *interface)
{
	struct rtw_usb *rtwusb;
	struct usb_interface_descriptor *interface_desc;
	struct usb_host_interface *host_interface;
	struct usb_endpoint_descriptor *endpoint;
	struct device *dev;
	struct usb_device *usbd;
	int i, j = 0, endpoints;
	u8 dir, xtype, num;
	int ret = 0;

	rtwusb = rtw_get_usb_priv(rtwdev);

	dev = &rtwusb->udev->dev;

	usbd = interface_to_usbdev(interface);
	host_interface = &interface->altsetting[0];
	interface_desc = &host_interface->desc;
	endpoints = interface_desc->bNumEndpoints;

	rtwusb->num_in_pipes = 0;
	rtwusb->num_out_pipes = 0;
	for (i = 0; i < endpoints; i++) {
		endpoint = &host_interface->endpoint[i].desc;
		dir = endpoint->bEndpointAddress & USB_ENDPOINT_DIR_MASK;
		num = usb_endpoint_num(endpoint);
		xtype = usb_endpoint_type(endpoint);

		if (usb_endpoint_dir_in(endpoint) &&
		    usb_endpoint_xfer_bulk(endpoint)) {
			if (rtwusb->pipe_in) {
				ret = -EINVAL;
				goto exit;
			}

			rtwusb->pipe_in = num;
			rtwusb->num_in_pipes++;
		}

		if (usb_endpoint_dir_in(endpoint) &&
		    usb_endpoint_xfer_int(endpoint)) {
			if (rtwusb->pipe_interrupt) {
				ret = -EINVAL;
				goto exit;
			}

			rtwusb->pipe_interrupt = num;
		}

		if (usb_endpoint_dir_out(endpoint) &&
		    usb_endpoint_xfer_bulk(endpoint)) {
			if (j >= 4) {
				ret = -EINVAL;
				goto exit;
			}

			rtwusb->out_ep[j++] = num;
			rtwusb->num_out_pipes++;
		}
	}

	switch (usbd->speed) {
	case USB_SPEED_LOW:
		rtwusb->usb_speed = RTW_USB_SPEED_1_1;
		break;
	case USB_SPEED_FULL:
		rtwusb->usb_speed = RTW_USB_SPEED_1_1;
		break;
	case USB_SPEED_HIGH:
		rtwusb->usb_speed = RTW_USB_SPEED_2;
		break;
	case USB_SPEED_SUPER:
		rtwusb->usb_speed = RTW_USB_SPEED_3;
		break;
	default:
		rtw_err(rtwdev, "USB speed unknown\n");
		break;
	}

exit:
	rtwusb->nr_out_eps = j;
	return ret;
}

static
bool rtw_usb_is_bus_ready(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	return (atomic_read(&rtwusb->is_bus_drv_ready) == true);
}

static
void rtw_usb_set_bus_ready(struct rtw_dev *rtwdev, bool ready)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	atomic_set(&rtwusb->is_bus_drv_ready, ready);
}

/* RTW queue / pipe functions */
static u8 rtw_usb_ac_to_hwq[] = {
	[IEEE80211_AC_VO] = RTW_TX_QUEUE_VO,
	[IEEE80211_AC_VI] = RTW_TX_QUEUE_VI,
	[IEEE80211_AC_BE] = RTW_TX_QUEUE_BE,
	[IEEE80211_AC_BK] = RTW_TX_QUEUE_BK,
};

static u8 rtw_usb_tx_queue_mapping(struct sk_buff *skb)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	__le16 fc = hdr->frame_control;
	u8 q_mapping = skb_get_queue_mapping(skb);
	u8 queue = RTW_TX_QUEUE_BCN;

	if (unlikely(ieee80211_is_mgmt(fc) || ieee80211_is_ctl(fc)))
		queue = RTW_TX_QUEUE_MGMT;
	else if (q_mapping <= IEEE80211_AC_BK)
		queue = rtw_usb_ac_to_hwq[q_mapping];

	return queue;
}

static unsigned int rtw_usb_get_pipe(struct rtw_usb *rtwusb, u32 addr)
{
	unsigned int pipe = 0, ep_num = 0;
	struct usb_device *usbd = rtwusb->udev;

	if (addr == RTW_USB_BULK_IN_ADDR) {
		pipe = usb_rcvbulkpipe(usbd, rtwusb->pipe_in);
	} else if (addr == RTW_USB_INT_IN_ADDR) {
		pipe = usb_rcvintpipe(usbd, rtwusb->pipe_interrupt);
	} else if (addr < RTW_USB_HW_QUEUE_ENTRY) {
		ep_num = rtwusb->queue_to_pipe[addr];
		pipe = usb_sndbulkpipe(usbd, ep_num);
	}

	return pipe;
}

static void rtw_usb_one_outpipe_mapping(struct rtw_usb *rtwusb)
{
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_VO] = rtwusb->out_ep[0];/* VO */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_VI] = rtwusb->out_ep[0];/* VI */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BE] = rtwusb->out_ep[0];/* BE */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BK] = rtwusb->out_ep[0];/* BK */

	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BCN]	= rtwusb->out_ep[0];/* BCN */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_MGMT] = rtwusb->out_ep[0];/* MGT */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_HI0] = rtwusb->out_ep[0];/* HIGH */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_H2C] = rtwusb->out_ep[0];/* TXCMD */
}

static void rtw_usb_two_outpipe_mapping(struct rtw_usb *rtwusb)
{
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_VO] = rtwusb->out_ep[0];/* VO */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_VI] = rtwusb->out_ep[0];/* VI */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BE] = rtwusb->out_ep[1];/* BE */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BK] = rtwusb->out_ep[1];/* BK */

	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BCN]	= rtwusb->out_ep[0];/* BCN */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_MGMT] = rtwusb->out_ep[0];/* MGT */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_HI0] = rtwusb->out_ep[0];/* HIGH */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_H2C] = rtwusb->out_ep[0];/* TXCMD */
}

static void rtw_usb_three_outpipe_mapping(struct rtw_usb *rtwusb)
{
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_VO] = rtwusb->out_ep[0];/* VO */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_VI] = rtwusb->out_ep[1];/* VI */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BE] = rtwusb->out_ep[2];/* BE */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BK] = rtwusb->out_ep[2];/* BK */

	rtwusb->queue_to_pipe[RTW_TX_QUEUE_BCN]	= rtwusb->out_ep[0];/* BCN */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_MGMT] = rtwusb->out_ep[0];/* MGT */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_HI0] = rtwusb->out_ep[0];/* HIGH */
	rtwusb->queue_to_pipe[RTW_TX_QUEUE_H2C] = rtwusb->out_ep[0];/* TXCMD */
}

static u8 rtw_usb_set_queue_pipe_mapping(struct rtw_dev *rtwdev, u8 in_pipes,
					 u8 out_pipes)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	rtwusb->out_ep_queue_sel = 0;
	rtwdev->hci.bulkout_num = 0;

	switch (out_pipes) {
	case 4:
		rtwusb->out_ep_queue_sel = RTW_USB_TX_SEL_HQ |
					   RTW_USB_TX_SEL_LQ |
					   RTW_USB_TX_SEL_NQ;
		rtwdev->hci.bulkout_num = 4;
		break;
	case 3:
		rtwusb->out_ep_queue_sel = RTW_USB_TX_SEL_HQ |
					   RTW_USB_TX_SEL_LQ |
					   RTW_USB_TX_SEL_NQ;
		rtwdev->hci.bulkout_num = 3;
		break;
	case 2:
		rtwusb->out_ep_queue_sel = RTW_USB_TX_SEL_HQ |
					   RTW_USB_TX_SEL_NQ;
		rtwdev->hci.bulkout_num = 2;
		break;
	case 1:
		rtwusb->out_ep_queue_sel = RTW_USB_TX_SEL_HQ;
		rtwdev->hci.bulkout_num = 1;
		break;
	default:
		break;
	}

	switch (out_pipes) {
	case 2:
		rtw_usb_two_outpipe_mapping(rtwusb);
		break;
	case 3:
	case 4:
		rtw_usb_three_outpipe_mapping(rtwusb);
		break;
	case 1:
		rtw_usb_one_outpipe_mapping(rtwusb);
		break;
	default:
		return -1;
	}

	return 0;
}

static void rtw_usb_interface_configure(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	if (RTW_USB_IS_SUPER_SPEED(rtwusb))
		rtwusb->bulkout_size = RTW_USB_SUPER_SPEED_BULK_SIZE;
	else if (RTW_USB_IS_HIGH_SPEED(rtwusb))
		rtwusb->bulkout_size = RTW_USB_HIGH_SPEED_BULK_SIZE;
	else
		rtwusb->bulkout_size = RTW_USB_FULL_SPEED_BULK_SIZE;

	rtw_usb_set_queue_pipe_mapping(rtwdev, rtwusb->num_in_pipes,
				       rtwusb->num_out_pipes);
}

static int rtw_usb_init_event(struct rtw_usb_event *event)
{
	atomic_set(&event->event_condition, 1);
	init_waitqueue_head(&event->event_queue);
	return 0;
}

static bool rtw_usb_wait_ev_cond(struct rtw_usb_event *event)
{
	return (atomic_read(&event->event_condition) == 0);
}

static int rtw_usb_wait_event(struct rtw_usb_event *event)
{
	int status = 0;

	status = wait_event_interruptible(event->event_queue,
					  rtw_usb_wait_ev_cond(event));
	return status;
}

static void rtw_usb_set_event(struct rtw_usb_event *event)
{
	atomic_set(&event->event_condition, 0);
	wake_up_interruptible(&event->event_queue);
}

static void rtw_usb_reset_event(struct rtw_usb_event *event)
{
	atomic_set(&event->event_condition, 1);
}

static void rtw_usb_create_handler(struct rtw_usb_handler *handler)
{
	atomic_set(&handler->handler_done, 0);
}

static void rtw_usb_kill_handler(struct rtw_usb_handler *handler)
{
	atomic_inc(&handler->handler_done);
	rtw_usb_set_event(&handler->event);
}

void rtw_usb_tx_func(struct rtw_usb *rtwusb);
static void rtw_usb_tx_handler(struct work_struct *work)
{
	struct rtw_usb_work_data *work_data = container_of(work,
						       struct rtw_usb_work_data,
						       work);
	struct rtw_dev *rtwdev = work_data->rtwdev;
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	do {
		rtw_usb_wait_event(&rtwusb->tx_handler.event);
		rtw_usb_reset_event(&rtwusb->tx_handler.event);

		rtw_usb_tx_func(rtwusb);
	} while (atomic_read(&rtwusb->tx_handler.handler_done) == 0);
}

static void rtw_usb_indicate_tx_status(struct rtw_dev *rtwdev,
				       struct sk_buff *skb)
{
	struct ieee80211_hw *hw = rtwdev->hw;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

	info->flags |= IEEE80211_TX_STAT_ACK;

	ieee80211_tx_info_clear_status(info);
	ieee80211_tx_status_irqsafe(hw, skb);
}

static void rtw_usb_write_port_direct_complete(struct urb *urb)
{
	struct sk_buff *skb;

	skb = (struct sk_buff *)urb->context;
	dev_kfree_skb(skb);
	usb_free_urb(urb);
}

static u32 rtw_usb_write_port_direct(struct rtw_dev *rtwdev, u8 addr, u32 cnt,
				     struct sk_buff *skb)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct usb_device *usbd = rtwusb->udev;
	struct urb *urb;
	unsigned int pipe;
	int ret;

	pipe = rtw_usb_get_pipe(rtwusb, addr);

	urb = usb_alloc_urb(0, GFP_ATOMIC);
	if (!urb)
		return -ENOMEM;

	usb_fill_bulk_urb(urb, usbd, pipe, skb->data, (int)cnt,
			  rtw_usb_write_port_direct_complete, skb);

	ret = usb_submit_urb(urb, GFP_ATOMIC);
	if (unlikely(ret))
		usb_free_urb(urb);

	return ret;
}

static u32 rtw_usb_write_port_wait(struct rtw_dev *rtwdev, u8 addr, u32 cnt,
				   struct sk_buff *skb)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct usb_device *usbd = rtwusb->udev;
	unsigned int pipe;
	int ret;
	int transfer;

	pipe = rtw_usb_get_pipe(rtwusb, addr);

	ret = usb_bulk_msg(usbd, pipe, (void *)skb->data, (int)cnt,
			   &transfer, USB_MSG_TIMEOUT);
	if (ret < 0)
		rtw_err(rtwdev, "usb_bulk_msg error, ret=%d\n", ret);

	return ret;
}

static inline void rtw_usb_tx_queue_init(struct rtw_usb *rtwusb)
{
	int i;

	for (i = 0; i < RTK_MAX_TX_QUEUE_NUM; i++)
		skb_queue_head_init(&rtwusb->tx_queue[i]);

	skb_queue_head_init(&rtwusb->tx_ack_queue);
}

static inline void rtw_usb_tx_queue_purge(struct rtw_usb *rtwusb)
{
	int i;

	for (i = 0; i < RTK_MAX_TX_QUEUE_NUM; i++)
		skb_queue_purge(&rtwusb->tx_queue[i]);

	skb_queue_purge(&rtwusb->tx_ack_queue);
}

static struct sk_buff *rtw_usb_tx_dequeue(struct rtw_usb *rtwusb)
{
	struct sk_buff *skb = NULL;
	static int index = RTK_MAX_TX_QUEUE_NUM - 1;

	for (; index >= 0; index--) {
		skb = skb_dequeue(&rtwusb->tx_queue[index]);
		if (skb)
			break;
	}

	if (index < 0)
		index = RTK_MAX_TX_QUEUE_NUM - 1;

	return skb;
}

static inline void rtw_usb_tx_ack_enqueue(struct rtw_usb *rtwusb,
					  struct sk_buff *skb)
{
	skb_queue_tail(&rtwusb->tx_ack_queue, skb);
}

static inline void rtw_usb_do_tx_ack_queue(struct rtw_usb *rtwusb)
{
	struct rtw_dev *rtwdev = rtwusb->rtwdev;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&rtwusb->tx_ack_queue))) {
		u8 qsel, queue;

		qsel = GET_TX_DESC_QSEL(skb->data);
		queue = rtw_tx_qsel_to_queue(qsel);

		if (queue <= RTW_TX_QUEUE_VO)
			rtw_usb_indicate_tx_status(rtwdev, skb);
		else
			dev_kfree_skb(skb);
	}
}

static inline void rtw_usb_tx_agg(struct rtw_usb *rtwusb, struct sk_buff *skb)
{
	struct rtw_dev *rtwdev = rtwusb->rtwdev;
	struct sk_buff_head *list;
	struct sk_buff *skb_head = NULL, *skb_iter;
	unsigned long flags;
	int status, len, agg_num = 0;
	u8 *data_ptr, queue, qsel;

	qsel = GET_TX_DESC_QSEL(skb->data);
	queue = rtw_tx_qsel_to_queue(qsel);
	if (queue != RTW_TX_QUEUE_VO)
		goto err_no_need_agg;

	list = &rtwusb->tx_queue[queue];
	if (skb_queue_empty(list))
		goto err_no_need_agg;

	skb_head = dev_alloc_skb(RTW_USB_MAX_XMITBUF_SZ);
	if (!skb_head)
		goto err_no_need_agg;

	data_ptr = skb_head->data;
	skb_iter = skb;
	while (skb_iter) {
		memcpy(data_ptr, skb_iter->data, skb_iter->len);
		len = ALIGN(skb_iter->len, 8);
		skb_put(skb_head, len);
		data_ptr += len;
		agg_num++;

		rtw_usb_tx_ack_enqueue(rtwusb, skb_iter);

		spin_lock_irqsave(&list->lock, flags);
		skb_iter = skb_peek(list);
		if (skb_iter &&
		    skb_iter->len < RTW_USB_MAX_XMITBUF_SZ - skb_head->len)
			__skb_unlink(skb_iter, list);
		else
			skb_iter = NULL;
		spin_unlock_irqrestore(&list->lock, flags);
	};

	if (agg_num > 1)
		rtw_usb_fill_tx_checksum(rtwusb, skb_head, agg_num);

	goto write_port;

err_no_need_agg:
	skb_head = skb;
	rtw_usb_tx_ack_enqueue(rtwusb, skb);

write_port:
	status = rtw_usb_write_port_wait(rtwdev, queue, skb_head->len,
					 skb_head);
	if (status)
		rtw_err(rtwdev, "rtw_usb_write_xmit failed, ret=%d\n", status);

	if (skb_head != skb)
		dev_kfree_skb(skb_head);

	rtw_usb_do_tx_ack_queue(rtwusb);
}

void rtw_usb_tx_func(struct rtw_usb *rtwusb)
{
	struct sk_buff *skb;

	while (1) {
		mutex_lock(&rtwusb->tx_lock);

		skb = rtw_usb_tx_dequeue(rtwusb);
		if (!skb) {
			mutex_unlock(&rtwusb->tx_lock);
			break;
		}

		rtw_usb_tx_agg(rtwusb, skb);

		mutex_unlock(&rtwusb->tx_lock);
	}
}

static int
rtw_usb_write_data(struct rtw_dev *rtwdev, struct rtw_tx_pkt_info *pkt_info,
		   u8 *buf)
{
	struct rtw_chip_info *chip = rtwdev->chip;
	struct sk_buff *skb;
	u32 desclen, len, headsize, size;
	u8 queue, qsel;
	u8 ret = 0;

	size = pkt_info->tx_pkt_size;
	qsel = pkt_info->qsel;
	desclen = chip->tx_pkt_desc_sz;
	headsize = (pkt_info->offset) ? pkt_info->offset : desclen;
	len = headsize + size;

	skb = dev_alloc_skb(len);
	if (unlikely(!skb))
		return -ENOMEM;

	skb_reserve(skb, headsize);

	memcpy((u8 *)skb_put(skb, size), buf, size);

	skb_push(skb, headsize);
	memset(skb->data, 0, headsize);

	rtw_tx_fill_tx_desc(pkt_info, skb);

	chip->ops->fill_txdesc_checksum(rtwdev, pkt_info, skb->data);

	queue = rtw_tx_qsel_to_queue(qsel);

	ret = rtw_usb_write_port_direct(rtwdev, queue, len, skb);
	if (unlikely(ret))
		rtw_err(rtwdev, "rtw_usb_write_port failed, ret=%d\n", ret);

	return ret;
}

static int rtw_usb_write_data_rsvd_page(struct rtw_dev *rtwdev, u8 *buf,
					u32 size)
{
	struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_usb *rtwusb;
	struct rtw_tx_pkt_info pkt_info;
	u32 len, desclen;
	u8 qsel = TX_DESC_QSEL_BEACON;

	if (unlikely(!rtwdev))
		return -EINVAL;

	rtwusb = rtw_get_usb_priv(rtwdev);
	if (unlikely(!rtwusb))
		return -EINVAL;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.tx_pkt_size = size;
	pkt_info.qsel = qsel;

	desclen = chip->tx_pkt_desc_sz;
	len = desclen + size;
	if (len % rtwusb->bulkout_size == 0) {
		len = len + RTW_USB_PACKET_OFFSET_SZ;
		pkt_info.offset = desclen + RTW_USB_PACKET_OFFSET_SZ;
		pkt_info.pkt_offset = 1;
	} else {
		pkt_info.offset = desclen;
	}

	return rtw_usb_write_data(rtwdev, &pkt_info, buf);
}

static int rtw_usb_write_data_h2c(struct rtw_dev *rtwdev, u8 *buf, u32 size)
{
	struct rtw_tx_pkt_info pkt_info;
	u8 qsel = TX_DESC_QSEL_H2C;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.tx_pkt_size = size;
	pkt_info.qsel = qsel;

	return rtw_usb_write_data(rtwdev, &pkt_info, buf);
}

static int rtw_usb_tx_write(struct rtw_dev *rtwdev,
			    struct rtw_tx_pkt_info *pkt_info,
			    struct sk_buff *skb)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct rtw_chip_info *chip = rtwdev->chip;
	struct rtw_usb_tx_data *tx_data;
	u8 *pkt_desc;
	u8 queue = rtw_usb_tx_queue_mapping(skb);

	if (!pkt_info)
		return -EINVAL;

	pkt_desc = skb_push(skb, chip->tx_pkt_desc_sz);
	memset(pkt_desc, 0, chip->tx_pkt_desc_sz);
	pkt_info->qsel = rtw_tx_queue_to_qsel(skb, queue);
	rtw_tx_fill_tx_desc(pkt_info, skb);

	chip->ops->fill_txdesc_checksum(rtwdev, pkt_info, skb->data);

	tx_data = rtw_usb_get_tx_data(skb);
	tx_data->sn = pkt_info->sn;

	skb_queue_tail(&rtwusb->tx_queue[queue], skb);
	return 0;
}

static void rtw_usb_tx_kick_off(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	rtw_usb_set_event(&rtwusb->tx_handler.event);
}

static u32 rtw_usb_read_port(struct rtw_dev *rtwdev, u8 addr,
			     struct rx_usb_ctrl_block *rxcb);

static void rtw_usb_rx_handler(struct work_struct *work)
{
	struct rtw_usb_work_data *work_data = container_of(work,
						struct rtw_usb_work_data,
						work);
	struct rtw_dev *rtwdev = work_data->rtwdev;
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct sk_buff *skb;

	do {
		rtw_usb_wait_event(&rtwusb->rx_handler.event);
		rtw_usb_reset_event(&rtwusb->rx_handler.event);

		while (true) {
			u8 *rx_desc;
			struct rtw_chip_info *chip = rtwdev->chip;
			struct ieee80211_rx_status rx_status;
			struct rtw_rx_pkt_stat pkt_stat;
			u32 pkt_desc_sz = chip->rx_pkt_desc_sz;
			u32 pkt_offset;

			if (atomic_read(&rtwusb->rx_handler.handler_done))
				goto out;

			skb = skb_dequeue(&rtwusb->rx_queue);
			if (!skb)
				break;

			rx_desc = skb->data;
			chip->ops->query_rx_desc(rtwdev, rx_desc, &pkt_stat,
						 &rx_status);

			pkt_offset = pkt_desc_sz + pkt_stat.drv_info_sz +
				     pkt_stat.shift;

			if (pkt_stat.is_c2h) {
				skb_put(skb, pkt_stat.pkt_len + pkt_offset);
				rtw_fw_c2h_cmd_rx_irqsafe(rtwdev, pkt_offset,
							  skb);
				continue;
			}

			if (skb_queue_len(&rtwusb->rx_queue) >= 64) {
				rtw_err(rtwdev, "rx_queue overflow\n");
				dev_kfree_skb(skb);
				continue;
			}

			skb_put(skb, pkt_stat.pkt_len);
			skb_reserve(skb, pkt_offset);

			memcpy(skb->cb, &rx_status, sizeof(rx_status));
			ieee80211_rx_irqsafe(rtwdev->hw, skb);
		}
	} while (atomic_read(&rtwusb->rx_handler.handler_done) == 0);

out:
	skb_queue_purge(&rtwusb->rx_queue);
}

static void rtw_usb_read_port_complete(struct urb *urb)
{
	struct rx_usb_ctrl_block *rxcb = urb->context;
	struct rtw_dev *rtwdev = (struct rtw_dev *)rxcb->data;
	struct sk_buff *skb = rxcb->rx_skb;
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;

	if (urb->status == 0) {
		if (urb->actual_length >= RTW_USB_MAX_RECVBUF_SZ ||
		    urb->actual_length < 24) {
			rtw_err(rtwdev, "actual_size error:%d\n",
				urb->actual_length);
			if (skb)
				dev_kfree_skb(skb);
		} else {
			skb_queue_tail(&rtwusb->rx_queue, skb);
			rtw_usb_set_event(&rtwusb->rx_handler.event);
		}

		rtw_usb_read_port(rtwdev, RTW_USB_BULK_IN_ADDR, rxcb);
	} else {
		switch (urb->status) {
		case -EINVAL:
		case -EPIPE:
		case -ENODEV:
		case -ESHUTDOWN:
		case -ENOENT:
			rtw_usb_set_bus_ready(rtwdev, false);
			break;
		case -EPROTO:
		case -EILSEQ:
		case -ETIME:
		case -ECOMM:
		case -EOVERFLOW:
			break;
		case -EINPROGRESS:
			break;
		default:
			rtw_err(rtwdev, "unknown : status=%d\n", urb->status);
			break;
		}
		if (skb)
			dev_kfree_skb(skb);
	}
}

static u32 rtw_usb_read_port(struct rtw_dev *rtwdev, u8 addr,
			     struct rx_usb_ctrl_block *rxcb)
{
	unsigned int pipe;
	int ret = -1;
	struct urb *urb = NULL;
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct usb_device *usbd = rtwusb->udev;
	struct sk_buff *skb;
	u32 len;
	size_t buf_addr;
	size_t alignment = 0;

	if (!rtw_usb_is_bus_ready(rtwdev))
		return 0;

	urb = rxcb->rx_urb;
	rxcb->data = (u8 *)rtwdev;

	pipe = rtw_usb_get_pipe(rtwusb, RTW_USB_BULK_IN_ADDR);

	len = RTW_USB_MAX_RECVBUF_SZ + RTW_USB_RECVBUFF_ALIGN_SZ;
	skb = dev_alloc_skb(len);
	if (!skb) {
		rtw_err(rtwdev, "dev_alloc_skb failed\n");
		return -ENOMEM;
	}
	buf_addr = (size_t)skb->data;
	alignment = buf_addr & (RTW_USB_RECVBUFF_ALIGN_SZ - 1);
	skb_reserve(skb, RTW_USB_RECVBUFF_ALIGN_SZ - alignment);

	urb->transfer_buffer = skb->data;
	rxcb->rx_skb = skb;

	usb_fill_bulk_urb(urb, usbd, pipe,
			  urb->transfer_buffer,
			  RTW_USB_MAX_RECVBUF_SZ,
			  rtw_usb_read_port_complete,
			  rxcb);

	ret = usb_submit_urb(urb, GFP_ATOMIC);
	if (ret)
		rtw_err(rtwdev, "usb_submit_urb failed, ret=%d\n", ret);

	return ret;
}

static void rtw_usb_inirp_init(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct rx_usb_ctrl_block *rxcb;
	int i;

	rtw_usb_set_bus_ready(rtwdev, true);

	for (i = 0; i < RTW_USB_RXCB_NUM; i++) {
		rxcb = &rtwusb->rx_cb[i];
		rxcb->rx_urb = NULL;
	}

	for (i = 0; i < RTW_USB_RXCB_NUM; i++) {
		rxcb = &rtwusb->rx_cb[i];
		rxcb->rx_urb = usb_alloc_urb(0, GFP_KERNEL);
		if (!rxcb->rx_urb)
			goto err_exit;
		rtw_usb_read_port(rtwdev, RTW_USB_BULK_IN_ADDR, rxcb);
	}

	return;

err_exit:
	for (i = 0; i < RTW_USB_RXCB_NUM; i++) {
		rxcb = &rtwusb->rx_cb[i];
		if (rxcb->rx_urb)
			usb_kill_urb(rxcb->rx_urb);
	}
}

static void rtw_usb_inirp_deinit(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);
	struct rx_usb_ctrl_block *rxcb;
	int i;

	rtw_usb_set_bus_ready(rtwdev, false);

	for (i = 0; i < RTW_USB_RXCB_NUM; i++) {
		rxcb = &rtwusb->rx_cb[i];
		if (rxcb->rx_urb)
			usb_kill_urb(rxcb->rx_urb);
	}
}

static int rtw_usb_setup(struct rtw_dev *rtwdev)
{
	return 0;
}

static int rtw_usb_start(struct rtw_dev *rtwdev)
{
	rtw_usb_inirp_init(rtwdev);
	return 0;
}

static void rtw_usb_stop(struct rtw_dev *rtwdev)
{
	rtw_usb_inirp_deinit(rtwdev);
}

static void rtw_usb_deep_ps(struct rtw_dev *rtwdev, bool enter)
{
}

static void rtw_usb_link_ps(struct rtw_dev *rtwdev, bool enter)
{
}

static void rtw_usb_interface_cfg(struct rtw_dev *rtwdev)
{
}

static struct rtw_hci_ops rtw_usb_ops = {
	.tx_write = rtw_usb_tx_write,
	.tx_kick_off = rtw_usb_tx_kick_off,
	.setup = rtw_usb_setup,
	.start = rtw_usb_start,
	.stop = rtw_usb_stop,
	.deep_ps = rtw_usb_deep_ps,
	.link_ps = rtw_usb_link_ps,
	.interface_cfg = rtw_usb_interface_cfg,

	.read8 = rtw_usb_read8,
	.read16 = rtw_usb_read16,
	.read32 = rtw_usb_read32,
	.write8 = rtw_usb_write8,
	.write16 = rtw_usb_write16,
	.write32 = rtw_usb_write32,

	.write_data_rsvd_page = rtw_usb_write_data_rsvd_page,
	.write_data_h2c = rtw_usb_write_data_h2c,
};

static int rtw_usb_init_rx(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	rtwusb->rxwq = create_singlethread_workqueue("rtw88_usb: rx wq");
	if (!rtwusb->rxwq) {
		rtw_err(rtwdev, "create_singlethread_workqueue failed\n");
		goto err;
	}

	skb_queue_head_init(&rtwusb->rx_queue);
	rtw_usb_create_handler(&rtwusb->rx_handler);
	rtw_usb_init_event(&rtwusb->rx_handler.event);

	rtwusb->rx_handler_data = kmalloc(sizeof(*rtwusb->rx_handler_data),
					  GFP_KERNEL);
	if (!rtwusb->rx_handler_data)
		goto err_destroy_wq;

	rtwusb->rx_handler_data->rtwdev = rtwdev;

	INIT_WORK(&rtwusb->rx_handler_data->work, rtw_usb_rx_handler);
	queue_work(rtwusb->rxwq, &rtwusb->rx_handler_data->work);

	return 0;

err_destroy_wq:
	rtw_usb_kill_handler(&rtwusb->rx_handler);
	destroy_workqueue(rtwusb->rxwq);

err:
	return -ENOMEM;
}

static int rtw_usb_init_tx(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = rtw_get_usb_priv(rtwdev);

	rtwusb->txwq = create_singlethread_workqueue("rtw88_usb: tx wq");
	if (!rtwusb->txwq) {
		rtw_err(rtwdev, "create_singlethread_workqueue failed\n");
		goto err;
	}

	rtw_usb_tx_queue_init(rtwusb);

	rtw_usb_create_handler(&rtwusb->tx_handler);
	rtw_usb_init_event(&rtwusb->tx_handler.event);

	rtwusb->tx_handler_data = kmalloc(sizeof(*rtwusb->tx_handler_data),
					  GFP_KERNEL);
	if (!rtwusb->tx_handler_data)
		goto err_destroy_wq;

	rtwusb->tx_handler_data->rtwdev = rtwdev;

	INIT_WORK(&rtwusb->tx_handler_data->work, rtw_usb_tx_handler);
	queue_work(rtwusb->txwq, &rtwusb->tx_handler_data->work);

	return 0;

err_destroy_wq:
	rtw_usb_kill_handler(&rtwusb->tx_handler);
	destroy_workqueue(rtwusb->txwq);

err:
	return -ENOMEM;
}

int rtw_usb_probe(struct usb_interface *intf,
		  const struct usb_device_id *id)
{
	struct rtw_dev *rtwdev;
	struct usb_device *udev;
	struct rtw_usb *rtwusb;
	struct ieee80211_hw *hw;
	int drv_data_size;
	int ret = 0;

	drv_data_size = sizeof(struct rtw_dev) + sizeof(struct rtw_usb);
	hw = ieee80211_alloc_hw(drv_data_size, &rtw_ops);
	if (!hw)
		return -ENOMEM;

	rtwdev = hw->priv;
	rtwdev->hw = hw;
	rtwdev->chip = (struct rtw_chip_info *)id->driver_info;
	ret = rtw_core_init(rtwdev);
	if (ret)
		goto err_release_hw;

	rtwdev->dev = &intf->dev;
	udev = usb_get_dev(interface_to_usbdev(intf));

	rtwdev->hci.ops = &rtw_usb_ops;
	rtwdev->hci.type = RTW_HCI_TYPE_USB;

	usb_set_intfdata(intf, rtwdev->hw);

	rtwusb = rtw_get_usb_priv(rtwdev);
	rtwusb->udev = udev;
	rtwusb->rtwdev = rtwdev;
	mutex_init(&rtwusb->tx_lock);

	ret = rtw_usb_parse(rtwdev, intf);
	if (ret) {
		rtw_err(rtwdev, "rtw_usb_parse failed, ret=%d\n", ret);
		goto err_deinit_core;
	}

	rtw_usb_interface_configure(rtwdev);

	SET_IEEE80211_DEV(rtwdev->hw, &intf->dev);

	ret = rtw_usb_init_tx(rtwdev);
	if (ret)
		goto err_destroy_usb;

	ret = rtw_usb_init_rx(rtwdev);
	if (ret)
		goto err_destroy_txwq;

	ret = rtw_chip_info_setup(rtwdev);
	if (ret) {
		rtw_err(rtwdev, "failed to setup chip information\n");
		goto err_destroy_rxwq;
	}

	ret = rtw_register_hw(rtwdev, rtwdev->hw);
	if (ret) {
		rtw_err(rtwdev, "rtw_register_hw failed: ret=%d\n", ret);
		goto err_destroy_rxwq;
	}

	return 0;

err_destroy_rxwq:
	rtw_usb_kill_handler(&rtwusb->rx_handler);
	cancel_work_sync(&rtwusb->rx_handler_data->work);
	destroy_workqueue(rtwusb->rxwq);

err_destroy_txwq:
	rtw_usb_kill_handler(&rtwusb->tx_handler);
	cancel_work_sync(&rtwusb->tx_handler_data->work);
	destroy_workqueue(rtwusb->txwq);

err_destroy_usb:
	usb_put_dev(rtwusb->udev);
	usb_set_intfdata(intf, NULL);

err_deinit_core:
	rtw_core_deinit(rtwdev);
	mutex_destroy(&rtwusb->usb_buf_mutex);
	mutex_destroy(&rtwusb->tx_lock);

err_release_hw:
	ieee80211_free_hw(hw);

	return ret;
}
EXPORT_SYMBOL(rtw_usb_probe);

void rtw_usb_disconnect(struct usb_interface *intf)
{
	struct ieee80211_hw *hw = usb_get_intfdata(intf);
	struct rtw_dev *rtwdev;
	struct rtw_usb *rtwusb;

	if (!hw)
		return;

	rtwdev = hw->priv;
	rtwusb = rtw_get_usb_priv(rtwdev);

	rtw_usb_tx_queue_purge(rtwusb);
	skb_queue_purge(&rtwusb->rx_queue);
	rtw_usb_kill_handler(&rtwusb->tx_handler);
	rtw_usb_kill_handler(&rtwusb->rx_handler);
	cancel_work_sync(&rtwusb->rx_handler_data->work);
	cancel_work_sync(&rtwusb->tx_handler_data->work);
	destroy_workqueue(rtwusb->rxwq);
	destroy_workqueue(rtwusb->txwq);

	kfree(rtwusb->tx_handler_data);
	kfree(rtwusb->rx_handler_data);

	rtw_unregister_hw(rtwdev, hw);

	if (rtwusb->udev->state != USB_STATE_NOTATTACHED)
		usb_reset_device(rtwusb->udev);

	usb_put_dev(rtwusb->udev);
	usb_set_intfdata(intf, NULL);
	rtw_core_deinit(rtwdev);
	mutex_destroy(&rtwusb->usb_buf_mutex);
	mutex_destroy(&rtwusb->tx_lock);
	ieee80211_free_hw(hw);
}
EXPORT_SYMBOL(rtw_usb_disconnect);

MODULE_AUTHOR("Realtek Corporation");
MODULE_DESCRIPTION("Realtek 802.11ac wireless USB driver");
MODULE_LICENSE("Dual BSD/GPL");
