# rtw88-usb - for kernel upstream

This branch is to upstream to Linux kernel in the future.

Driver for 802.11ac USB Adapter with chipset:
  RTL88x2BU / RTL88x2CU

supports at least managed (i.e. client) and monitor mode.

A few known wireless cards that use this driver include 
* [Edimax EW-7822ULC](http://us.edimax.com/edimax/merchandise/merchandise_detail/data/edimax/us/wireless_adapters_ac1200_dual-band/ew-7822ulc/)
* [ASUS AC-53 NANO](https://www.asus.com/Networking/USB-AC53-Nano/)
* [TPLink Archer T4U v3](https://www.tp-link.com/tw/support/download/archer-t4u/)


## Build

```console
$ make clean
$ make
```

## Installation

Load driver for test:
```console
$ sudo mkdir -p /lib/firmware/rtw88
$ sudo cp fw/rtw8822* /lib/firmware/rtw88/
$ sudo insmod rtw88_core.ko
$ sudo insmod rtw88_usb.ko
$ sudo insmod rtw88_8822c.ko
$ sudo insmod rtw88_8822cu.ko

```
## General Commands

Scan:
```console
$ sudo iw wlanX scan
```
Connect to the AP without security:
```console
$ sudo iw wlanX connect <AP name>
```
## Wifi Sniffer - monitor mode
```console
$ sudo ifconfig wlanX down
$ sudo iwconfig wlanX mode monitor
$ sudo rfkill unblock all
$ sudo ifconfig wlanX up
```

Then you can use "iwconfig" to check if the wireless mode is correct.
```console
e.g.
    wlan1    IEEE 802.11  Mode:Monitor ... 
```

And you can use the program like wireshark to sniffer wifi packets.
1. set up the sniffer channel
```console
$ sudo iwconfig wlanX channel xxx
```

2. run the program
```console
$ sudo wireshark
```

## Test
test ok with general commands with the latest kernel


