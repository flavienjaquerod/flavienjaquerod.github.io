---
title: Logger
date: 2025-02-07
author: Flavien
draft: false
tags:
  - CTF
  - HTB
  - Challenge
  - Forensics
  - Easy
  - USB
  - Wireshark
categories:
  - Writeup
  - Challenge
  - Forensics
description: HTB writeup for the  easy forensics challenge "Logger"
summary: This challenge contains a file with `USB` traffic between many hosts. We can inspect this traffic and use a script to recover the keystrokes which contain the flag.
---

```
A client reported that a PC might have been infected, as it's running slow. We've collected all the evidence from the suspect workstation, and found a suspicious trace of USB traffic. Can you identify the compromised data?
```

==> We get a single file for this challenge `keystrokes.pcapng` --> opening it in `Wireshark`, we see that it contains many messages using the `USB` protocol.

Looking around, we notice that many different devices seem to be conversing using this protocol and announce themselves with a `DESCRIPTION RESPONSE DEVICE` packet that contains the type of device it is. From this list, we gather 5 different devices after filtering using the filter:

```http
_ws.col.info == "GET DESCRIPTOR Response DEVICE"
```

- `idProduct: Optical Gaming Mouse [Xtrem] (0x0f97)`
- `idProduct: Keyboard LKS02 (0x1702)`
- `idProduct: RTS5129 Card Reader Controller (0x0129)`
- `idVendor: MSI (0x1770)`
- `idProduct: steel series rgb keyboard (0xff00)`

==> Since the challenge requires us to find suspicious data, we can look at the keyboards as they seem likely to hold more data. The hosts are then:

```
Keyboard LKS02 = 1.16.0
Steel series rgb keyboard = 1.2.0
```

==> Focusing on the first keyboard, we can check the values that it sent to the host:

```js
No.	Time	Source	Destination	Protocol	Length	Info
2	0.000000	1.16.0	host	USB	46	GET DESCRIPTOR Response DEVICE
4	0.000000	1.16.0	host	USB	87	GET DESCRIPTOR Response CONFIGURATION
6	0.000000	1.16.0	host	USB	28	SET CONFIGURATION Response
52	5.978987	1.16.0	host	USBHID	28	SET_REPORT Response
78	13.491183	1.16.0	host	USBHID	28	SET_REPORT Response
96	16.867092	1.16.0	host	USBHID	28	SET_REPORT Response
142	31.163016	1.16.0	host	USBHID	28	SET_REPORT Response
152	35.099262	1.16.0	host	USBHID	28	SET_REPORT Response
166	39.939391	1.16.0	host	USBHID	28	SET_REPORT Response
184	44.490997	1.16.0	host	USBHID	28	SET_REPORT Response
206	50.747549	1.16.0	host	USBHID	28	SET_REPORT Response
```

and we see that there is some `USBHID` data --> we can then use `tshark` to extract this content. [This repository](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser) has some amazing content on `USB forensics` and so we can take their commands to get the content of the keystrokes:

```bash
tshark -r keystrokes.pcapng -Y 'usb.device_address == 16 && usb.data_len == 8' -Tfields -e usbhid.data | sed 's/../:&/g2' > usbPcapData
```

and we can then run the script on this output:

```bash
python3 usbkeyboard.py usbPcapData 
[CAPSLOCK]htb{[CAPSLOCK]i_[CAPSLOCK]c4n_533_[CAPSLOCK]y[CAPSLOCK]ou[CAPSLOCK]r_[CAPSLOCK]k3y2[CAPSLOCK]}
```

where we see something that seems to be the flag but we have a bit of clean up to do by modifying the characters that must be in capital and we get the flag:

==> **`HTB{i_C4N_533_yOUr_K3Y2}`**

