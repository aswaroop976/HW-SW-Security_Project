Installing Debian Linux Image
============

In the project we will use a Debian image as the nonsecure OS. Released Debian images can be found [here](https://github.com/usbarmory/usbarmory-debian-base_image/releases). I installed release 20250801 on a uSD card using Etcher, but it's possible to install it on the internal eMMC. Later, the nonsecure OS can be spawned from the GoTEE example using the `linux uSD/eMMC` command.


Routing Internet to USB Armory
============

Internet will be needed to install the required tools and to sync time. It can be routed to the USB Armory from the Host by following these steps.

* On the Host:
```
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE
sudo iptables -A FORWARD -i enx1a5589a26942 -o enp0s3 -j ACCEPT
sudo iptables -A FORWARD -i enp0s3 -o enx1a5589a26942 -m state --state ESTABLISHED,RELATED -j ACCEPT
```
Here `enx1a5589a26942` is the USB Armory interface and `enp0s3` is the Internet interface.

* On USB Armory:
```
sudo ip route del default 2>/dev/null
sudo ip route add default via 10.0.0.2 dev usb0
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```


Enable the required kernel modules
============

Install the Debian package `linux-image-6.12-usbarmory-mark-two_6.12.40-0_armhf.deb` to enable USBIP-required kernel modules by:
```
dpkg -i linux-image-6.12-usbarmory-mark-two_6.12.40-0_armhf.deb
```

Installing required tools
============

You might need to install the following tools in the USB Armory:
```
sudo apt-get update
sudo apt-get install -y \
  usbip \
  linux-tools-$(uname -r) \
  udev \
  python3 \
  python3-pip \
  jq \
  rsyslog \
  net-tools iproute2 \
  curl \
  rsyslog \
  usbutils
```
Configuring the USB Armory for USBIP
============

First, you need to add a udev rule to trigger an event when a USB device is connected. To do that, copy the file `90-usb-policy.rules` to `/etc/udev/rules.d/`. Then, run the command:
```
sudo udevadm control --reload
```

After that, copy the files `usb-policy-handler.sh` and `endorsment_service` to `/usr/local/bin/` and run the following commands:
```
sudo chmod 755 /usr/local/sbin/usb-policy-handler.sh
sudo chmod 755 /usr/local/sbin/endorsement_service
sudo modprobe usbip-core
sudo modprobe usbip-host
sudo usbipd -D
```

Configuring the Host for USBIP
============

On the host, do the following:
```
sudo apt-get update
sudo apt-get install -y usbip
sudo modprobe vhci-hcd
```
Then, run `usbip-auto-attach.sh` as root. 

How the endorsment service works?
============

Currently, when a USB device is connected to the USB Armory, it will check if the device is in the endorsement cache `/var/lib/usb-policy/endorsements.json` based on its VID and PID (and optionally its serial number) and, if it's allowed, it will pass it to the host over the network connection. An example of `endorsements.json` is included. The host (while running the `usbip-auto-attach.sh` script) will keep checking USB devices exported by the USB Armory and attach any new device it finds.

A USB device can be endorsed using the command:
```
endorsment_service endorse  [VID] [PID] [Serial number (optional)] --ttl [Time-to-live in seconds (optional)] --note [Readable note (optional)]
```
Time-to-live is optional and, if an endorsement is expired for a USB device, it will not bind it to the host when the device gets connected, but if it's already attached it will not detach it (a service that detaches expired devices can be added later). 

To revoke an endorsment:
```
endorsment_service revoke [VID] [PID] [Serial number (optional)]
```

Also, it's possible to list devices in the endorsement cache by:
```
endorsment_service list
```

