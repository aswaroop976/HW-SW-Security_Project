#!/bin/sh

BUSID="$1"
SYSFS_BASE="/sys/bus/usb/devices/$BUSID"

[ -d "$SYSFS_BASE" ] || exit 0

VID=$(cat "$SYSFS_BASE/idVendor" 2>/dev/null || echo "0000")
PID=$(cat "$SYSFS_BASE/idProduct" 2>/dev/null || echo "0000")
SERIAL=$(cat "$SYSFS_BASE/serial" 2>/dev/null || echo "")

/usr/bin/logger -t usb-policy "New device busid=$BUSID vid=$VID pid=$PID serial=$SERIAL"

if /usr/local/bin/endorsment_service check "$VID" "$PID" "$SERIAL"; then
    /usr/bin/logger -t usb-policy "Policy: ALLOW for $BUSID, binding to usbip"
    /usr/sbin/usbip bind -b "$BUSID" || \
        /usr/bin/logger -t usb-policy "usbip bind failed for $BUSID"
else
    /usr/bin/logger -t usb-policy "Policy: DENY for $BUSID, not binding"
fi

exit 0
