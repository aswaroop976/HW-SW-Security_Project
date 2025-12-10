// Copyright (c) The GoTEE authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package main

import (
	"log"
	"os"
	"runtime"

	"github.com/usbarmory/GoTEE-example/util"
	"github.com/usbarmory/GoTEE/applet"
	"github.com/usbarmory/GoTEE/syscall"
)

func init() {
	log.SetFlags(log.Ltime)
	log.SetOutput(os.Stdout)

	// yield to monitor (w/ err != nil) on runtime panic
	runtime.Exit = applet.Crash
}

type endorsementStatus uint8

const (
	endorsementUnknown endorsementStatus = iota
	endorsementActive
	endorsementExpired
)

type endorsementEntry struct {
	device util.USBDeviceID
	status endorsementStatus
	TTL    uint32
	log    packetRingBuffer
}

type endorsementCache struct {
	entries map[util.USBDeviceID]*endorsementEntry
}

func newEndorsementCache() *endorsementCache {
	return &endorsementCache{
		entries: make(map[util.USBDeviceID]*endorsementEntry),
	}
}

// ======= Circular buffer logic =======

const (
	maxPacketsPerDevice     = 256
	maxLoggedBytesPerPacket = 64
)

type packetRecord struct {
	len  int
	data [maxLoggedBytesPerPacket]byte
}

type packetRingBuffer struct {
	next    int
	wrapped bool
	records [maxPacketsPerDevice]packetRecord
}

func (rb *packetRingBuffer) logPacket(pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	if len(pkt) > maxLoggedBytesPerPacket {
		pkt = pkt[:maxLoggedBytesPerPacket]
	}

	rec := &rb.records[rb.next]
	rec.len = len(pkt)

	copy(rec.data[:], pkt)
	rb.next++
	if rb.next >= maxPacketsPerDevice {
		rb.next = 0
		rb.wrapped = true
	}
}

func (rb *packetRingBuffer) dumpToLog(dev util.USBDeviceID) {
	start := 0
	if rb.wrapped {
		start = rb.next
	}
	idx := 0
	for i := 0; i < maxPacketsPerDevice; i++ {
		pos := (start + i) % maxPacketsPerDevice
		rec := rb.records[pos]
		if rec.len == 0 {
			continue
		}
		idx++
		log.Printf("[APPLET-USB] log[%d] dev=%s len=%d data=% x", idx, dev, rec.len, rec.data[:rec.len])
	}
}

// ======= Checking endorsement cache and logging packets =======

var usbEndorsements = newEndorsementCache()

func handleUsbPacket(dev util.USBDeviceID, payload []byte) byte {
	entry, ok := usbEndorsements.entries[dev]

	if !ok {
		log.Printf("[APPLET-USB] BLOCK dev=%s (not endorsed) len=%d", dev, len(payload))
		return 0x00
	}

	// if TTL exhausted or status not active, mark as expired and block
	if entry.status != endorsementActive || entry.TTL == 0 {
		if entry.status != endorsementExpired {
			entry.status = endorsementExpired
		}
		log.Printf("[APPLET-USB] BLOCK vID=%04x pID=%04x (endorsement expired, TTL=%d) len=%d",
			dev.VendorID, dev.ProductID, entry.TTL, len(payload))
		// TODO: Call placeholder re-endorsement function here
		return 0x00
	}

	entry.TTL--
	entry.log.logPacket(payload)

	log.Printf("[APPLET-USB] PASS vID=%04x pID=%04x len=%d remaining_TTL=%d",
		dev.VendorID, dev.ProductID, len(payload), entry.TTL)
	return 0x01
}

// ======= RPC Communication =======

func wait_command() *util.TLV {
	var status bool
	status = false
	for !status {
		syscall.Call("RPC.CheckChannel", nil, &status)
	}

	var cmd util.TLV
	syscall.Call("RPC.PopChannel", nil, &cmd)
	return &cmd
}

func send_response(tag byte, embed bool, value []byte) *util.TLV {
	rspTLV, err := util.TLV_pack(tag, embed, []byte(value))
	if err != nil {
		panic(err)
	}

	syscall.Call("RPC.SendResponse", &rspTLV, nil)
	return rspTLV
}

func main() {
	log.Printf("[APPLET] Booting!")

	for {
		cmdTLV := wait_command()
		log.Printf("[APPLET] Received TAG: %x DATA: %s", cmdTLV.Tag, string(cmdTLV.Value))

		if cmdTLV.Tag == 0x7F { // quit
			break
		}

		switch cmdTLV.Tag & 0x7F {
		case 0x30: // check device
			rdr := util.CreateDeserializer(cmdTLV.Value)
			tlvDeviceID := util.TLV_deserialize(rdr)
			tlvUSBPacket := util.TLV_deserialize(rdr)

			var deviceID util.USBDeviceID
			rdr = util.CreateDeserializer(tlvDeviceID.Value)
			util.Deserialize(rdr, &deviceID)
			usbPkt := tlvUSBPacket.Value

			log.Printf("[APPLET] Received USB packet from VID: %04x, PID: %04x", deviceID.VendorID, deviceID.ProductID)
			log.Printf("[APPLET] Received USB packet %x\n", usbPkt)

			decision := handleUsbPacket(deviceID, usbPkt)
			send_response(0x30, false, []byte{decision})

		case 0x31: // endorse
			var deviceID util.USBDeviceID
			rdr := util.CreateDeserializer(cmdTLV.Value)
			util.Deserialize(rdr, &deviceID)

			log.Printf("[APPLET] Received endorsement request for VID: %04x, PID: %04x", deviceID.VendorID, deviceID.ProductID)

			// Authentication procedure
			success := true
			if success {
				endorsement_cache_entry := &endorsementEntry{
					device: deviceID,
					status: endorsementActive,
					TTL:    1000, //TBD
				}
				usbEndorsements.entries[deviceID] = endorsement_cache_entry
			}

			send_response(0x31, false, []byte{1})
		}
	}

	log.Printf("[APPLET] Exiting!")
	applet.Exit()
}
