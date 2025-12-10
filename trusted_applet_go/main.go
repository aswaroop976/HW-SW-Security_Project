// Copyright (c) The GoTEE authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package main

import (
	"log"
	"os"
	"runtime"
	"sync"

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
	mu     sync.Mutex
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

func (entry *endorsementEntry) incrementTTL(increment int) {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	entry.TTL--
}

func (entry *endorsementEntry) modifyStatus(status endorsementStatus) {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	entry.status = status
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

func (entry *endorsementEntry) logPacket(pkt []byte) {
	entry.mu.Lock()
	defer entry.mu.Unlock()

	if len(pkt) == 0 {
		return
	}
	if len(pkt) > maxLoggedBytesPerPacket {
		pkt = pkt[:maxLoggedBytesPerPacket]
	}

	rec := &entry.log.records[entry.log.next]
	rec.len = len(pkt)

	copy(rec.data[:], pkt)
	entry.log.next++
	if entry.log.next >= maxPacketsPerDevice {
		entry.log.next = 0
		entry.log.wrapped = true
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

	if !ok || entry.status == endorsementUnknown {
		log.Printf("[APPLET-USB] BLOCK dev=%s (not endorsed) len=%d", dev, len(payload))
		return 0x00
	}

	// if TTL exhausted or status not active, mark as expired and block
	if entry.status == endorsementExpired {
		log.Printf("[APPLET-USB] BLOCK vID=%04x pID=%04x (endorsement expired, TTL=%d) len=%d",
			dev.VendorID, dev.ProductID, entry.TTL, len(payload))
		// TODO: Call placeholder re-endorsement function here
		return 0x00
	}

	entry.incrementTTL(-1)
	entry.logPacket(payload)

	log.Printf("[APPLET-USB] PASS vID=%04x pID=%04x len=%d remaining_TTL=%d",
		dev.VendorID, dev.ProductID, len(payload), entry.TTL)

	if entry.status == endorsementActive && entry.TTL == 0 {
		entry.modifyStatus(endorsementExpired)
	}
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

func channel_receiver(usbCh, vesCh chan<- *util.TLV) {
	log.Printf("[APPLET-RCV] Channel RCV Routine Booting!")

	for {
		cmdTLV := wait_command()
		log.Printf("[APPLET-RCV] Received TAG: %x DATA: %s", cmdTLV.Tag, string(cmdTLV.Value))

		if cmdTLV.Tag == 0x7F { // quit
			usbCh <- cmdTLV
			vesCh <- cmdTLV
			break
		}

		if (cmdTLV.Tag&0x7F) >= 0x30 && (cmdTLV.Tag&0x7F) < 0x50 {
			// Belongs to the USB handler.
			usbCh <- cmdTLV
		}

		if (cmdTLV.Tag&0x7F) >= 0x50 && (cmdTLV.Tag&0x7F) < 0x70 {
			// Belongs to the Endorsement Service handler.
			vesCh <- cmdTLV
		}
	}

	log.Printf("[APPLET-RCV] Channel RCV Routine Booting!")
}

func channel_sender(usbCh, vesCh <-chan *util.TLV) {
	// nothing for now
}

func usb_handler(ch <-chan *util.TLV, wg *sync.WaitGroup) {
	defer wg.Done()
	log.Printf("[APPLET-USB] USB Routine Booting!")

	for {
		cmdTLV := <-ch
		log.Printf("[APPLET-USB] USB Routine received packet.")

		if cmdTLV.Tag == 0x7F { // quit
			break
		}

		if cmdTLV.Tag&0x7F == 0x30 {
			rdr := util.CreateDeserializer(cmdTLV.Value)
			tlvDeviceID := util.TLV_deserialize(rdr)
			tlvUSBPacket := util.TLV_deserialize(rdr)

			var deviceID util.USBDeviceID
			rdr = util.CreateDeserializer(tlvDeviceID.Value)
			util.Deserialize(rdr, &deviceID)
			usbPkt := tlvUSBPacket.Value

			log.Printf("[APPLET-USB] Received USB packet from VID: %04x, PID: %04x", deviceID.VendorID, deviceID.ProductID)
			log.Printf("[APPLET-USB] Received USB packet %x\n", usbPkt)

			decision := handleUsbPacket(deviceID, usbPkt)
			send_response(0x30, false, []byte{decision})
		}
	}

	log.Printf("[APPLET-USB] USB Routine Exiting!")
}

func validation_handler(ch <-chan *util.TLV, wg *sync.WaitGroup) {
	defer wg.Done()
	log.Printf("[APPLET-VES] Validation Routine Booting!")

	for {
		cmdTLV := <-ch
		log.Printf("[APPLET-VES] Validation Routine received packet.")

		if cmdTLV.Tag == 0x7F { // quit
			break
		}

		if cmdTLV.Tag&0x7F == 0x50 {
			var deviceID util.USBDeviceID
			rdr := util.CreateDeserializer(cmdTLV.Value)
			util.Deserialize(rdr, &deviceID)

			log.Printf("[APPLET-VES] Received endorsement request for VID: %04x, PID: %04x", deviceID.VendorID, deviceID.ProductID)

			// Authentication procedure
			success := true
			if success {
				endorsement_cache_entry := &endorsementEntry{
					device: deviceID,
					status: endorsementActive,
					TTL:    5, //TBD
				}
				usbEndorsements.entries[deviceID] = endorsement_cache_entry
			}

			send_response(0x31, false, []byte{1})
		}
	}

	log.Printf("[APPLET-VES] Validation Routine Exiting!")
}

func main() {
	log.Printf("[APPLET] Booting!")

	usbCh := make(chan *util.TLV)
	vesCh := make(chan *util.TLV)
	var wg sync.WaitGroup

	go channel_receiver(usbCh, vesCh)

	wg.Add(2)
	go usb_handler(usbCh, &wg)
	go validation_handler(vesCh, &wg)
	wg.Wait()

	log.Printf("[APPLET] Exiting!")
	applet.Exit()
}
