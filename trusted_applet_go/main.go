// Copyright (c) The GoTEE authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/usbarmory/GoTEE-example/util"
	"github.com/usbarmory/GoTEE/applet"
	"github.com/usbarmory/GoTEE/syscall"
)

// Global state in applet
var (
	lastNonce        [32]byte
	haveNonce        bool
	vesAuthenticated bool
)
var expectedVESPub = [32]byte{
	0x67, 0x95, 0x5e, 0xd9, 0x4d, 0xb1, 0x0c, 0xb4,
	0xb1, 0x23, 0x46, 0x54, 0xc6, 0x8c, 0xdb, 0x90,
	0x33, 0x4b, 0xa0, 0xcf, 0xc1, 0x83, 0x27, 0xd9,
	0xcc, 0xcf, 0xa5, 0x37, 0x74, 0x57, 0x46, 0x50,
}

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
		time.Sleep(100 * time.Microsecond)
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

// If first time we see an endorse request (or VES de-auth'd); send challenge
func sendChallenge(cmdTLV *util.TLV) {
	var chal util.AuthChallenge
	err := syscall.Call("RPC.GetChallenge", struct{}{}, &chal)
	if err != nil {
		log.Printf("applet: RPC.GetChallenge error: %v", err)
		rsp := util.AuthResult{OK: 0}
		buf := util.CreateSerializer()
		b, _ := util.Serialize(buf, rsp)
		send_response(0x34, false, b)
		return
	}

	lastNonce = chal.Nonce
	haveNonce = true
	log.Printf("Applet received NONCE: %x\n", lastNonce)

	buf := util.CreateSerializer()
	b, err := util.Serialize(buf, chal)
	if err != nil {
		log.Printf("[APPLET] Serialize AuthChallenge failed: %v", err)
		rsp := util.AuthResult{OK: 0}
		b2, _ := util.Serialize(buf, rsp)
		send_response(0x34, false, b2)
		return
	}

	send_response(0x32, false, b)
	log.Printf("[APPLET] Sent auth challenge to VES (nonce from trusted_os)")
	return
}

func handleAuthResponse(cmdTLV *util.TLV) {
	if !haveNonce {
		log.Printf("[APPLET] got response without outstanding nonce")
		rsp := util.AuthResult{OK: 0}
		buf := util.CreateSerializer()
		b, _ := util.Serialize(buf, rsp)
		send_response(util.TagAuthResult, false, b)
		return
	}
	var resp util.AuthResponse
	rdr := util.CreateDeserializer(cmdTLV.Value)
	if err := util.Deserialize(rdr, &resp); err != nil {
		log.Printf("[APPLET] Failed to deserialize AuthResponse: %v", err)
		rsp := util.AuthResult{OK: 0}
		buf := util.CreateSerializer()
		b, _ := util.Serialize(buf, rsp)
		send_response(util.TagAuthResult, false, b)
		return
	}

	// 1) Check nonce matches
	if resp.Nonce != lastNonce {
		log.Printf("[APPLET] Nonce mismatch in AuthResponse")
		rsp := util.AuthResult{OK: 0}
		buf := util.CreateSerializer()
		b, _ := util.Serialize(buf, rsp)
		send_response(util.TagAuthResult, false, b)
		return
	}

	log.Printf("[APPLET] VES NONCE received matches challenge NONCE.\n")

	// 2) Compute expected message and verify signature
	msg := buildVESAuthMessage(resp.Nonce) // same as VES side

	if !bytes.Equal(resp.VESPub[:], expectedVESPub[:]) {
		log.Printf("[APPLET] VES public key mismatch")
		rsp := util.AuthResult{OK: 0}
		buf := util.CreateSerializer()
		b, _ := util.Serialize(buf, rsp)
		send_response(util.TagAuthResult, false, b)
		return
	}

	pk := ed25519.PublicKey(expectedVESPub[:])
	if !ed25519.Verify(pk, msg, resp.Sig[:]) {
		log.Printf("[APPLET] AuthResponse signature verification failed")
		rsp := util.AuthResult{OK: 0}
		buf := util.CreateSerializer()
		b, _ := util.Serialize(buf, rsp)
		send_response(util.TagAuthResult, false, b)
		return
	}

	log.Printf("[APPLET] Signature verification succeeded.\n")

	// 3) Success: mark VES as authenticated
	vesAuthenticated = true
	haveNonce = false // consume nonce
	log.Printf("[APPLET] VES authenticated")

	rsp := util.AuthResult{OK: 1}
	buf := util.CreateSerializer()
	b, _ := util.Serialize(buf, rsp)
	send_response(util.TagAuthResult, false, b)
}
func buildVESAuthMessage(nonce [32]byte) []byte {
	h := sha256.New()
	h.Write(nonce[:])
	h.Write([]byte("GoTEE-VES-auth-v1")) // context string
	return h.Sum(nil)
}

func main() {
	log.Printf("[APPLET] Booting!")

	for {
		cmdTLV := wait_command()
		log.Printf("[APPLET] Received TAG: %x DATA: %x", cmdTLV.Tag, cmdTLV.Value)

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
			if !vesAuthenticated {
				log.Printf("[APPLET] VES not authenticated. Creating Authentication challenge.")
				sendChallenge(cmdTLV)
				continue
			}
			var deviceID util.USBDeviceID
			rdr := util.CreateDeserializer(cmdTLV.Value)
			util.Deserialize(rdr, &deviceID)
			log.Printf("[APPLET] Received endorsement for VID: %04x, PID: %04x", deviceID.VendorID, deviceID.ProductID)

			endorsement_cache_entry := &endorsementEntry{
				device: deviceID,
				status: endorsementActive,
				TTL:    1000, //TBD
			}
			usbEndorsements.entries[deviceID] = endorsement_cache_entry
			send_response(0x31, false, []byte{1})
		case 0x33: // authentication response VES -> Applet
			handleAuthResponse(cmdTLV)
		}
	}

	log.Printf("[APPLET] Exiting!")
	applet.Exit()
}
