// Copyright (c) The GoTEE authors. All Rights Reserved.
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package main

import (
	//"crypto/aes"
	//"crypto/sha256"
	"log"
	"os"
	"runtime"
	_ "unsafe"
	"bufio"
	"strings"

	"github.com/usbarmory/tamago/dma"
	"github.com/usbarmory/tamago/soc/nxp/imx6ul"

	"github.com/usbarmory/GoTEE-example/mem"
	//usbarmory "github.com/usbarmory/tamago/board/usbarmory/mk2"
	//"time"
)

//go:linkname ramStart runtime.ramStart
var ramStart uint32 = mem.NonSecureStart

//go:linkname ramSize runtime.ramSize
var ramSize uint32 = mem.NonSecureSize

//go:linkname hwinit runtime.hwinit1
func hwinit() {
	imx6ul.Init()
}

//go:linkname printk runtime.printk
func printk(c byte) {
	printSecure(c)
}

// static buffer in .data/.bss, visible to the monitor through ExecCtx
var Pwd = [...]byte{'s','u','p','e','r','s','e','c','r','e','t','1','2','3'}

// ======= Decode hex function helpers =======

func decodeHexString(s string) ([]byte, error) {
    // must be even length
    out := make([]byte, len(s)/2)
    for i := 0; i < len(out); i++ {
        hi := fromHexChar(s[2*i])
        lo := fromHexChar(s[2*i+1])
        out[i] = byte((hi << 4) | lo)
    }
    return out, nil
}

func fromHexChar(c byte) int {
    switch {
    case c >= '0' && c <= '9':
        return int(c - '0')
    case c >= 'a' && c <= 'f':
        return int(c - 'a' + 10)
    case c >= 'A' && c <= 'F':
        return int(c - 'A' + 10)
    }
    return -1
}

type deviceID struct {
	vendorID uint16
	productID uint16
}

type endorsementStatus uint8

const (
	endorsementUnknown endorsementStatus = iota
	endorsementActive
	endorsementExpired
)

type endorsementEntry struct {
	device deviceID
	status endorsementStatus
	TTL uint32
	log packetRingBuffer
}

type endorsementCache struct {
	entries map[deviceID]*endorsementEntry
}

func newEndorsementCache() *endorsementCache {
	return &endorsementCache{
		entries: make(map[deviceID]*endorsementEntry),
	}
}

// ======= Circular buffer logic =======

const (
	maxPacketsPerDevice = 256
	maxLoggedBytesPerPacket = 64
)

type packetRecord struct {
	len int
	data [maxLoggedBytesPerPacket] byte
}

type packetRingBuffer struct {
	next int
	wrapped bool
	records [maxPacketsPerDevice] packetRecord
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
	if rb.next >= maxPacketsPerDevice{
		rb.next = 0
		rb.wrapped = true
	}
}

func (rb *packetRingBuffer) dumpToLog(dev deviceID){
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
		log.Printf("[USB] log[%d] dev=%s len=%d data=% x", idx, dev, rec.len, rec.data[:rec.len])
	}
}

// ======= Checking endorsement cache and logging packets =======

var usbEndorsements = newEndorsementCache()

func handleUsbPacketFromDevice(dev deviceID, payload []byte) bool {
	entry, ok := usbEndorsements.entries[dev]

	if !ok {
		log.Printf("[USB] BLOCK dev=%s (not endorsed) len=%d", dev, len(payload))
		// TODO: Trigger re-endorsement request via applet/TEE
		return false
	}

	// if TTL exhausted or status not active, mark as expired and block
	if entry.status != endorsementActive || entry.TTL == 0 {
		if entry.status != endorsementExpired {
			entry.status = endorsementExpired
		}
		log.Printf("[USB] BLOCK dev=%s (endorsement expired, TTL=%d) len=%d",
		    dev, entry.TTL, len(payload))
		// TODO: Call placeholder re-endorsement function here
		return false
	}

	entry.TTL--
	entry.log.logPacket(payload)

	log.Printf("[USB] PASS dev=%s len=%d remaining_TTL=%d", dev, len(payload), entry.TTL)
	return true
}


func init() {
	log.SetFlags(log.Ltime)
	log.SetOutput(os.Stdout)

	if !imx6ul.Native {
		return
	}

	switch imx6ul.Family {
	case imx6ul.IMX6UL:
		imx6ul.SetARMFreq(imx6ul.Freq528)
		imx6ul.CAAM.DeriveKeyMemory = dma.Default()
	case imx6ul.IMX6ULL:
		imx6ul.SetARMFreq(imx6ul.FreqMax)
	}
}

var embeddedKeyboardPackets = `
6 0000160000000000
6 0000000000000000
6 0000160000000000
6 0000000000000000
6 0000160000000000
6 0000000000000000
`
func main() {
	log.Printf("%s/%s (%s) • system/supervisor (Non-secure:%v)", runtime.GOOS, runtime.GOARCH, runtime.Version(), imx6ul.ARM.NonSecure())

	scanner := bufio.NewScanner(strings.NewReader(embeddedKeyboardPackets))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" { continue }
		
		parts := strings.Fields(line)


		hexStr := strings.ReplaceAll(parts[1], ":", "")
		pkt, _ := decodeHexString(hexStr)

		dev := deviceID{
			vendorID: 0x046d,
			productID: 0xc53f,
		}

		// Add entry into endorsement cache for testing
		entry, ok := usbEndorsements.entries[dev]
		if !ok {
			entry = &endorsementEntry{
				device: dev,
				status: endorsementActive,
				TTL: 1000, //TBD
			}
			usbEndorsements.entries[dev] = entry
		}

		permitted := handleUsbPacketFromDevice(dev, pkt)
		if !permitted {
			log.Printf("[REPLAY] packet BLOCKED dev = %s", dev)
		}
	}

	log.Printf("[REPLAY] embedded keyboard packet replay complete")

	// uncomment to test memory protection
	//mem.TestAccess("Non-secure OS")
	//blink_right()


	// yield back to secure monitor
	log.Printf("supervisor is about to yield back")
	exit()

	// this should be unreachable
	log.Printf("supervisor says goodbye")
}
