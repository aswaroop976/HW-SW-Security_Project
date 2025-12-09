package main

import (
	"bufio"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/usbarmory/GoTEE-example/util"
)

const (
	maxUSBPorts = 7
)

var USBDeviceMap [maxUSBPorts]util.USBDeviceID

var testDeviceID = util.USBDeviceID{
	VendorID:  0x046d,
	ProductID: 0xc53f,
}

var embeddedKeyboardPackets = `
6 0000160000000000
6 0000000000000000
6 0000160000000000
6 0000000000000000
6 0000160000000000
6 0000000000000000
`

func decodeHexString(s string) ([]byte, error) {
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

func handleUsbPacketFromDevice(deviceID util.USBDeviceID, pkt []byte, reqCh chan<- smcRequest) bool {
	var rspTLV *util.TLV
	r := smcRequest{
		tag:        0x30, // device check
		embed:      false,
		value:      pkt,
		expect_rsp: true,
		rsp:        &rspTLV,
		done:       make(chan struct{}),
	}

	fmt.Printf("USB Bridge sending DEVICE CHECK command.\n")

	reqCh <- r // secure monitor call
	<-r.done   // block until SMC completed
	return (rspTLV.Value[0] != 0)
}

func scan_USB(reqCh chan<- smcRequest) {
	scanner := bufio.NewScanner(strings.NewReader(embeddedKeyboardPackets))
	lineNum := 0

	// Install dummy device without going through USB enumeration.
	USBDeviceMap[6] = testDeviceID

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)

		hexStr := strings.ReplaceAll(parts[1], ":", "")
		pkt, _ := decodeHexString(hexStr)

		usbPort := int(parts[0][0] - '0')
		deviceID := USBDeviceMap[usbPort]

		permitted := handleUsbPacketFromDevice(deviceID, pkt, reqCh)
		if !permitted {
			log.Printf("[REPLAY] packet BLOCKED port = %d", usbPort)
		} else {
			log.Printf("[REPLAY] packet ACCEPTED port = %d", usbPort)
		}
	}

	log.Printf("[REPLAY] embedded keyboard packet replay complete")
}

func USBBridge(reqCh chan<- smcRequest, wg *sync.WaitGroup) {
	defer wg.Done()
	scan_USB(reqCh)
	fmt.Printf("USB Bridge finished\n")
}
