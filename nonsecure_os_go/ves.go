package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/usbarmory/GoTEE-example/util"
)

func endorseDeviceID(deviceID util.USBDeviceID, reqCh chan<- smcRequest) bool {

	buf := util.CreateSerializer()
	serial, _ := util.Serialize(buf, &deviceID)

	var rspTLV *util.TLV
	r := smcRequest{
		tag:        0x31, // endorse
		embed:      false,
		value:      serial,
		expect_rsp: true,
		rsp:        &rspTLV,
		done:       make(chan struct{}),
	}
	fmt.Printf("[VES] Sending DEVICE ENDORSE (0x31) command.\n")

	reqCh <- r // secure monitor call
	<-r.done   // block until SMC completed
	return (rspTLV.Value[0] != 0)
}

func ValidationService(reqCh chan<- smcRequest, wg *sync.WaitGroup) {
	defer wg.Done()
	fmt.Printf("[VES] Booting!\n")

	var testDeviceID = util.USBDeviceID{
		VendorID:  0x046d,
		ProductID: 0xc53f,
	}

	success := endorseDeviceID(testDeviceID, reqCh)
	if success {
		log.Printf("[VES] Success in endorsing device VID: %04x, PID: %04x",
			testDeviceID.VendorID, testDeviceID.ProductID)
	} else {
		log.Printf("[VES] Failure in endorsing device VID: %04x, PID: %04x",
			testDeviceID.VendorID, testDeviceID.ProductID)
	}

	fmt.Printf("[VES] Exiting!\n")
}
