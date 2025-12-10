// Copyright (c) The GoTEE authors. All Rights Reserved.
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
	_ "unsafe"

	"github.com/usbarmory/tamago/dma"
	"github.com/usbarmory/tamago/soc/nxp/imx6ul"

	"github.com/usbarmory/GoTEE-example/mem"
	"github.com/usbarmory/GoTEE-example/util"
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

func send_command(tag byte, embed bool, value []byte) *util.TLV {
	cmdTLV, err := util.TLV_pack(tag, embed, []byte(value))
	if err != nil {
		panic(err)
	}

	commandApplet(cmdTLV)
	return cmdTLV
}

func wait_response() *util.TLV {
	rspLen := uint16(0)
	for rspLen == 0 {
		checkAppletResponse(&rspLen)
	}

	var rspTLV util.TLV
	rspTLV.Length = rspLen
	rspTLV.Value = make([]byte, rspLen)
	getAppletResponse(&rspTLV)
	return &rspTLV
}

// Request type: each goroutine creates one of these
type smcRequest struct {
	tag        byte
	embed      bool
	value      []byte
	expect_rsp bool
	rsp        **util.TLV
	done       chan struct{}
}

func SMBridge(reqCh <-chan smcRequest) {
	for req := range reqCh {
		send_command(req.tag, req.embed, req.value)
		if req.expect_rsp {
			*req.rsp = wait_response()
		}
		close(req.done)
	}
}

func main() {
	log.Printf("%s/%s (%s) • system/supervisor (Non-secure:%v)",
		runtime.GOOS, runtime.GOARCH, runtime.Version(), imx6ul.ARM.NonSecure())

	smcRequestCh := make(chan smcRequest)
	var wg sync.WaitGroup

	go SMBridge(smcRequestCh)

	wg.Add(2)
	go USBBridge(smcRequestCh, &wg)
	go ValidationService(smcRequestCh, &wg)
	wg.Wait()

	r := smcRequest{
		tag:        0x7F,
		embed:      false,
		value:      []byte(""),
		expect_rsp: false,
		rsp:        nil,
		done:       make(chan struct{}),
	}

	fmt.Printf("[NS-OS] Terminating APPLET.\n")

	smcRequestCh <- r // secure monitor call
	<-r.done          // block until SMC completed
	close(smcRequestCh)

	log.Printf("[NS-OS] Exiting!")
	exit()
}
