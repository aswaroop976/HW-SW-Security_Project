// Copyright (c) The GoTEE authors. All Rights Reserved.
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package main

import (
	"log"
	"os"
	"runtime"
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
	cmdTLV, err := util.TLV_pack(1, embed, []byte(value))
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

func main() {
	log.Printf("%s/%s (%s) • system/supervisor (Non-secure:%v)", runtime.GOOS, runtime.GOARCH, runtime.Version(), imx6ul.ARM.NonSecure())

	log.Printf("Packing a TLV...")

	msg := "ToMyTrustedApplet"
	send_command(0x20, false, []byte(msg))
	rspTLV := wait_response()

	log.Printf("OS Received response: %s", string(rspTLV.Value))

	log.Printf("Supervisor exits.")
	exit()
}
