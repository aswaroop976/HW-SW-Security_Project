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

		switch cmdTLV.Tag {
		case 0x30: // check device
			send_response(0x30, false, []byte{1})
		case 0x31: // endorse
			var deviceID util.USBDeviceID
			util.Deserialize(cmdTLV.Value, &deviceID)
			log.Printf("[APPLET] Received endorsement for VID: %04x, PID: %04x", deviceID.VendorID, deviceID.ProductID)
			send_response(0x31, false, []byte{1})
		}
	}

	log.Printf("[APPLET] Exiting!")
	applet.Exit()
}
