// Copyright (c) The GoTEE authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package main

import (
	"bytes"
	"log"
	"os"
	"runtime"
	"crypto/ed25519"
	"crypto/sha256"

	"github.com/usbarmory/GoTEE-example/util"
	"github.com/usbarmory/GoTEE/applet"
	"github.com/usbarmory/GoTEE/syscall"
)

// Global state in applet
var (
	lastNonce      [32]byte
	haveNonce      bool
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

// If first time we see an endorse request (or VES de-auth'd); send challenge
func sendChallenge(cmdTLV *util.TLV) {
	var chal util.AuthChallenge
	err := syscall.Call("RPC.GetChallenge", struct{}{}, &chal)
	if err != nil {
		log.Printf("applet: RPC.GetChallenge error: %v", err)
		rsp := util.AuthResult{OK: 0}
		b, _ := util.Serialize(rsp)
		send_response(0x34, false, b)
		return
	}

	lastNonce = chal.Nonce
	haveNonce = true

	b, err := util.Serialize(chal)
        if err != nil {
		log.Printf("[APPLET] Serialize AuthChallenge failed: %v", err)
		rsp := util.AuthResult{OK: 0}
		b2, _ := util.Serialize(rsp)
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
		b, _ := util.Serialize(rsp)
		send_response(util.TagAuthResult, false, b)
		return
	}
	var resp util.AuthResponse
	if err := util.Deserialize(cmdTLV.Value, &resp); err != nil {
		log.Printf("[APPLET] Failed to deserialize AuthResponse: %v", err)
		rsp := util.AuthResult{OK: 0}
		b, _ := util.Serialize(rsp)
		send_response(util.TagAuthResult, false, b)
		return
	}

	// 1) Check nonce matches
	if resp.Nonce != lastNonce {
		log.Printf("[APPLET] Nonce mismatch in AuthResponse")
		rsp := util.AuthResult{OK: 0}
		b, _ := util.Serialize(rsp)
		send_response(util.TagAuthResult, false, b)
		return
	}

	// 2) Compute expected message and verify signature
	msg := buildVESAuthMessage(resp.Nonce) // same as VES side

	if !bytes.Equal(resp.VESPub[:], expectedVESPub[:]) {
		log.Printf("[APPLET] VES public key mismatch")
		rsp := util.AuthResult{OK: 0}
		b, _ := util.Serialize(rsp)
		send_response(util.TagAuthResult, false, b)
		return
	}

	pk := ed25519.PublicKey(expectedVESPub[:])
	if !ed25519.Verify(pk, msg, resp.Sig[:]) {
		log.Printf("[APPLET] AuthResponse signature verification failed")
		rsp := util.AuthResult{OK: 0}
		b, _ := util.Serialize(rsp)
		send_response(util.TagAuthResult, false, b)
		return
	}

	// 3) Success: mark VES as authenticated
	vesAuthenticated = true
	haveNonce = false // consume nonce
	log.Printf("[APPLET] VES authenticated")

	rsp := util.AuthResult{OK: 1}
	b, _ := util.Serialize(rsp)
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
		log.Printf("[APPLET] Received TAG: %x DATA: %s", cmdTLV.Tag, string(cmdTLV.Value))

		if cmdTLV.Tag == 0x7F { // quit
			break
		}

		switch cmdTLV.Tag {
		case 0x30: // check device
			send_response(0x30, false, []byte{1})
		case 0x31: // endorse
			if !vesAuthenticated{
				sendChallenge(cmdTLV)
				continue
			}
			var deviceID util.USBDeviceID
			util.Deserialize(cmdTLV.Value, &deviceID)
			log.Printf("[APPLET] Received endorsement for VID: %04x, PID: %04x", deviceID.VendorID, deviceID.ProductID)
			send_response(0x31, false, []byte{1})
		case 0x33: // authentication response VES -> Applet
			handleAuthResponse(cmdTLV)
		}
	}

	log.Printf("[APPLET] Exiting!")
	applet.Exit()
}
