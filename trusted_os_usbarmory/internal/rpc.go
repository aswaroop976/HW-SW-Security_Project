// Copyright (c) The GoTEE authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package gotee

import (
	"crypto/rand"
	"errors"

	usbarmory "github.com/usbarmory/tamago/board/usbarmory/mk2"

	"github.com/usbarmory/GoTEE-example/util"
)

// RPC represents an example receiver for user mode <--> system RPC over system
// calls.
type RPC struct{}

// Echo returns a response with the input string.
func (r *RPC) Echo(in string, out *string) error {
	*out = in
	return nil
}

// LED receives a LED state request.
func (r *RPC) LED(led util.LEDStatus, _ *bool) error {
	switch led.Name {
	case "white", "White", "WHITE":
		return errors.New("LED is secure only")
	case "blue", "Blue", "BLUE":
		return usbarmory.LED(led.Name, led.On)
	default:
		return errors.New("invalid LED")
	}

	return nil
}

func (r *RPC) CheckChannel(_ *bool, ready *bool) error {
	// log.Printf("Checking for APPLET command. %d commands in queue.", len(appletCmdCh))
	*ready = len(appletCmdCh) > 0
	return nil
}

func (r *RPC) PopChannel(_ *bool, s_tlv *util.TLV) error {
	// log.Printf("Collecting APPLET command.")
	ns_tlv := <-appletCmdCh
	secure_buffer := make([]byte, ns_tlv.Length)
	copy(secure_buffer, ns_tlv.Value)
	s_tlv.Tag = ns_tlv.Tag
	s_tlv.Length = ns_tlv.Length
	s_tlv.Value = secure_buffer
	return nil
}

func (r *RPC) SendResponse(rsp *util.TLV, _ *bool) error {
	// log.Printf("Stashing APPLET response.")
	appletRspCh <- rsp
	appletRspLenCh <- rsp.Length
	// log.Printf("received message... TAG: %d, LENGTH: %d, VALUE:%s", rsp.Tag, rsp.Length, string(rsp.Value))
	return nil
}

func (r *RPC) CheckRspChannel(_ *bool, ready *bool) error {
	// log.Printf("Checking for APPLET command. %d commands in queue.", len(appletCmdCh))
	*ready = len(osRespondCh) > 0
	return nil
}

func (r *RPC) PopRspChannel(_ *bool, s_tlv *util.TLV) error {
	// log.Printf("Collecting APPLET command.")
	ns_tlv := <-osRespondCh
	secure_buffer := make([]byte, ns_tlv.Length)
	copy(secure_buffer, ns_tlv.Value)
	s_tlv.Tag = ns_tlv.Tag
	s_tlv.Length = ns_tlv.Length
	s_tlv.Value = secure_buffer
	return nil
}

func (r *RPC) GetChallenge(_ struct{}, out *util.AuthChallenge) error {
	// generate a fresh 32-byte nonce using crypto/rand
	if _, err := rand.Read(out.Nonce[:]); err != nil {
		return errors.New("[RPC.GetChallenge] rand.Read error")
	}
	return nil
}

func (r *RPC) SendCommand(cmd *util.TLV, _ *bool) error {
	appletToOSCh <- cmd
	appletToOSLenCh <- cmd.Length
	return nil
}
