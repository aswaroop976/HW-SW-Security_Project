package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"log"
	"sync"

	"github.com/usbarmory/GoTEE-example/util"
)

var VESPub = [32]byte{
	0x67, 0x95, 0x5e, 0xd9, 0x4d, 0xb1, 0x0c, 0xb4,
	0xb1, 0x23, 0x46, 0x54, 0xc6, 0x8c, 0xdb, 0x90,
	0x33, 0x4b, 0xa0, 0xcf, 0xc1, 0x83, 0x27, 0xd9,
	0xcc, 0xcf, 0xa5, 0x37, 0x74, 0x57, 0x46, 0x50,
}

var VESPriv = [64]byte{
	0x7d, 0x50, 0x56, 0xc1, 0x21, 0xa8, 0x11, 0x0b,
	0x14, 0x69, 0xbd, 0x26, 0x3b, 0x93, 0x5f, 0x5d,
	0x6e, 0xe3, 0xda, 0x6b, 0x5a, 0x4e, 0x3c, 0x6c,
	0x7f, 0x70, 0xb0, 0x55, 0xd6, 0x17, 0x6a, 0x4c,
	0x67, 0x95, 0x5e, 0xd9, 0x4d, 0xb1, 0x0c, 0xb4,
	0xb1, 0x23, 0x46, 0x54, 0xc6, 0x8c, 0xdb, 0x90,
	0x33, 0x4b, 0xa0, 0xcf, 0xc1, 0x83, 0x27, 0xd9,
	0xcc, 0xcf, 0xa5, 0x37, 0x74, 0x57, 0x46, 0x50,
}

func VESPublicKey() ed25519.PublicKey {
	return ed25519.PublicKey(VESPub[:])
}

func VESPrivateKey() ed25519.PrivateKey {
	return ed25519.PrivateKey(VESPriv[:])
}

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

func mutualAttestationVES(reqCh chan<- smcRequest) error {
	log.Printf("[VES] Starting attestation with applet")

	payload := []byte{}
	rspTLV, err := smcRoundTrip(reqCh, 0x31, payload)
	if err != nil {
		return err
	}

	// 0x32 is AuthChallenge tag
	// Wait till trusted applet sends AuthChallenge
	for {
		if rspTLV.Tag == 0x32 {
			log.Printf("[VES] Received AuthChallenge from trusted_applet")
			break
		}
	}

	var chal util.AuthChallenge
	rdr := util.CreateDeserializer(rspTLV.Value)
	if err := util.Deserialize(rdr, &chal); err != nil {
		log.Printf("[VES] deserialize issue")
		return fmt.Errorf("deserialize challenge: %w", err)
	}

	// Build AuthResponse: VESPub, nonce, sig
	msg := buildVESAuthMessage(chal.Nonce)
	sig := ed25519.Sign(VESPrivateKey(), msg)

	var resp util.AuthResponse
	copy(resp.VESPub[:], VESPub[:])
	resp.Nonce = chal.Nonce
	copy(resp.Sig[:], sig)

	buf := util.CreateSerializer()
	respBytes, err := util.Serialize(buf, resp)
	if err != nil {
		log.Printf("[VES] serialize issue")
		return fmt.Errorf("serialize auth response: %w", err)
	}

	rspTLV, err = smcRoundTrip(reqCh, 0x33, respBytes)
	if err != nil {
		log.Printf("[VES] smcRoundTrip issue")
		return err
	}

	// 0x34 is AuthResult tag
	for {
		if rspTLV.Tag == 0x34 {
			log.Printf("[VES] Received AuthResult from trusted_applet")
			break
		}
	}
	//if rspTLV.Tag != 0x34 {
	//	return fmt.Errorf("expected AuthResult (0x34), got 0x%x", rspTLV.Tag)
	//}

	var result util.AuthResult
	rdr = util.CreateDeserializer(rspTLV.Value)
	if err := util.Deserialize(rdr, &result); err != nil {
		return fmt.Errorf("deserialize auth result: %w", err)
	}

	if result.OK != 1 {
		return fmt.Errorf("applet rejected VES authentication")
	}

	log.Printf("[VES] Authenticated by applet")
	return nil
}

func buildVESAuthMessage(nonce [32]byte) []byte {
	h := sha256.New()
	h.Write(nonce[:])
	h.Write([]byte("GoTEE-VES-auth-v1")) // context string to bind signature usage
	return h.Sum(nil)
}

func ValidationService(reqCh chan<- smcRequest, done <-chan bool, wg *sync.WaitGroup) {
	defer wg.Done()
	fmt.Printf("[VES] Booting!\n")

	// Attestation logic:
	if err := mutualAttestationVES(reqCh); err != nil {
		log.Printf("[VES] Mutual attestation failed: %v", err)
		return
	}

	log.Printf("[VES] Mutual attestation succeeded, proceeding with validation logic")

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

	// for {
	// 	cmd := WaitAppletCommand(done)
	// 	if cmd == nil {
	// 		break
	// 	}

	// 	log.Printf("[VES] Received Applet Command TAG: %04x, Value: %x\n", cmd.Tag, cmd.Value)
	// }

	fmt.Printf("[VES] Exiting!\n")
}
