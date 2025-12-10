// Copyright (c) The GoTEE authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package main

import (
	"log"
	"os"
	"runtime"
	"time"
	//"crypto/aes"
	"crypto/ed25519"
	//"crypto/rand"
	"crypto/sha256"
	//"encoding/binary"
	//"encoding/hex"

	"github.com/usbarmory/GoTEE/applet"
	"github.com/usbarmory/GoTEE/syscall"

	"github.com/usbarmory/GoTEE-example/mem"
	"github.com/usbarmory/GoTEE-example/util"
	//"github.com/usbarmory/tamago/soc/nxp/imx6ul"
)

func init() {
	log.SetFlags(log.Ltime)
	log.SetOutput(os.Stdout)

	// yield to monitor (w/ err != nil) on runtime panic
	runtime.Exit = applet.Crash
}

func testRNG(n int) {
	buf := make([]byte, n)
	syscall.GetRandom(buf, uint(n))
	log.Printf("applet obtained %d random bytes from monitor: %x", n, buf)
}

func testRPC() {
	res := ""
	req := "hello"

	log.Printf("applet requests echo via RPC: %s", req)
	err := syscall.Call("RPC.Echo", req, &res)

	if err != nil {
		log.Printf("applet received RPC error: %v", err)
	} else {
		log.Printf("applet received echo via RPC: %s", res)
	}
}

// Quote is a tiny stand-in for an attestation structure.
type Quote struct {
	Nonce    [32]byte
	CodeHash [32]byte
	BuildID  string
}

func testChallenge() {
	var ch util.Challenge
	log.Printf("applet: requesting challenge nonce via RPC")
	err := syscall.Call("RPC.GetChallenge", struct{}{}, &ch)
	if err != nil {
		log.Printf("applet: RPC.GetChallenge error: %v", err)
	}
	log.Printf("applet: received challenge nonce: %x", ch.Nonce[:])
}

// testEd25519 uses randomness from syscall.GetRandom (monitor → hardware RNG)
// and checks sign/verify, like what you’ll use for mutual attestation.
func testEd25519() {
	log.Printf("applet: testing ed25519 (using syscall.GetRandom for entropy)")

	// 1) get 32 bytes of entropy from the monitor (which uses RNGB under the hood)
	seed := make([]byte, ed25519.SeedSize)
	syscall.GetRandom(seed, uint(len(seed)))

	// 2) derive keypair from seed
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	// 3) build a fake "quote"
	var q Quote
	var nonce [32]byte
	syscall.GetRandom(nonce[:], uint(len(nonce)))
	q.Nonce = nonce
	q.CodeHash = sha256.Sum256([]byte("test-applet-code"))
	q.BuildID = "trusted-applet-test-v1"

	// canonical hash of the quote
	h := sha256.New()
	h.Write(q.Nonce[:])
	h.Write(q.CodeHash[:])
	h.Write([]byte(q.BuildID))
	msg := h.Sum(nil)

	sig := ed25519.Sign(priv, msg)
	ok := ed25519.Verify(pub, msg, sig)

	log.Printf("applet: quote nonce    = %x", q.Nonce[:])
	log.Printf("applet: quote codehash = %x", q.CodeHash[:])
	log.Printf("applet: sig            = %x", sig)
	log.Printf("applet: verify(pub, msg, sig) = %v", ok)

	// tamper test
	h2 := sha256.New()
	h2.Write(q.Nonce[:])

	diffHash := sha256.Sum256([]byte("different-code"))
	h2.Write(diffHash[:])

	h2.Write([]byte(q.BuildID))
	msgTampered := h2.Sum(nil)
	ok2 := ed25519.Verify(pub, msgTampered, sig)
	log.Printf("applet: verify(pub, tampered_msg, sig) = %v (should be false)", ok2)
}

func main() {
	log.Printf("%s/%s (%s) • TEE user applet", runtime.GOOS, runtime.GOARCH, runtime.Version())

	// test syscall interface
	testRNG(16)

	// test RPC interface
	testRPC()

	testEd25519()

	testChallenge()

	log.Printf("applet will sleep for 5 seconds")

	ledStatus := util.LEDStatus{
		Name: "blue",
		On:   true,
	}

	// test concurrent execution of applet and supervisor/monitor
	for i := 0; i < 5; i++ {
		syscall.Call("RPC.LED", ledStatus, nil)
		ledStatus.On = !ledStatus.On

		time.Sleep(1 * time.Second)
		log.Printf("applet says %d mississippi", i+1)
	}

	// test memory protection
	mem.TestAccess("applet")

	// this should be unreachable

	// test exception handling
	mem.TestDataAbort("applet")

	// terminate applet
	applet.Exit()
}
