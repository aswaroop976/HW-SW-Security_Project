// Copyright (c) The GoTEE authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package gotee

import (
	"errors"
	"log"
	"math/rand"
	"sync"

	"github.com/usbarmory/GoTEE-example/util"
	"github.com/usbarmory/GoTEE/monitor"
)

// TrustZone Watchdog interval (in ms) to force Non-Secure to Secure World
// switching.
const (
	watchdogTimeout         = 10000
	watchdogWarningInterval = 2000
)

var nsBoot bool

var appletCmdCh chan *util.TLV
var appletRspCh chan *util.TLV
var appletToOSCh chan *util.TLV
var osRespondCh chan *util.TLV
var appletRspLenCh chan uint16
var appletToOSLenCh chan uint16

func GoTEE() (err error) {
	var wg sync.WaitGroup
	var ta *monitor.ExecCtx
	var os *monitor.ExecCtx

	if ta, err = loadApplet(false); err != nil {
		return
	}

	if os, err = loadNormalWorld(false); err != nil {
		return
	}

	appletCmdCh = make(chan *util.TLV, 10)
	appletRspCh = make(chan *util.TLV, 10)
	appletToOSCh = make(chan *util.TLV, 10)
	appletRspLenCh = make(chan uint16, 10)
	appletToOSLenCh = make(chan uint16, 10)

	nsBoot = true

	// test concurrent execution of:
	//   Secure    World PL1 (system/monitor mode) - secure OS (this program)
	//   Secure    World PL0 (user mode)           - trusted applet
	//   NonSecure World PL1                       - main OS
	wg.Add(2)
	go run(ta, &wg)
	go run(os, &wg)

	log.Printf("SM waiting for applet and kernel")
	wg.Wait()
	log.Printf("All goroutines finished.")
	return
}

func Linux(device string) (err error) {
	var os *monitor.ExecCtx

	if nsBoot {
		return errors.New("previous Non-secure kernel run detected, reboot first to launch Linux")
	}

	if os, err = loadLinux(device); err != nil {
		return
	}

	log.Printf("SM enabling TrustZone Watchdog")
	enableTrustZoneWatchdog()

	log.Printf("SM launching Linux")
	run(os, nil)

	return
}

func fault(ctx *monitor.ExecCtx, faultPercentage float64) {
	if n := rand.Float64() * 100; n >= faultPercentage {
		return
	}

	log.Printf("!! injecting register fault !!")
	ctx.R0 += 1
}

func Lockstep(faultPercentage float64) (err error) {
	var once sync.Once
	var ta *monitor.ExecCtx

	if ta, err = loadApplet(true); err != nil {
		return
	}

	defer run(ta, nil)

	if faultPercentage <= 0 {
		return
	}

	primaryHandler := ta.Handler

	ta.Handler = func(ctx *monitor.ExecCtx) error {
		once.Do(func() {
			ta.Shadow.Handler = func(ctx *monitor.ExecCtx) error {
				fault(ctx, faultPercentage)
				return nil
			}
		})

		return primaryHandler(ctx)
	}

	return
}
