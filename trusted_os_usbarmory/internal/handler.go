// Copyright (c) The GoTEE authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package gotee

import (
	"errors"
	"fmt"
	"log"
	"unsafe"

	"github.com/usbarmory/tamago/arm"
	"github.com/usbarmory/tamago/soc/nxp/imx6ul"

	"github.com/usbarmory/GoTEE/monitor"
	"github.com/usbarmory/GoTEE/syscall"

	"github.com/usbarmory/GoTEE-example/util"
)

var Console *util.Console

func goHandler(ctx *monitor.ExecCtx) (err error) {
	if ctx.ExceptionVector == arm.DATA_ABORT && ctx.NonSecure() {
		log.Printf("SM trapped Non-secure data abort pc:%#.8x", ctx.R15-8)

		log.Print(ctx)
		ctx.Stop()

		return
	}

	if ctx.ExceptionVector != arm.SUPERVISOR {
		return fmt.Errorf("exception %x", ctx.ExceptionVector)
	}

	switch ctx.A0() {
	case 50:
		// log.Printf("Received applet-command syscall.")
		tlv_addr := uintptr(ctx.A1())
		tlv := (*util.TLV)(unsafe.Pointer(tlv_addr))
		appletCmdCh <- tlv

	case 51:
		// log.Printf("Received applet-response-check syscall.")
		check_addr := uintptr(ctx.A1())
		check := (*uint16)(unsafe.Pointer(check_addr))
		if len(appletRspCh) > 0 && len(appletRspLenCh) > 0 {
			*check = <-appletRspLenCh
		} else {
			*check = 0
		}

	case 52:
		// log.Printf("Received applet-response-get syscall.")
		ns_tlv_addr := uintptr(ctx.A1())
		ns_tlv := (*util.TLV)(unsafe.Pointer(ns_tlv_addr))
		s_tlv := <-appletRspCh

		// log.Printf("Copying...")
		ns_tlv.Tag = s_tlv.Tag
		ns_tlv.Length = s_tlv.Length
		copy(ns_tlv.Value, s_tlv.Value)

		// log.Printf("SYSCALL received message... TAG: %d, LENGTH: %d, VALUE:%s", s_tlv.Tag, s_tlv.Length, string(s_tlv.Value))
		// log.Printf("copied message... TAG: %d, LENGTH: %d, VALUE:%s", ns_tlv.Tag, ns_tlv.Length, string(ns_tlv.Value))

	case 53:
		// log.Printf("Received applet-response syscall.")
		tlv_addr := uintptr(ctx.A1())
		tlv := (*util.TLV)(unsafe.Pointer(tlv_addr))
		osRespondCh <- tlv

	case 54:
		// log.Printf("Received applet-command-check syscall.")
		check_addr := uintptr(ctx.A1())
		check := (*uint16)(unsafe.Pointer(check_addr))
		if len(appletToOSCh) > 0 && len(appletToOSLenCh) > 0 {
			*check = <-appletToOSLenCh
		} else {
			*check = 0
		}

	case 55:
		// log.Printf("Received applet-command-get syscall.")
		ns_tlv_addr := uintptr(ctx.A1())
		ns_tlv := (*util.TLV)(unsafe.Pointer(ns_tlv_addr))
		s_tlv := <-appletToOSCh

		// log.Printf("Copying...")
		ns_tlv.Tag = s_tlv.Tag
		ns_tlv.Length = s_tlv.Length
		copy(ns_tlv.Value, s_tlv.Value)

	case syscall.SYS_WRITE:
		// Override write syscall to avoid interleaved logs and to log
		// simultaneously to remote terminal and serial console.
		if Console != nil {
			util.BufferedTermLog(byte(ctx.A1()), !ctx.NonSecure(), Console.Term)
		} else {
			util.BufferedStdoutLog(byte(ctx.A1()), !ctx.NonSecure())
		}
	case syscall.SYS_EXIT:
		// support exit syscall on both security states
		ctx.Stop()
	default:
		if ctx.NonSecure() {
			log.Print(ctx)
			return errors.New("unexpected monitor call")
		} else {
			return monitor.SecureHandler(ctx)
		}
	}

	return
}

func linuxHandler(ctx *monitor.ExecCtx) (err error) {
	if !ctx.NonSecure() {
		return errors.New("unexpected processor mode")
	}

	switch ctx.ExceptionVector {
	case arm.FIQ:
		switch imx6ul.GIC.GetInterrupt(true) {
		case imx6ul.TZ_WDOG.IRQ:
			imx6ul.TZ_WDOG.Service(watchdogTimeout)
			log.Printf("SM serviced TrustZone Watchdog")
		}

		return
	case arm.SUPERVISOR:
		return monitor.NonSecureHandler(ctx)
	default:
		return fmt.Errorf("unhandled exception %x", ctx.ExceptionVector)
	}

	return
}
