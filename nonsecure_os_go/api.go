// Copyright (c) The GoTEE authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package main

import (
	"github.com/usbarmory/GoTEE-example/util"
	"github.com/usbarmory/GoTEE/syscall"
)

const (
	SYS_WRITE = syscall.SYS_WRITE
	SYS_EXIT  = syscall.SYS_EXIT
)

// defined in api_*.s
func printSecure(byte)
func commandApplet(*util.TLV)
func checkAppletResponse(*uint16)
func getAppletResponse(*util.TLV)
func respondApplet(*util.TLV)
func checkAppletCommand(*uint16)
func getAppletCommand(*util.TLV)
func exit()
