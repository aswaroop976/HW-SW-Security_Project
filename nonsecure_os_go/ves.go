package main

import (
	"fmt"
	"sync"

	"github.com/usbarmory/GoTEE-example/util"
)

func ValidationService(reqCh chan<- smcRequest, wg *sync.WaitGroup) {
	defer wg.Done()

	var rspTLV *util.TLV
	r := smcRequest{
		tag:        0x31,
		embed:      false,
		value:      []byte("hello2"),
		expect_rsp: true,
		rsp:        &rspTLV,
		done:       make(chan struct{}),
	}
	fmt.Printf("Validation Service sending request to SMC serializer.\n")

	reqCh <- r // secure monitor call
	<-r.done   // block until SMC completed
	fmt.Printf("Validation Service Exiting\n")
}
