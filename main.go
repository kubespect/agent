package main

import (
	"os"
	"log"
	"github.com/kubespect/agent/bpf"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <interface>", os.Args[0])
	}
	// Look up the network interface by name.
	ifaceName := os.Args[1]

	bpf := bpf.NewBpf(ifaceName)
	bpf.Run()
}
