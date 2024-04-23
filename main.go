package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Removing memlock: ", err)
	}

	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects: ", err)
	}
	defer objs.Close()

	ifname := "ens18"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program: objs.CountPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Attaching XDP: ", err)
	}
	defer link.Close()

	log.Printf("Counting incoming packets on %s..\n", ifname)

	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)

	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <- tick:
			var count uint64
			err := objs.PktCount.Lookup(uint32(0), &count)
			if err != nil {
				log.Fatal("Map lookup: ", err)
			}
			log.Printf("Received %d packets\n", count)
		case <- stop:
			log.Print("Received signal, exiting...")
			return
		}
	}
}
