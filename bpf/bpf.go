package bpf

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/kubespect/agent/bpf/xdp"
)

type Bpf struct {
	Xdp *xdp.Xdp

	stopper chan os.Signal
}

func NewBpf(ifaceName string) *Bpf {

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	// Look up the network interface by name.
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	return &Bpf{
		stopper: stopper,
		Xdp:     xdp.NewXdp(stopper, iface),
	}
}

func (b *Bpf) Run() {
	go b.Xdp.Run()

	for {
		packet, err := b.Xdp.GetPacket()
		if err != nil {
			log.Fatalf("get packet: %s", err)
			break
		}
		if packet == (xdp.XdpPacket{}) {
			log.Fatalf("get packet: packet is empty")
			break
		}
		log.Printf("%+v", packet)
	}
}
