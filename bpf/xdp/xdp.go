package xdp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdp ../kernel/xdp.c


import (
	"C"
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type XdpPacket struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint32
	DstPort uint32
	Seq     uint32
	Ack     uint32
	Flags   uint32
	Window  uint32
}

type Xdp struct {
	stopper chan os.Signal
	iface *net.Interface
	buffer chan XdpPacket
}

func NewXdp(stopper chan os.Signal, iface *net.Interface) *Xdp {

	return &Xdp{
		stopper: stopper,
		iface: iface,
		buffer: make(chan XdpPacket, 1024),
	}
}

func (x *Xdp) Run() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	log.Printf("Load Object")
	// Load pre-compiled programs into the kernel.
	objs := xdpObjects{}
	if err := loadXdpObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: x.iface.Index,
	})
	log.Printf("XDP Attached")
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()
	log.Printf("Attached XDP program to iface %q (index %d)", x.iface.Name, x.iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	rd, err := ringbuf.NewReader(objs.Packets)
	if err != nil {
		log.Fatalf("creating ring buffer reader: %s", err)
	}
	defer rd.Close()

	go func() {
		<-x.stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ring buffer reader: %s", err)
		}
	}()

	log.Println("Waiting for packets...")

	var packet XdpPacket
	
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting...")
				close(x.buffer)
				return
			}
			log.Printf("reading from ring buffer: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &packet); err != nil {
			log.Printf("decoding ring buffer record: %s", err)
			continue
		}

		x.buffer <- packet
	}
}

func (x *Xdp) GetPacket() (XdpPacket, error) {
	if x.isBufferClosed() {
		return XdpPacket{}, errors.New("buffer is closed")
	}
	return <-x.buffer, nil
}

func (x *Xdp) isBufferClosed() bool {
	_, ok := <-x.buffer
	return !ok
}