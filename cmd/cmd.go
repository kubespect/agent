package cmd

import (
	"github.com/kubespect/agent/bpf"
	"github.com/kubespect/agent/bpf/xdp"
	"github.com/kubespect/agent/internal/grpc"
)

type Cmd struct {
	ifaceName string
}

func NewCmd(ifaceName string) *Cmd {
	return &Cmd{ifaceName: ifaceName}
}

func (c *Cmd) Run() {
	
	xdpChannel := make(chan xdp.XdpPacket, 1024)
	bpf := bpf.NewBpf(c.ifaceName, xdpChannel)
	bpf.Run()

	grpc := grpc.NewGrpcClient(xdpChannel)

	for {
		err := grpc.SendXdpPackets()
		if err != nil {
			break
		}
	}
}