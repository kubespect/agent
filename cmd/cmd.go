package cmd

import (
	"github.com/kubespect/agent/bpf"
	"github.com/kubespect/agent/internal/grpc"
)

type Cmd struct {
	ifaceName string
}

func NewCmd(ifaceName string) *Cmd {
	return &Cmd{ifaceName: ifaceName}
}

func (c *Cmd) Run() {
	
	bpf := bpf.NewBpf(c.ifaceName)
	bpf.Run()

	grpc := grpc.NewGrpcClient()
	grpc.SendXdpPackets(bpf.Xdp.Packets)
}