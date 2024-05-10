package grpc

import (
	"context"
	"errors"
	"log"

	"github.com/kubespect/agent/bpf/xdp"
	pb "github.com/kubespect/protobuf/xdp"
	"google.golang.org/grpc"
)

type GrpcClient struct {
	conn *grpc.ClientConn
	client pb.XDPClient
	xdpChannel chan xdp.XdpPacket
}

func NewGrpcClient(xdpChannel chan xdp.XdpPacket) *GrpcClient {
	conn, err := grpc.Dial("192.168.219.103:9090", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	// defer conn.Close()

	xdpClient := pb.NewXDPClient(conn)
	return &GrpcClient{conn, xdpClient, xdpChannel}
}

func (c *GrpcClient) SendXdpPackets() error {

	// send XDP data to server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := c.client.XDPStream(ctx)
	if err != nil {
		log.Fatalf("open stream error: %v", err)
		return err
	}

	packet, err := c.GetPacket()
	if err != nil {
		log.Fatalf("get packet error: %v", err)
	}
	// for packet := range packets {
	if err := stream.Send(c.XdpToProto(packet)); err != nil {
		log.Fatalf("send error: %v", err)
		return err
	}
	// }
	reply, err := stream.CloseAndRecv()
	if err != nil {
		log.Fatalf("close and recv error: %v", err)
		return err
	}
	log.Printf("Response: %s", reply)	
	return nil
}

func (c *GrpcClient) Close() {
	c.conn.Close()
}

func (c *GrpcClient) XdpToProto(packet xdp.XdpPacket) *pb.XDPRequest {
	return &pb.XDPRequest{
		SrcIP:   packet.SrcIP,
		DstIP:   packet.DstIP,
		SrcPort: packet.SrcPort,
		DstPort: packet.DstPort,
		Seq:     packet.Seq,
		Ack:     packet.Ack,
		Flags:   packet.Flags,
		Window:  packet.Window,
	}
}

func (c *GrpcClient) GetPacket() (xdp.XdpPacket, error) {
	packet, ok := <-c.xdpChannel
	if !ok {
		return xdp.XdpPacket{}, errors.New("buffer is closed")
	}
	return packet, nil
}
