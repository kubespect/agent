package grpc

import (
	"log"
	"context"

	"google.golang.org/grpc"
	pb "github.com/kubespect/agent/protobuf/xdp"
	"github.com/kubespect/agent/bpf/xdp"
)

type GrpcClient struct {
	conn *grpc.ClientConn
	client pb.XDPClient
}

func NewGrpcClient() *GrpcClient {
	conn, err := grpc.Dial("192.168.219.103:9090", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	// defer conn.Close()

	xdpClient := pb.NewXDPClient(conn)
	return &GrpcClient{conn, xdpClient}
}

func (c *GrpcClient) SendXdpPackets(packets chan xdp.XdpPacket) error {

	// send XDP data to server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := c.client.XDPStream(ctx)
	if err != nil {
		log.Fatalf("open stream error: %v", err)
		return err
	}

	packet := <-packets
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