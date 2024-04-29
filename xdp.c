//go: build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct packet
{
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 seq;
    __u32 ack;
    __u16 flags;
    __u16 window;
    __u64 timestamp;
};

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} packets SEC(".maps");

const struct packet *unused __attribute__((unused));

static __always_inline int parse_packets(struct xdp_md *ctx, struct packet *pkt) {

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        return 0;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return 0;
    }
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
    {
        return 0;
    }


    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
    {
        return 0;
    }

    pkt->src_ip = (__u32)(ip->saddr);
    pkt->dst_ip = (__u32)(ip->daddr);
    pkt->src_port = (__u16)(bpf_ntohs(tcp->source));
    pkt->dst_port = (__u16)(bpf_ntohs(tcp->dest));
    pkt->seq = (__u32)(bpf_ntohl(tcp->seq));
    pkt->ack = (__u32)(bpf_ntohl(tcp->ack_seq));
    pkt->window = (__u16)(bpf_ntohs(tcp->window));
    pkt->timestamp = (__u64)(bpf_ktime_get_ns());

    return 1;
}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx)
{
    struct packet *pkt;

    pkt = bpf_ringbuf_reserve(&packets, sizeof(struct packet), 0);
    if (!pkt)
    {
        return XDP_PASS;
    }

    if (!parse_packets(ctx, pkt))
    {
        bpf_ringbuf_discard(pkt, 0);
        return XDP_PASS;
    }

    bpf_ringbuf_submit(pkt, 0);

    return XDP_PASS;
}