#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>

#define ETHERNET_HEADER_LEN 14

typedef struct {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;
} ethernet_header_t;

typedef struct {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} ipv4_header_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} tcp_header_t;

int packet_count = 0;

void print_ip(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    printf("%s", inet_ntoa(addr));
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    packet_count++;

    printf("Packet #%d | Length: %d bytes", packet_count, header->caplen);

    if (header->caplen < ETHERNET_HEADER_LEN) {
        printf("\n");
        return;
    }

    ethernet_header_t *eth = (ethernet_header_t *)packet;
    uint16_t ethertype = ntohs(eth->ethertype);

    if (ethertype == 0x0806) {
        printf(" | ARP\n");
        return;
    }

    if (ethertype != 0x0800) {
        printf(" | EtherType: 0x%04x\n", ethertype);
        return;
    }

    if (header->caplen < ETHERNET_HEADER_LEN + 20) {
        printf(" | IPv4 (too short)\n");
        return;
    }

    ipv4_header_t *ip = (ipv4_header_t *)(packet + ETHERNET_HEADER_LEN);
    uint8_t ihl = (ip->version_ihl & 0x0F) * 4;

    printf(" | ");
    print_ip(ip->src_ip);
    printf(" -> ");
    print_ip(ip->dst_ip);

    if (ip->protocol == 1) {
        printf(" | ICMP\n");
        return;
    }

    if (ip->protocol == 17) {
        // UDP
        const u_char *udp = packet + ETHERNET_HEADER_LEN + ihl;
        uint16_t src_port = ntohs(*(uint16_t *)udp);
        uint16_t dst_port = ntohs(*(uint16_t *)(udp + 2));
        printf(" | UDP %d -> %d", src_port, dst_port);
        if (src_port == 4840 || dst_port == 4840) printf(" [OPC-UA]");
        printf("\n");
        return;
    }

    if (ip->protocol != 6) {
        printf(" | Proto: %d\n", ip->protocol);
        return;
    }

    if (header->caplen < ETHERNET_HEADER_LEN + ihl + 20) {
        printf(" | TCP (too short)\n");
        return;
    }

    tcp_header_t *tcp    = (tcp_header_t *)(packet + ETHERNET_HEADER_LEN + ihl);
    uint16_t src_port    = ntohs(tcp->src_port);
    uint16_t dst_port    = ntohs(tcp->dst_port);
    uint8_t  tcp_hdr_len = ((tcp->data_offset >> 4) & 0x0F) * 4;
    int payload_len      = header->caplen - ETHERNET_HEADER_LEN - ihl - tcp_hdr_len;

    printf(" | TCP %d -> %d | Payload: %d bytes", src_port, dst_port, payload_len);

    if (src_port == 502  || dst_port == 502)  printf(" [MODBUS]");
    if (src_port == 4840 || dst_port == 4840) printf(" [OPC-UA]");

    printf("\n");
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live("enp0s3", 65535, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    printf("[*] Capture started on enp0s3...\n");
    pcap_loop(handle, 30, packet_handler, NULL);

    pcap_close(handle);
    printf("[*] Capture complete.\n");
    return 0;
}
