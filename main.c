#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>

int packet_count = 0;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    packet_count++;
    printf("Packet #%d | Time: %ld | Length: %d bytes\n",
           packet_count,
           header->ts.tv_sec,
           header->caplen);
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
    pcap_loop(handle, 10, packet_handler, NULL);

    pcap_close(handle);
    printf("[*] Capture complete.\n");
    return 0;
}
