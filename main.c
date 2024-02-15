#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>

#define ETHERNET_HEADER_LEN  14
#define MAX_ASSETS           256
#define DCP_FRAME_ID         0xFEFF
#define DCP_SERVICE_IDENTIFY 0x05
#define DCP_RESPONSE         0x01
#define INTERFACE            "enp0s3"

// Ethernet header
typedef struct {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;
} ethernet_header_t;

// ARP header
typedef struct {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t  hw_len;
    uint8_t  proto_len;
    uint16_t operation;
    uint8_t  sender_mac[6];
    uint8_t  sender_ip[4];
    uint8_t  target_mac[6];
    uint8_t  target_ip[4];
} arp_header_t;

// Asset record
typedef struct {
    uint8_t  mac[6];
    char     mac_str[18];
    char     protocol[32];
    char     chassis_id[64];
    char     system_name[64];
    char     system_desc[256];
    char     mgmt_ip[16];
    char     dcp_station_name[64];
    char     dcp_vendor[64];
    char     dcp_ip[16];
    char     arp_ip[16];
    char     oui_vendor[64];
    uint16_t dcp_vendor_id;
    uint16_t dcp_device_id;
    int      packet_count;
    int      active;
} asset_t;

asset_t asset_table[MAX_ASSETS];
int     asset_count = 0;

// OUI table
typedef struct {
    uint8_t     oui[3];
    const char *vendor;
} oui_entry_t;

static const oui_entry_t oui_table[] = {
    {{0x00, 0x0E, 0xCF}, "Profibus Nutzerorg."},
    {{0x00, 0x1B, 0x1B}, "Siemens"},
    {{0x28, 0x63, 0x36}, "Siemens"},
    {{0x38, 0x4B, 0x24}, "Siemens"},
    {{0x3C, 0x97, 0x0E}, "Siemens"},
    {{0x54, 0x7F, 0xEE}, "Siemens"},
    {{0x80, 0x2A, 0xA8}, "Siemens"},
    {{0x8C, 0xF3, 0x19}, "Siemens"},
    {{0xB8, 0x75, 0xD3}, "Siemens"},
    {{0xD8, 0x44, 0x89}, "Siemens"},
    {{0x7C, 0xF1, 0x7E}, "Siemens"},
    {{0xA8, 0x6E, 0x84}, "TP-Link"},
    {{0xA8, 0x41, 0xF4}, "HP"},
    {{0xD8, 0x43, 0xAE}, "MSI"},
    {{0x00, 0x0C, 0x29}, "VMware"},
    {{0x00, 0x50, 0x56}, "VMware"},
    {{0x00, 0x1A, 0xA0}, "Rockwell"},
    {{0x00, 0x00, 0xBC}, "Rockwell"},
    {{0x00, 0x09, 0x1A}, "Rockwell"},
    {{0x00, 0x00, 0x5E}, "Beckhoff"},
    {{0x00, 0x01, 0x05}, "Schneider"},
    {{0x00, 0x80, 0xF4}, "Schneider"},
};

#define OUI_TABLE_SIZE (sizeof(oui_table) / sizeof(oui_table[0]))

const char *lookup_oui(const uint8_t *mac) {
    for (int i = 0; i < (int)OUI_TABLE_SIZE; i++) {
        if (memcmp(oui_table[i].oui, mac, 3) == 0)
            return oui_table[i].vendor;
    }
    return NULL;
}

void mac_to_str(const uint8_t *mac, char *buf) {
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void trim_at_double_space(char *str) {
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] == ' ' && str[i+1] == ' ') {
            str[i] = '\0';
            return;
        }
    }
}

asset_t *find_or_create_asset(const uint8_t *mac, int *is_new) {
    for (int i = 0; i < asset_count; i++) {
        if (memcmp(asset_table[i].mac, mac, 6) == 0) {
            if (is_new) *is_new = 0;
            return &asset_table[i];
        }
    }
    if (asset_count >= MAX_ASSETS) return NULL;

    asset_t *a = &asset_table[asset_count++];
    memset(a, 0, sizeof(asset_t));
    memcpy(a->mac, mac, 6);
    mac_to_str(mac, a->mac_str);
    a->active = 1;

    const char *vendor = lookup_oui(mac);
    if (vendor)
        strncpy(a->oui_vendor, vendor, sizeof(a->oui_vendor) - 1);

    if (is_new) *is_new = 1;
    return a;
}

// Return best available display name
const char *display_name(asset_t *a) {
    if (a->dcp_station_name[0]) return a->dcp_station_name;
    if (a->system_name[0])      return a->system_name;
    if (a->chassis_id[0])       return a->chassis_id;
    return a->mac_str;
}

// Return best available vendor
const char *display_vendor(asset_t *a) {
    if (a->dcp_vendor[0])  return a->dcp_vendor;
    if (a->oui_vendor[0])  return a->oui_vendor;
    return "-";
}

// Return best available IP
const char *display_ip(asset_t *a) {
    if (a->dcp_ip[0])   return a->dcp_ip;
    if (a->mgmt_ip[0])  return a->mgmt_ip;
    if (a->arp_ip[0])   return a->arp_ip;
    return "-";
}

// Write asset table to CSV file
void write_csv(const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        perror("fopen");
        return;
    }

    fprintf(f, "MAC Address,Protocol,Device Name,Vendor,IP Address,Packets,Description\n");

    for (int i = 0; i < asset_count; i++) {
        asset_t *a = &asset_table[i];
        fprintf(f, "%s,%s,%s,%s,%s,%d,\"%s\"\n",
                a->mac_str,
                a->protocol[0]  ? a->protocol      : "-",
                display_name(a),
                display_vendor(a),
                display_ip(a),
                a->packet_count,
                a->system_desc[0] ? a->system_desc : "-");
    }

    fclose(f);
    printf("[*] Asset table written to %s\n", filename);
}

// Print final asset inventory table
void print_asset_table(const char *csv_file) {
    printf("\n");
    printf("╔═══════════════════╦══════════════════╦════════════════════╦══════════════════╦═════════════════╦═════════╗\n");
    printf("║ %-17s ║ %-16s ║ %-18s ║ %-16s ║ %-15s ║ %-7s ║\n",
           "MAC Address", "Protocol", "Device Name", "Vendor", "IP Address", "Packets");
    printf("╠═══════════════════╬══════════════════╬════════════════════╬══════════════════╬═════════════════╬═════════╣\n");

    for (int i = 0; i < asset_count; i++) {
        asset_t *a = &asset_table[i];

        char name_buf[19];
        snprintf(name_buf, sizeof(name_buf), "%s", display_name(a));

        char vendor_buf[17];
        snprintf(vendor_buf, sizeof(vendor_buf), "%s", display_vendor(a));

        printf("║ %-17s ║ %-16s ║ %-18s ║ %-16s ║ %-15s ║ %-7d ║\n",
               a->mac_str,
               a->protocol[0] ? a->protocol : "-",
               name_buf,
               vendor_buf,
               display_ip(a),
               a->packet_count);

        if (a->system_desc[0])
            printf("║   Desc : %-109s║\n", a->system_desc);

        if (a->dcp_vendor_id || a->dcp_device_id)
            printf("║   DCP  : VendorID=0x%04x  DeviceID=0x%04x%-67s║\n",
                   a->dcp_vendor_id, a->dcp_device_id, "");

        printf("╠═══════════════════╬══════════════════╬════════════════════╬══════════════════╬═════════════════╬═════════╣\n");
    }

    printf("╚═══════════════════╩══════════════════╩════════════════════╩══════════════════╩═════════════════╩═════════╝\n");
    printf("\n[*] %d unique asset(s) observed.\n", asset_count);

    if (csv_file)
        write_csv(csv_file);
}

// Signal handler
pcap_t *global_handle = NULL;
char    csv_output[256] = {0};

void handle_sigint(int sig) {
    (void)sig;
    printf("\n[*] Stopping capture...");
    if (global_handle) pcap_breakloop(global_handle);
}

// Send DCP Identify All multicast
void send_dcp_identify_all() {
    uint8_t dst_mac[6]    = {0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00};
    uint8_t dcp_payload[] = {
        0xFE, 0xFF, 0x05, 0x00,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x04,
        0xFF, 0xFF, 0x00, 0x00
    };

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); return; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX"); close(sock); return;
    }
    int ifindex = ifr.ifr_ifindex;

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR"); close(sock); return;
    }

    uint8_t frame[64];
    memset(frame, 0, sizeof(frame));
    memcpy(frame,     dst_mac, 6);
    memcpy(frame + 6, ifr.ifr_hwaddr.sa_data, 6);
    frame[12] = 0x88; frame[13] = 0x92;
    memcpy(frame + 14, dcp_payload, sizeof(dcp_payload));

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family   = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex  = ifindex;
    addr.sll_halen    = 6;
    memcpy(addr.sll_addr, dst_mac, 6);

    if (sendto(sock, frame, 14 + sizeof(dcp_payload), 0,
               (struct sockaddr *)&addr, sizeof(addr)) < 0)
        perror("sendto");
    else
        printf("[*] DCP Identify All sent - waiting for responses...\n");

    close(sock);
}

// Parse ARP frame - extract sender MAC/IP and update asset table
void parse_arp(const u_char *payload, int payload_len) {
    if (payload_len < (int)sizeof(arp_header_t)) return;

    arp_header_t *arp = (arp_header_t *)payload;

    // only process IPv4 over Ethernet
    if (ntohs(arp->hw_type)    != 0x0001) return;
    if (ntohs(arp->proto_type) != 0x0800) return;
    if (arp->hw_len   != 6) return;
    if (arp->proto_len != 4) return;

    // skip all-zero sender MACs (gratuitous ARP edge case)
    uint8_t zero_mac[6] = {0};
    if (memcmp(arp->sender_mac, zero_mac, 6) == 0) return;

    int is_new = 0;
    asset_t *a = find_or_create_asset(arp->sender_mac, &is_new);
    if (!a) return;

    // format sender IP
    char ip_str[16];
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
             arp->sender_ip[0], arp->sender_ip[1],
             arp->sender_ip[2], arp->sender_ip[3]);

    // only update if we didn't already have an IP
    int learned_ip = 0;
    if (!a->arp_ip[0] && !a->mgmt_ip[0] && !a->dcp_ip[0]) {
        strncpy(a->arp_ip, ip_str, sizeof(a->arp_ip) - 1);
        learned_ip = 1;
    }

    a->packet_count++;

    uint16_t op = ntohs(arp->operation);

    if (is_new || learned_ip) {
        printf("[+] ARP      | %-17s | %-20s | %-10s | %s (%s)\n",
               a->mac_str,
               display_name(a),
               display_vendor(a),
               ip_str,
               op == 1 ? "request" : "reply");
    }
}

// Parse LLDP frame
void parse_lldp(const u_char *payload, int payload_len, const uint8_t *src_mac) {
    int is_new = 0;
    asset_t *a = find_or_create_asset(src_mac, &is_new);
    if (!a) return;

    strncpy(a->protocol, "LLDP", sizeof(a->protocol) - 1);
    a->packet_count++;

    int offset = 0;

    while (offset + 2 <= payload_len) {
        uint16_t tlv_header = (payload[offset] << 8) | payload[offset + 1];
        uint8_t  tlv_type   = (tlv_header >> 9) & 0x7F;
        uint16_t tlv_len    = tlv_header & 0x01FF;
        offset += 2;

        if (tlv_type == 0) break;
        if (offset + tlv_len > payload_len) break;

        const u_char *tlv_value = payload + offset;

        switch (tlv_type) {
            case 1: {
                if (tlv_len > 1) {
                    int len = tlv_len - 1;
                    if (len > (int)sizeof(a->chassis_id) - 1)
                        len = sizeof(a->chassis_id) - 1;
                    memcpy(a->chassis_id, tlv_value + 1, len);
                    a->chassis_id[len] = '\0';
                    trim_at_double_space(a->chassis_id);
                }
                break;
            }
            case 5: {
                int len = tlv_len < (int)sizeof(a->system_name) - 1
                          ? tlv_len : (int)sizeof(a->system_name) - 1;
                memcpy(a->system_name, tlv_value, len);
                a->system_name[len] = '\0';
                break;
            }
            case 6: {
                int len = tlv_len < (int)sizeof(a->system_desc) - 1
                          ? tlv_len : (int)sizeof(a->system_desc) - 1;
                memcpy(a->system_desc, tlv_value, len);
                a->system_desc[len] = '\0';
                break;
            }
            case 8: {
                if (tlv_len >= 6 && tlv_value[1] == 1) {
                    snprintf(a->mgmt_ip, sizeof(a->mgmt_ip), "%d.%d.%d.%d",
                             tlv_value[2], tlv_value[3],
                             tlv_value[4], tlv_value[5]);
                }
                break;
            }
            default:
                break;
        }

        offset += tlv_len;
    }

    if (is_new)
        printf("[+] LLDP     | %-17s | %-20s | %-10s | %s\n",
               a->mac_str,
               display_name(a),
               display_vendor(a),
               a->mgmt_ip[0] ? a->mgmt_ip : "no mgmt IP");
}

// Parse PROFINET DCP blocks
void parse_profinet_dcp(const u_char *payload, int payload_len, const uint8_t *src_mac) {
    if (payload_len < 12) return;

    uint8_t  service_id   = payload[2];
    uint8_t  service_type = payload[3];
    uint16_t dcp_length   = (payload[10] << 8) | payload[11];

    if (service_id != DCP_SERVICE_IDENTIFY || service_type != DCP_RESPONSE) return;

    int is_new = 0;
    asset_t *a = find_or_create_asset(src_mac, &is_new);
    if (!a) return;

    strncpy(a->protocol, "PROFINET/DCP", sizeof(a->protocol) - 1);
    a->packet_count++;

    int offset = 12;
    int end    = 12 + dcp_length;
    if (end > payload_len) end = payload_len;

    while (offset + 4 <= end) {
        uint8_t  option    = payload[offset];
        uint8_t  suboption = payload[offset + 1];
        uint16_t block_len = (payload[offset + 2] << 8) | payload[offset + 3];
        offset += 4;

        if (offset + block_len > end) break;

        const u_char *block_data = payload + offset;

        if (option == 0x01 && suboption == 0x02 && block_len >= 14) {
            snprintf(a->dcp_ip, sizeof(a->dcp_ip), "%d.%d.%d.%d",
                     block_data[2], block_data[3],
                     block_data[4], block_data[5]);
        }
        else if (option == 0x02 && suboption == 0x01 && block_len > 0) {
            int len = block_len < (int)sizeof(a->dcp_vendor) - 1
                      ? block_len : (int)sizeof(a->dcp_vendor) - 1;
            memcpy(a->dcp_vendor, block_data, len);
            a->dcp_vendor[len] = '\0';
        }
        else if (option == 0x02 && suboption == 0x02 && block_len > 0) {
            int len = block_len < (int)sizeof(a->dcp_station_name) - 1
                      ? block_len : (int)sizeof(a->dcp_station_name) - 1;
            memcpy(a->dcp_station_name, block_data, len);
            a->dcp_station_name[len] = '\0';
        }
        else if (option == 0x02 && suboption == 0x03 && block_len >= 4) {
            a->dcp_vendor_id = (block_data[0] << 8) | block_data[1];
            a->dcp_device_id = (block_data[2] << 8) | block_data[3];
        }

        offset += block_len;
        if (block_len % 2 != 0) offset++;
    }

    printf("[+] DCP      | %-17s | %-20s | %-10s | %s\n",
           a->mac_str,
           display_name(a),
           display_vendor(a),
           a->dcp_ip[0] ? a->dcp_ip : "no IP in DCP");
}

// Parse PROFINET RT - dispatch DCP or count cyclic
void parse_profinet(const u_char *payload, int payload_len, const uint8_t *src_mac) {
    if (payload_len < 2) return;

    uint16_t frame_id = (payload[0] << 8) | payload[1];

    if (frame_id == DCP_FRAME_ID) {
        parse_profinet_dcp(payload, payload_len, src_mac);
        return;
    }

    int is_new = 0;
    asset_t *a = find_or_create_asset(src_mac, &is_new);
    if (!a) return;

    if (!a->protocol[0] || strcmp(a->protocol, "PROFINET") == 0)
        strncpy(a->protocol, "PROFINET", sizeof(a->protocol) - 1);

    a->packet_count++;

    if (is_new)
        printf("[+] PROFINET | %-17s | Frame ID: 0x%04x | Vendor: %s\n",
               a->mac_str, frame_id,
               a->oui_vendor[0] ? a->oui_vendor : "Unknown");
}

// Main packet callback
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    if (header->caplen < ETHERNET_HEADER_LEN) return;

    ethernet_header_t *eth = (ethernet_header_t *)packet;
    uint16_t ethertype     = ntohs(eth->ethertype);
    const u_char *payload  = packet + ETHERNET_HEADER_LEN;
    int payload_len        = header->caplen - ETHERNET_HEADER_LEN;

    switch (ethertype) {
        case 0x0806:
            parse_arp(payload, payload_len);
            break;
        case 0x88CC:
            parse_lldp(payload, payload_len, eth->src_mac);
            break;
        case 0x8892:
        case 0x8899:
            parse_profinet(payload, payload_len, eth->src_mac);
            break;
        default:
            break;
    }
}

// Print usage
void usage(const char *prog) {
    printf("Usage: %s [-o output.csv]\n", prog);
    printf("  -o <file>  Write asset table to CSV file on exit\n");
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            strncpy(csv_output, argv[i+1], sizeof(csv_output) - 1);
            i++;
        } else if (strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    signal(SIGINT, handle_sigint);

    global_handle = pcap_open_live(INTERFACE, 65535, 1, 1000, errbuf);
    if (global_handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    printf("[*] OT Asset Fingerprinter - listening on %s\n", INTERFACE);
    printf("[*] Protocols: ARP + LLDP + PROFINET RT + PROFINET DCP\n");
    if (csv_output[0])
        printf("[*] Output CSV: %s\n", csv_output);
    printf("[*] Press Ctrl+C to stop and print asset table\n\n");

    send_dcp_identify_all();

    pcap_loop(global_handle, -1, packet_handler, NULL);

    pcap_close(global_handle);
    print_asset_table(csv_output[0] ? csv_output : NULL);

    return 0;
}
