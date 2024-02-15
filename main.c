#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>

#define ETHERNET_HEADER_LEN 14
#define MAX_ASSETS          256

// Ethernet header
typedef struct {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;
} ethernet_header_t;

// Asset record
typedef struct {
    uint8_t  mac[6];
    char     mac_str[18];
    char     protocol[32];
    char     chassis_id[64];
    char     system_name[64];
    char     system_desc[256];
    char     mgmt_ip[16];
    int      packet_count;
    int      active;
} asset_t;

asset_t asset_table[MAX_ASSETS];
int     asset_count = 0;

// Convert MAC bytes to string
void mac_to_str(const uint8_t *mac, char *buf) {
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Find existing asset by MAC or create a new one
// Returns 1 if newly created, 0 if already existed
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
    if (is_new) *is_new = 1;
    return a;
}

// Return display name: system name, chassis id, or mac as fallback
const char *display_name(asset_t *a) {
    if (a->system_name[0]) return a->system_name;
    if (a->chassis_id[0])  return a->chassis_id;
    return a->mac_str;
}

// Print final asset inventory table
void print_asset_table() {
    printf("\n");
    printf("╔═══════════════════╦══════════════════╦══════════════════════╦═════════════════╦═════════╗\n");
    printf("║ %-17s ║ %-16s ║ %-20s ║ %-15s ║ %-7s ║\n",
           "MAC Address", "Protocol", "Device Name", "Mgmt IP", "Packets");
    printf("╠═══════════════════╬══════════════════╬══════════════════════╬═════════════════╬═════════╣\n");

    for (int i = 0; i < asset_count; i++) {
        asset_t *a = &asset_table[i];
        printf("║ %-17s ║ %-16s ║ %-20s ║ %-15s ║ %-7d ║\n",
               a->mac_str,
               a->protocol[0]  ? a->protocol  : "-",
               display_name(a),
               a->mgmt_ip[0]   ? a->mgmt_ip   : "-",
               a->packet_count);

        if (a->system_desc[0])
            printf("║   Desc: %-79s║\n", a->system_desc);

        printf("╠═══════════════════╬══════════════════╬══════════════════════╬═════════════════╬═════════╣\n");
    }

    printf("╚═══════════════════╩══════════════════╩══════════════════════╩═════════════════╩═════════╝\n");
    printf("\n[*] %d unique asset(s) observed.\n", asset_count);
}

// Signal handler - print table on Ctrl+C
pcap_t *global_handle = NULL;

void handle_sigint(int sig) {
    (void)sig;
    printf("\n[*] Stopping capture...");
    if (global_handle) pcap_breakloop(global_handle);
}

// Parse LLDP frame and extract device identity
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
                // Chassis ID - subtype byte first, then the value
                // subtype 7 = locally assigned string (common on Siemens devices)
                if (tlv_len > 1) {
                    int len = tlv_len - 1;
                    if (len > (int)sizeof(a->chassis_id) - 1)
                        len = sizeof(a->chassis_id) - 1;
                    memcpy(a->chassis_id, tlv_value + 1, len);
                    a->chassis_id[len] = '\0';
                    // trim trailing spaces
                    for (int j = len - 1; j >= 0 && a->chassis_id[j] == ' '; j--)
                        a->chassis_id[j] = '\0';
                }
                break;
            }
            case 5: {
                // System name
                int len = tlv_len < (int)sizeof(a->system_name) - 1
                          ? tlv_len : (int)sizeof(a->system_name) - 1;
                memcpy(a->system_name, tlv_value, len);
                a->system_name[len] = '\0';
                break;
            }
            case 6: {
                // System description
                int len = tlv_len < (int)sizeof(a->system_desc) - 1
                          ? tlv_len : (int)sizeof(a->system_desc) - 1;
                memcpy(a->system_desc, tlv_value, len);
                a->system_desc[len] = '\0';
                break;
            }
            case 8: {
                // Management IP address (subtype 1 = IPv4)
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

    // Only print on first discovery or when we learn the name
    if (is_new)
        printf("[+] LLDP     | %-17s | %-24s | %s\n",
               a->mac_str,
               display_name(a),
               a->mgmt_ip[0] ? a->mgmt_ip : "no mgmt IP");
}

// Parse PROFINET frame - only announce new devices
void parse_profinet(const u_char *payload, int payload_len, const uint8_t *src_mac) {
    if (payload_len < 2) return;

    int is_new = 0;
    asset_t *a = find_or_create_asset(src_mac, &is_new);
    if (!a) return;

    strncpy(a->protocol, "PROFINET", sizeof(a->protocol) - 1);
    a->packet_count++;

    // Only print on first time we see this device
    if (is_new) {
        uint16_t frame_id = (payload[0] << 8) | payload[1];
        printf("[+] PROFINET | %-17s | Frame ID: 0x%04x (new device)\n",
               a->mac_str, frame_id);
    }
}

// Main packet callback - dispatches to protocol parsers by EtherType
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    if (header->caplen < ETHERNET_HEADER_LEN) return;

    ethernet_header_t *eth = (ethernet_header_t *)packet;
    uint16_t ethertype     = ntohs(eth->ethertype);
    const u_char *payload  = packet + ETHERNET_HEADER_LEN;
    int payload_len        = header->caplen - ETHERNET_HEADER_LEN;

    switch (ethertype) {
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

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];

    signal(SIGINT, handle_sigint);

    global_handle = pcap_open_live("enp0s3", 65535, 1, 1000, errbuf);
    if (global_handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    printf("[*] OT Asset Fingerprinter - listening on enp0s3\n");
    printf("[*] Protocols: LLDP + PROFINET\n");
    printf("[*] Press Ctrl+C to stop and print asset table\n\n");

    pcap_loop(global_handle, -1, packet_handler, NULL);

    pcap_close(global_handle);
    print_asset_table();

    return 0;
}
