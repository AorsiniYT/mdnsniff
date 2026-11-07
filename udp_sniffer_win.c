/*
 * Modular mDNS UDP Sniffer for Windows
 * Detection of Moonlight/Sunshine (GameStream) services on the local network.
 *
 * Author: AorsiniYT
 * Copyright 2025
 */

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "udp_sniffer_win.h"
#include "mdns_dns.h"
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define MAX_SUNSHINE 16
#define HOSTNAME_LEN 256
#define CACHE_TIMEOUT 10 // seconds

struct sunshine_entry {
    char host[HOSTNAME_LEN];
    int port;
    time_t last_seen;
    char ip[INET_ADDRSTRLEN];
    char target[HOSTNAME_LEN];
};

static struct sunshine_entry sunshine_table[MAX_SUNSHINE];
// Multi-socket support: one per real interface
#define MAX_MDNS_SOCKETS 8
static SOCKET mdns_sockets[MAX_MDNS_SOCKETS];
static int mdns_socket_count = 0;
static int initialized = 0;
static int moonlight_count = 0;
static moonlight_found_cb_win g_found_cb = NULL;

void udp_sniffer_win_set_callback(moonlight_found_cb_win cb) {
    g_found_cb = cb;
}

int udp_sniffer_win_init(void) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) return -1;
    memset(mdns_sockets, 0, sizeof(mdns_sockets));
    mdns_socket_count = 0;
    printf("[mDNS] Enumerating network interfaces...\n");
    ULONG bufLen = 15000;
    IP_ADAPTER_ADDRESSES *pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(bufLen);
    DWORD dwRetVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, pAddresses, &bufLen);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(bufLen);
        dwRetVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, pAddresses, &bufLen);
    }
    int iface_count = 0, joined_count = 0;
    if (dwRetVal == NO_ERROR) {
        IP_ADAPTER_ADDRESSES *pCurr = pAddresses;
        while (pCurr && mdns_socket_count < MAX_MDNS_SOCKETS) {
            int is_up = (pCurr->OperStatus == IfOperStatusUp);
            int is_loopback = (pCurr->IfType == IF_TYPE_SOFTWARE_LOOPBACK);
            char descA[256] = {0};
            if (pCurr->Description) {
                WideCharToMultiByte(CP_UTF8, 0, pCurr->Description, -1, descA, sizeof(descA)-1, NULL, NULL);
            }
            int is_virtual = (pCurr->IfType == IF_TYPE_TUNNEL || pCurr->IfType == IF_TYPE_IEEE1394 || pCurr->IfType == IF_TYPE_OTHER || strstr(descA, "Virtual") || strstr(descA, "VMware") || strstr(descA, "Loopback") || strstr(descA, "Bluetooth") || strstr(descA, "Pseudo") || strstr(descA, "WSL") || strstr(descA, "VPN"));
            if (is_up && !is_loopback && !is_virtual) {
                IP_ADAPTER_UNICAST_ADDRESS *u = pCurr->FirstUnicastAddress;
                for (; u && mdns_socket_count < MAX_MDNS_SOCKETS; u = u->Next) {
                    struct sockaddr_in* if_addr = (struct sockaddr_in*)u->Address.lpSockaddr;
                    char ipstr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &if_addr->sin_addr, ipstr, sizeof(ipstr));
                    printf("[mDNS] Interface %d: %s | Type: %u | IP: %s\n", iface_count, descA, pCurr->IfType, ipstr);
                    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                    if (s == INVALID_SOCKET) continue;
                    u_long nonblocking = 1;
                    ioctlsocket(s, FIONBIO, &nonblocking);
                    int opt = 1;
                    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
                    struct sockaddr_in bind_addr;
                    memset(&bind_addr, 0, sizeof(bind_addr));
                    bind_addr.sin_family = AF_INET;
                    bind_addr.sin_addr = if_addr->sin_addr;
                    bind_addr.sin_port = htons(5353);
                    if (bind(s, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
                        closesocket(s); continue;
                    }
                    struct ip_mreq mreq;
                    mreq.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
                    mreq.imr_interface.s_addr = if_addr->sin_addr.s_addr;
                    if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq, sizeof(mreq)) == 0) {
                        printf("[mDNS] -> Joined multicast on %s\n", ipstr);
                        mdns_sockets[mdns_socket_count++] = s;
                        joined_count++;
                    } else {
                        printf("[mDNS] -> ERROR joining multicast on %s\n", ipstr);
                        closesocket(s);
                    }
                }
            }
            iface_count++;
            pCurr = pCurr->Next;
        }
    } else {
        printf("[mDNS] ERROR: Could not enumerate interfaces (code %ld)\n", dwRetVal);
    }
    if (pAddresses) free(pAddresses);
    printf("[mDNS] Total interfaces detected: %d, multicast sockets: %d\n", iface_count, mdns_socket_count);
    // Send mDNS query to force Sunshine response on each socket
    unsigned char query[] = {
        0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
        9,'_','n','v','s','t','r','e','a','m',
        4,'_','t','c','p',
        5,'l','o','c','a','l',0x00,
        0x00,0x0C,0x00,0x01
    };
    for (int i = 0; i < mdns_socket_count; ++i) {
        struct sockaddr_in mcast_addr;
        memset(&mcast_addr, 0, sizeof(mcast_addr));
        mcast_addr.sin_family = AF_INET;
        mcast_addr.sin_addr.s_addr = inet_addr("224.0.0.251");
        mcast_addr.sin_port = htons(5353);
        sendto(mdns_sockets[i], (const char*)query, sizeof(query), 0, (struct sockaddr*)&mcast_addr, sizeof(mcast_addr));
    }
    memset(sunshine_table, 0, sizeof(sunshine_table));
    initialized = 1;
    moonlight_count = 0;
    return 0;
}

static void update_sunshine(const char* host, int port, const char* ip, const char* target) {
    time_t now = time(NULL);
    int idx = -1;
    for (int i = 0; i < MAX_SUNSHINE; ++i) {
        if (strcmp(sunshine_table[i].host, host) == 0) { idx = i; break; }
    }
    if (idx == -1) {
        time_t oldest = now;
        for (int i = 0; i < MAX_SUNSHINE; ++i) {
            if (sunshine_table[i].host[0] == '\0') { idx = i; break; }
            if (sunshine_table[i].last_seen < oldest) { oldest = sunshine_table[i].last_seen; idx = i; }
        }
        if (idx >= 0) {
            strncpy(sunshine_table[idx].host, host, HOSTNAME_LEN);
            sunshine_table[idx].port = 0;
            sunshine_table[idx].ip[0] = '\0';
            sunshine_table[idx].target[0] = '\0';
        }
    }
    if (idx >= 0) {
        if (port > 0) sunshine_table[idx].port = port;
        if (ip) strncpy(sunshine_table[idx].ip, ip, sizeof(sunshine_table[idx].ip));
        if (target && target[0]) {
            memset(sunshine_table[idx].target, 0, sizeof(sunshine_table[idx].target));
            strncpy(sunshine_table[idx].target, target, sizeof(sunshine_table[idx].target) - 1);
            sunshine_table[idx].target[sizeof(sunshine_table[idx].target) - 1] = '\0';
            for (int j = 0; j < MAX_SUNSHINE; ++j) {
                if (j != idx && strcmp(sunshine_table[j].target, target) == 0 && sunshine_table[j].ip[0]) {
                    strncpy(sunshine_table[idx].ip, sunshine_table[j].ip, sizeof(sunshine_table[idx].ip));
                    break;
                }
            }
        }
        sunshine_table[idx].last_seen = now;
    }
}

static void update_sunshine_ip_by_target(const char* target, const char* ip) {
    time_t now = time(NULL);
    for (int i = 0; i < MAX_SUNSHINE; ++i) {
        if (strcmp(sunshine_table[i].target, target) == 0 && sunshine_table[i].host[0]) {
            strncpy(sunshine_table[i].ip, ip, sizeof(sunshine_table[i].ip));
            sunshine_table[i].last_seen = now;
            break;
        }
    }
}

static void merge_ip_entries() {
    for (int i = 0; i < MAX_SUNSHINE; ++i) {
        if (sunshine_table[i].host[0] && sunshine_table[i].target[0]) {
            for (int j = 0; j < MAX_SUNSHINE; ++j) {
                if (i != j && !sunshine_table[j].host[0] && sunshine_table[j].target[0] && sunshine_table[j].ip[0] && strcmp(sunshine_table[i].target, sunshine_table[j].target) == 0) {
                    strncpy(sunshine_table[i].ip, sunshine_table[j].ip, sizeof(sunshine_table[i].ip));
                    sunshine_table[j].target[0] = '\0';
                    sunshine_table[j].ip[0] = '\0';
                    sunshine_table[j].last_seen = 0;
                    break;
                }
            }
        }
    }
}

static void check_and_print_ready_entries_win() {
    for (int i = 0; i < MAX_SUNSHINE; ++i) {
        if (sunshine_table[i].host[0] && sunshine_table[i].target[0] && sunshine_table[i].ip[0] && sunshine_table[i].port > 0) {
            moonlight_count++;
            if (g_found_cb) {
                g_found_cb(moonlight_count, sunshine_table[i].host, sunshine_table[i].target, sunshine_table[i].ip, sunshine_table[i].port);
            }
            sunshine_table[i].host[0] = '\0';
            sunshine_table[i].ip[0] = '\0';
            sunshine_table[i].port = 0;
            sunshine_table[i].target[0] = '\0';
        }
    }
}

void udp_sniffer_win_poll(void) {
    if (!initialized || mdns_socket_count == 0) return;
    char buffer[2048];
    for (int i = 0; i < mdns_socket_count; ++i) {
        struct sockaddr_in from;
        int fromlen = sizeof(from);
        int n = recvfrom(mdns_sockets[i], buffer, sizeof(buffer), 0, (struct sockaddr*)&from, &fromlen);
        if (n <= 0) continue;
        const unsigned char* pkt = (const unsigned char*)buffer;
        int msglen = n;
        int qdcount = 0, ancount = 0;
        if (msglen > 12) {
            qdcount = (pkt[4]<<8) | pkt[5];
            ancount = (pkt[6]<<8) | pkt[7];
            int nscount = (pkt[8]<<8) | pkt[9];
            int arcount = (pkt[10]<<8) | pkt[11];
            int pos = 12;
            for (int q = 0; q < qdcount; ++q) {
                char qname[256];
                int l = decode_dns_name(pkt, msglen, pos, qname, sizeof(qname));
                if (l < 0 || l > msglen - pos - 4) {
                    pos = msglen;
                    break;
                }
                pos += l + 4;
            }
            int total_rr = ancount + nscount + arcount;
            for (int j = 0; j < total_rr && pos < msglen; ++j) {
                struct mdns_record rr;
                if (!mdns_next_record(pkt, msglen, pos, &rr)) break;
                const char* rrname = rr.name;
                int type = rr.type;
                int rdlength = rr.rdlength;
                pos = rr.rdata_offset;
                if (type == 12) { // PTR
                    char ptrname[256];
                    int ptr_used = decode_dns_name(pkt, msglen, pos, ptrname, sizeof(ptrname));
                    if (ptr_used >= 0 && ptr_used <= rdlength && strstr(ptrname, "_nvstream._tcp.local") != NULL) {
                        update_sunshine(ptrname, 0, NULL, NULL);
                    }
                }
                if (type == 33 && rdlength >= 6) { // SRV
                    int srv_port = (pkt[pos+4]<<8) | pkt[pos+5];
                    char target[256] = {0};
                    int target_used = decode_dns_name(pkt, msglen, pos+6, target, sizeof(target));
                    size_t len = strlen(rrname);
                    const char* suffix = "._nvstream._tcp.local";
                    size_t suffixlen = strlen(suffix);
                    if (target_used >= 0 && target_used <= rdlength - 6 && len > suffixlen && strcmp(rrname + len - suffixlen, suffix) == 0) {
                        if (target[0]) {
                            update_sunshine(rrname, srv_port, NULL, target);
                        }
                    }
                }
                if (type == 1 && rdlength == 4) { // A
                    char ip[INET_ADDRSTRLEN];
                    snprintf(ip, sizeof(ip), "%u.%u.%u.%u", pkt[pos], pkt[pos+1], pkt[pos+2], pkt[pos+3]);
                    update_sunshine_ip_by_target(rrname, ip);
                }
                pos = rr.next_offset;
            }
            merge_ip_entries();
            check_and_print_ready_entries_win();
        }
    }
}

void udp_sniffer_win_deinit(void) {
    for (int i = 0; i < mdns_socket_count; ++i) {
        if (mdns_sockets[i] != INVALID_SOCKET) {
            closesocket(mdns_sockets[i]);
            mdns_sockets[i] = INVALID_SOCKET;
        }
    }
    mdns_socket_count = 0;
    WSACleanup();
    initialized = 0;
}

// Usage example
#ifdef UDP_SNIFFER_WIN_MAIN
void moonlight_found_callback_win(int idx, const char* host, const char* pcname, const char* ip, int port) {
    printf("[Moonlight #%d] Host: %s | PC Name: %s | IP: %s | Port: %d\n", idx, host, pcname, ip, port);
}

int main() {
    printf("mDNS query sent for _nvstream._tcp.local.\n");
    printf("Listening only for Moonlight/Sunshine (_nvstream._tcp.local)...\n");
    udp_sniffer_win_set_callback(moonlight_found_callback_win);
    if (udp_sniffer_win_init() < 0) {
        printf("Error initializing mDNS sniffer.\n");
        return 1;
    }
    while (1) {
        udp_sniffer_win_poll();
        Sleep(10);
    }
    udp_sniffer_win_deinit();
    return 0;
}
#endif

#endif // _WIN32
