/*
 * UDP mDNS sniffer for Wii U (wut)
 * Detects Moonlight/Sunshine (GameStream) services on the local network.
 */

#ifdef __WIIU__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include "udp_sniffer_wiiu.h"
#include <stdarg.h>

#define UDP_LOG_PORT 4405
#define UDP_LOG_BUF_SIZE 1024

static int udp_log_sock = -1;
static struct sockaddr_in udp_log_addr;
static int udp_log_enabled = 0;

static void udp_debug_init(void) {
    udp_log_enabled = 0;
    udp_log_sock = -1;

    udp_log_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_log_sock < 0) {
        return;
    }

    int broadcast_enable = 1;
    setsockopt(udp_log_sock, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable));

    memset(&udp_log_addr, 0, sizeof(udp_log_addr));
    udp_log_addr.sin_family = AF_INET;
    udp_log_addr.sin_port = htons(UDP_LOG_PORT);
    udp_log_addr.sin_addr.s_addr = inet_addr("255.255.255.255");

    udp_log_enabled = 1;

    const char* init_msg = "[WIIU] UDP debug logger initialized (broadcast)\n";
    sendto(udp_log_sock, init_msg, strlen(init_msg), 0,
           (struct sockaddr*)&udp_log_addr, sizeof(udp_log_addr));
}

static void wiiu_log(const char* fmt, ...) {
    char buffer[UDP_LOG_BUF_SIZE];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buffer, sizeof(buffer) - 2, fmt, args);
    va_end(args);

    if (len < 0) len = 0;
    if ((size_t)len >= sizeof(buffer) - 2) len = sizeof(buffer) - 3;

    if (len > 0 && buffer[len - 1] != '\n') {
        buffer[len] = '\n';
        buffer[len + 1] = '\0';
        len++;
    }

    if (udp_log_enabled && udp_log_sock >= 0) {
        sendto(udp_log_sock, buffer, len, 0,
               (struct sockaddr*)&udp_log_addr, sizeof(udp_log_addr));
    }
}

static void udp_debug_shutdown(void) {
    if (udp_log_sock >= 0) {
        udp_log_sock = -1;
    }
    udp_log_enabled = 0;
}

#define MDNS_LOG(...) wiiu_log(__VA_ARGS__)

#define BUF_SIZE 2048
#define MCAST_ADDR "224.0.0.251"
#define MCAST_PORT 5353
#define MAX_SUNSHINE 16
#define HOSTNAME_LEN 256
#define CACHE_TIMEOUT 10

// Decode a compressed DNS name
static int decode_dns_name(const unsigned char* msg, int msglen, int offset, char* out, int outlen) {
    int len = 0, jumped = 0, pos = offset, outpos = 0;
    while (pos < msglen) {
        unsigned char c = msg[pos];
        if (c == 0) { if (!jumped) len++; break; }
        if ((c & 0xC0) == 0xC0) {
            int ptr = ((c & 0x3F) << 8) | msg[pos+1];
            if (!jumped) len += 2;
            pos = ptr; jumped = 1; continue;
        }
        pos++;
        if (outpos && outpos < outlen-1) out[outpos++] = '.';
        for (int i = 0; i < c && pos < msglen && outpos < outlen-1; ++i) out[outpos++] = msg[pos++];
        if (!jumped) len += c + 1;
    }
    out[outpos] = '\0';
    return jumped ? len : (pos - offset + 1);
}

struct sunshine_entry {
    char host[HOSTNAME_LEN];
    int port;
    unsigned int last_seen;
    char ip[16];
    char target[HOSTNAME_LEN];
};

static struct sunshine_entry sunshine_table[MAX_SUNSHINE];
static int sock = -1;
static int initialized = 0;
static int moonlight_count = 0;
static unsigned int poll_ticks = 0;

static unsigned int get_tick_ms(void) {
    // Wii U has no direct ms tick function; use a per-poll counter.
    return poll_ticks * 100;
}

static void update_sunshine(const char* host, int port, const char* ip, const char* target) {
    unsigned int now = get_tick_ms();
    int idx = -1;
    for (int i = 0; i < MAX_SUNSHINE; ++i) {
        if (strcmp(sunshine_table[i].host, host) == 0) { idx = i; break; }
    }
    if (idx == -1) {
        unsigned int oldest = now;
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
            strncpy(sunshine_table[idx].target, target, sizeof(sunshine_table[idx].target) - 1);
            sunshine_table[idx].target[sizeof(sunshine_table[idx].target) - 1] = '\0';
        }
        sunshine_table[idx].last_seen = now;
    }
}

static void update_sunshine_ip_by_target(const char* target, const char* ip) {
    unsigned int now = get_tick_ms();
    for (int i = 0; i < MAX_SUNSHINE; ++i) {
        if (strcmp(sunshine_table[i].target, target) == 0 && sunshine_table[i].host[0]) {
            strncpy(sunshine_table[i].ip, ip, sizeof(sunshine_table[i].ip));
            sunshine_table[i].last_seen = now;
            break;
        }
    }
}

typedef void (*moonlight_found_cb)(int idx, const char* host, const char* pcname, const char* ip, int port);
static moonlight_found_cb g_found_cb = NULL;

void udp_sniffer_wiiu_set_callback(moonlight_found_cb cb) {
    MDNS_LOG("[mdns_log] udp_sniffer_wiiu_set_callback: cb=%p\n", cb);
    g_found_cb = cb;
}

static void merge_ip_entries() {
    for (int i = 0; i < MAX_SUNSHINE; ++i) {
        if (sunshine_table[i].host[0] && sunshine_table[i].target[0]) {
            for (int j = 0; j < MAX_SUNSHINE; ++j) {
                if (i != j && !sunshine_table[j].host[0] && sunshine_table[j].target[0] && sunshine_table[j].ip[0]
                    && strcmp(sunshine_table[i].target, sunshine_table[j].target) == 0) {
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

static void check_and_print_ready_entries_wiiu() {
    for (int i = 0; i < MAX_SUNSHINE; ++i) {
        if (sunshine_table[i].host[0] && sunshine_table[i].target[0] && sunshine_table[i].ip[0] && sunshine_table[i].port > 0) {
            moonlight_count++;
            MDNS_LOG("[mdns_log] Host found: %s [%s:%d]\n", sunshine_table[i].target, sunshine_table[i].ip, sunshine_table[i].port);
            if (g_found_cb) {
                g_found_cb(moonlight_count, sunshine_table[i].host, sunshine_table[i].target, sunshine_table[i].ip, sunshine_table[i].port);
            }
            // Make the port negative to indicate it was already notified and prevent duplicates
            sunshine_table[i].port = -sunshine_table[i].port;
        }
    }
}

void udp_sniffer_wiiu_poll(void) {
    poll_ticks++;
    static int poll_count = 0;
    poll_count++;
    if (!initialized) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) { MDNS_LOG("[WIIU] socket() failed\n"); return; }
        
        int reuse = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        // Increase receive buffer
        int rcvbuf = 65536;
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(MCAST_PORT);
        int bindres = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
        if (bindres < 0) { MDNS_LOG("[WIIU] bind() failed\n"); close(sock); sock = -1; return; }
        struct ip_mreq mreq;
        mreq.imr_multiaddr.s_addr = inet_addr(MCAST_ADDR);
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);
        int sockoptres = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
        if (sockoptres < 0) { MDNS_LOG("[WIIU] setsockopt(IP_ADD_MEMBERSHIP) failed\n"); close(sock); sock = -1; return; }
        // Send an active mDNS query
        unsigned char query[] = {
            0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
            9,'_','n','v','s','t','r','e','a','m',
            4,'_','t','c','p',
            5,'l','o','c','a','l',0x00,
            0x00,0x0C,0x00,0x01
        };
        struct sockaddr_in mcast_addr;
        memset(&mcast_addr, 0, sizeof(mcast_addr));
        mcast_addr.sin_family = AF_INET;
        mcast_addr.sin_addr.s_addr = inet_addr(MCAST_ADDR);
        mcast_addr.sin_port = htons(MCAST_PORT);
        int sendto_res = sendto(sock, query, sizeof(query), 0, (struct sockaddr*)&mcast_addr, sizeof(mcast_addr));
        memset(sunshine_table, 0, sizeof(sunshine_table));
        initialized = 1;
        MDNS_LOG("[WIIU] mDNS UDP Sniffer initialized.\n");
    }
    if (sock < 0) {
        return;
    }
    // Re-send mDNS query every 500 polls (~5 seconds)
    if (poll_count % 500 == 0) {
        unsigned char requery[] = {
            0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
            9,'_','n','v','s','t','r','e','a','m',
            4,'_','t','c','p',
            5,'l','o','c','a','l',0x00,
            0x00,0x0C,0x00,0x01
        };
        struct sockaddr_in mcast_dst;
        memset(&mcast_dst, 0, sizeof(mcast_dst));
        mcast_dst.sin_family = AF_INET;
        mcast_dst.sin_addr.s_addr = inet_addr(MCAST_ADDR);
        mcast_dst.sin_port = htons(MCAST_PORT);
        sendto(sock, requery, sizeof(requery), 0, (struct sockaddr*)&mcast_dst, sizeof(mcast_dst));
    }

    // Drain ALL available packets (up to 32 per poll call)
    __attribute__((aligned(32))) char buffer[BUF_SIZE];
    struct sockaddr_in from;
    int packets_read = 0;
    for (int pkt_i = 0; pkt_i < 32; pkt_i++) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 0; // 0 ms timeout for non-blocking poll
        int ready = select(sock + 1, &readfds, NULL, NULL, &tv);
        if (ready <= 0) {
            break; // No data ready or error
        }

        socklen_t fromlen = sizeof(from);
        memset(&from, 0, sizeof(from));
        int n = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&from, &fromlen);
        if (n <= 0) {
            break;
        }
        packets_read++;
        
        const unsigned char* pkt = (const unsigned char*)buffer;
        int msglen = n;
        int qdcount = 0, ancount = 0;
        if (msglen > 12) {
            qdcount = (pkt[4]<<8) | pkt[5];
            ancount = (pkt[6]<<8) | pkt[7];
            int nscount = (pkt[8]<<8) | pkt[9];
            int arcount = (pkt[10]<<8) | pkt[11];
            int pos = 12;
            for (int q = 0; q < qdcount && pos < msglen; ++q) {
                char qname[256];
                int l = decode_dns_name(pkt, msglen, pos, qname, sizeof(qname));
                pos += l + 4;
            }
            int total_rr = ancount + nscount + arcount;
            for (int i = 0; i < total_rr && pos < msglen; ++i) {
                int rr_start = pos;
                char rrname[256];
                int l = decode_dns_name(pkt, msglen, pos, rrname, sizeof(rrname));
                pos += l;
                if (pos+10 > msglen) break;
                int type = (pkt[pos]<<8) | pkt[pos+1];
                int rdlength = (pkt[pos+8]<<8) | pkt[pos+9];
                pos += 10;
                
                if (type == 12) { // PTR
                    char ptrname[256];
                    decode_dns_name(pkt, msglen, pos, ptrname, sizeof(ptrname));
                    if (strstr(ptrname, "_nvstream._tcp.local") != NULL) {
                        update_sunshine(ptrname, 0, NULL, NULL);
                    }
                }
                if (type == 33 && rdlength >= 6) { // SRV
                    int srv_port = (pkt[pos+4]<<8) | pkt[pos+5];
                    char target[256] = {0};
                    decode_dns_name(pkt, msglen, pos+6, target, sizeof(target));
                    size_t len = strlen(rrname);
                    const char* suffix = "._nvstream._tcp.local";
                    size_t suffixlen = strlen(suffix);
                    if (len > suffixlen && strcmp(rrname + len - suffixlen, suffix) == 0) {
                        if (target[0]) {
                            update_sunshine(rrname, srv_port, NULL, target);
                        }
                    }
                }
                if (type == 1 && rdlength == 4) { // A
                    char ip[16];
                    snprintf(ip, sizeof(ip), "%u.%u.%u.%u", pkt[pos], pkt[pos+1], pkt[pos+2], pkt[pos+3]);
                    update_sunshine_ip_by_target(rrname, ip);
                }
                pos = rr_start + l + 10 + rdlength;
            }
            merge_ip_entries();
            check_and_print_ready_entries_wiiu();
        }
    }
}

void udp_sniffer_wiiu_deinit(void) {
    MDNS_LOG("[mdns_log] udp_sniffer_wiiu_deinit called\n");
    udp_debug_shutdown();
    sock = -1;
    initialized = 0;
    moonlight_count = 0;
    poll_ticks = 0;
    memset(sunshine_table, 0, sizeof(sunshine_table));
}

void udp_sniffer_wiiu_init(void) {
    udp_debug_init();
    MDNS_LOG("[mdns_log] udp_sniffer_wiiu_init called\n");
    initialized = 0;
    moonlight_count = 0;
    poll_ticks = 0;
    memset(sunshine_table, 0, sizeof(sunshine_table));
}
#else
void udp_sniffer_wiiu_poll(void) {}
void udp_sniffer_wiiu_deinit(void) {}
void udp_sniffer_wiiu_init(void) {}
void udp_sniffer_wiiu_set_callback(void* cb) { (void)cb; }
#endif
