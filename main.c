/*
 * mDNS UDP sniffer integration example for PSVita/Windows/Wii U
 *
 * Author: AorsiniYT
 * Copyright 2025
 */

#ifdef __vita__
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/clib.h> 
#include <psp2/sysmodule.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <psp2/ctrl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "udp_sniffer_vita.h"
#define MDNS_LOG sceClibPrintf
#include "common/debugScreen.h"

#define NET_PARAM_MEM_SIZE (256 * 1024)

void moonlight_found_callback(int idx, const char* host, const char* pcname, const char* ip, int port) {
    psvDebugScreenPrintf("[Moonlight #%d] Host: %s | PC Name: %s | IP: %s | Port: %d\n",
        idx, host, pcname, ip, port);
    MDNS_LOG("[Moonlight #%d] Host: %s | PC Name: %s | IP: %s | Port: %d\n",
        idx, host, pcname, ip, port);
}

int main(int argc, char *argv[]) {
    psvDebugScreenInit();
    MDNS_LOG("[USB] Network test and UDP mDNS sniffer started.\n");
    psvDebugScreenPrintf("Starting network test and UDP mDNS sniffer on Vita...\n");
    psvDebugScreenPrintf("\nIMPORTANT: GeForce Experience or Sunshine must be running on your local network to discover hosts.\n\n");
    MDNS_LOG("IMPORTANT: GeForce Experience or Sunshine must be running on your local network to discover hosts.\n");

    int ret;
    void *net_mem = NULL;

    psvDebugScreenPrintf("Loading network module (SCE_SYSMODULE_NET)...\n");
    ret = sceSysmoduleLoadModule(SCE_SYSMODULE_NET);
    if (ret < 0) {
        psvDebugScreenPrintf("ERROR: sceSysmoduleLoadModule failed: 0x%08X\n", ret);
        MDNS_LOG("ERROR: sceSysmoduleLoadModule failed: 0x%08X\n", ret);
        goto end;
    }

    psvDebugScreenPrintf("Initializing network (sceNetInit)...\n");
    SceNetInitParam netInitParam;
    net_mem = malloc(NET_PARAM_MEM_SIZE);
    if (!net_mem) {
        psvDebugScreenPrintf("ERROR: malloc for net_mem failed\n");
        MDNS_LOG("ERROR: malloc for net_mem failed\n");
        goto end;
    }
    netInitParam.memory = net_mem;
    netInitParam.size = NET_PARAM_MEM_SIZE;
    netInitParam.flags = 0;
    ret = sceNetInit(&netInitParam);
    if (ret < 0) {
        psvDebugScreenPrintf("ERROR: sceNetInit failed: 0x%08X\n", ret);
        MDNS_LOG("ERROR: sceNetInit failed: 0x%08X\n", ret);
        goto end;
    }

    psvDebugScreenPrintf("Initializing network control (sceNetCtlInit)...\n");
    ret = sceNetCtlInit();
    if (ret < 0) {
        psvDebugScreenPrintf("ERROR: sceNetCtlInit failed: 0x%08X\n", ret);
        MDNS_LOG("ERROR: sceNetCtlInit failed: 0x%08X\n", ret);
        goto end;
    }

    // Get network information
    SceNetCtlInfo info;
    ret = sceNetCtlInetGetInfo(SCE_NETCTL_INFO_GET_IP_ADDRESS, &info);
    if (ret < 0) {
        psvDebugScreenPrintf("ERROR: sceNetCtlInetGetInfo failed: 0x%08X\n", ret);
        MDNS_LOG("ERROR: sceNetCtlInetGetInfo failed: 0x%08X\n", ret);
        goto end;
    }

    psvDebugScreenPrintf("IP: %s\n", info.ip_address);
    MDNS_LOG("IP: %s\n", info.ip_address);

    psvDebugScreenPrintf("\nmDNS UDP Sniffer active. Watch the console for Moonlight/Sunshine service logs.\n");
    MDNS_LOG("mDNS UDP Sniffer active. Watch the console for Moonlight/Sunshine service logs.\n");
    psvDebugScreenPrintf("\nPress CIRCLE (O) to exit the application.\n");
    MDNS_LOG("Press CIRCLE (O) to exit the application.\n");

    // Main loop: only UDP sniffer
    udp_sniffer_vita_set_callback(moonlight_found_callback);
    SceCtrlData ctrl;
    while (1) {
        udp_sniffer_vita_poll(); // Process mDNS packet if available
        
        sceCtrlPeekBufferPositive(0, &ctrl, 1);
        if (ctrl.buttons & SCE_CTRL_CIRCLE) {
            break;
        }
        
        sceKernelDelayThread(1000 * 10); // 10ms to not saturate CPU
    }

end:
    if (net_mem) {
        free(net_mem);
    }
    sceSysmoduleUnloadModule(SCE_SYSMODULE_NET);
    return 0;
}
#elif defined(__WIIU__)
#include <coreinit/thread.h>
#include <coreinit/time.h>
#include <whb/proc.h>
#include <whb/log.h>
#include <whb/log_console.h>
#include <whb/log_udp.h>
#include <vpad/input.h>
#include <sysapp/launch.h>
#include <stdio.h>
#include <stdlib.h>
#include "udp_sniffer_wiiu.h"

#define MDNS_LOG WHBLogPrintf

void moonlight_found_callback(int idx, const char* host, const char* pcname, const char* ip, int port) {
    MDNS_LOG("[Moonlight #%d] Host: %s | PC Name: %s | IP: %s | Port: %d",
        idx, host, pcname, ip, port);
}

int main(int argc, char *argv[]) {
    WHBProcInit();
    WHBLogConsoleInit();

    MDNS_LOG("Starting network test and mDNS UDP sniffer on Wii U...");
    MDNS_LOG("");
    MDNS_LOG("IMPORTANT: GeForce Experience or Sunshine must be running");
    MDNS_LOG("on your local network to discover hosts.");
    MDNS_LOG("");
    MDNS_LOG("Press the B button on the GamePad to exit.");
    MDNS_LOG("");

    udp_sniffer_wiiu_init();
    udp_sniffer_wiiu_set_callback(moonlight_found_callback);

    VPADStatus vpad_status;
    VPADReadError vpad_error;
    int quitting = 0;

    while (WHBProcIsRunning()) {
        if (!quitting) {
            udp_sniffer_wiiu_poll();
        }

        VPADRead(VPAD_CHAN_0, &vpad_status, 1, &vpad_error);
        if (vpad_error == VPAD_READ_SUCCESS) {
            if (!quitting && (vpad_status.trigger & VPAD_BUTTON_B)) {
                MDNS_LOG("");
                MDNS_LOG("Exiting application...");
                WHBLogConsoleDraw();
                quitting = 1;
                SYSLaunchMenu();
            }
        }

        OSSleepTicks(OSMillisecondsToTicks(10));
        WHBLogConsoleDraw();
    }

    WHBLogConsoleFree();
    WHBProcShutdown();
    return 0;
}
#else // Windows/others
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "mdns.h"
#define MDNS_LOG printf

// Stubs for Vita functions
#define psvDebugScreenInit() ((void)0)
#define psvDebugScreenPrintf printf
#define sceKernelDelayThread(ms) Sleep((ms)/1000)

// Structure to store information about the discovered server
typedef struct {
    char instance[256];
    char host[256];
    uint16_t port;
    char ip_v4[16];
    int has_ptr;
    int has_srv;
    int has_a;
} ServerInfo;

ServerInfo servers[8];
static ServerInfo* find_or_create_server_by_instance(const char* instance) {
    for (int i = 0; i < 8; ++i) {
        if (servers[i].has_ptr && strcmp(servers[i].instance, instance) == 0) {
            return &servers[i];
        }
    }
    for (int i = 0; i < 8; ++i) {
        if (!servers[i].has_ptr) {
            strncpy(servers[i].instance, instance, sizeof(servers[i].instance) - 1);
            servers[i].has_ptr = 1;
            return &servers[i];
        }
    }
    return NULL;
}
static ServerInfo* find_server_by_host(const char* host) {
    for (int i = 0; i < 8; ++i) {
        if (servers[i].has_srv && strcmp(servers[i].host, host) == 0) {
            return &servers[i];
        }
    }
    return NULL;
}
static void clear_servers() { memset(servers, 0, sizeof(servers)); }

// Declarations for required functions from mdns.c
int mdns_socket_open_ipv4(const struct sockaddr_in* saddr);
void mdns_socket_close(int sock);
int mdns_discovery_send(int sock);
size_t mdns_discovery_recv(int sock, void* buffer, size_t capacity, mdns_record_callback_fn callback, void* user_data);
mdns_string_t mdns_record_parse_ptr(const void* buffer, size_t size, size_t offset, size_t length, char* strbuffer, size_t capacity);
mdns_record_srv_t mdns_record_parse_srv(const void* buffer, size_t size, size_t offset, size_t length, char* strbuffer, size_t capacity);
struct sockaddr_in* mdns_record_parse_a(const void* buffer, size_t size, size_t offset, size_t length, struct sockaddr_in* addr);

// Callback to process ALL mDNS responses
int mdns_callback(int sock, const struct sockaddr* from, size_t addrlen,
                  mdns_entry_type_t entry, uint16_t query_id,
                  uint16_t rtype, uint16_t rclass, uint32_t ttl,
                  const void* data, size_t size,
                  size_t name_offset, size_t name_length,
                  size_t record_offset, size_t record_length,
                  void* user_data) {
    (void)sock; (void)addrlen; (void)query_id; (void)rclass; (void)ttl; (void)data; (void)size; (void)user_data;
    char from_addr_buffer[64] = {0};
    const struct sockaddr_in* sa = (const struct sockaddr_in*)from;
    inet_ntop(AF_INET, &sa->sin_addr, from_addr_buffer, sizeof(from_addr_buffer));
    mdns_string_t from_addr_str = { from_addr_buffer, strlen(from_addr_buffer) };
    const char* entry_type = (entry == MDNS_ENTRYTYPE_ANSWER) ? "ANSWER" : (entry == MDNS_ENTRYTYPE_AUTHORITY) ? "AUTHORITY" : "ADDITIONAL";
    printf("[mDNS] [%s] from %s | rtype: %u\n", entry_type, from_addr_str.str, rtype);
    // Print record name
    printf("  Name: %.*s\n", (int)name_length, (const char*)MDNS_POINTER_OFFSET(data, name_offset));
    // Print data according to type
    if (rtype == MDNS_RECORDTYPE_PTR) {
        char name_buffer[256];
        mdns_string_t name_str = mdns_record_parse_ptr(data, size, record_offset, record_length, name_buffer, sizeof(name_buffer));
        printf("    PTR: %.*s\n", (int)name_str.length, name_str.str);
    } else if (rtype == MDNS_RECORDTYPE_SRV) {
        char srv_name_buffer[256];
        mdns_record_srv_t srv = mdns_record_parse_srv(data, size, record_offset, record_length, srv_name_buffer, sizeof(srv_name_buffer));
        printf("    SRV: %.*s port %d\n", (int)name_length, (const char*)MDNS_POINTER_OFFSET(data, name_offset), srv.port);
    } else if (rtype == MDNS_RECORDTYPE_A) {
        struct sockaddr_in addr;
        mdns_record_parse_a(data, size, record_offset, record_length, &addr);
        char a_addr_buffer[64];
        inet_ntop(AF_INET, &addr.sin_addr, a_addr_buffer, sizeof(a_addr_buffer));
        printf("    A: %s\n", a_addr_buffer);
    } else if (rtype == MDNS_RECORDTYPE_TXT) {
        const uint8_t* txt = (const uint8_t*)MDNS_POINTER_OFFSET(data, record_offset);
        size_t txt_len = record_length;
        printf("    TXT: ");
        for (size_t i = 0; i < txt_len; ++i) {
            char c = txt[i];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        printf("\n");
    }
    // Other types are also printed
    return 0;
}

int main(int argc, char *argv[]) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }
    printf("[WIN] Network test and mDNS started.\n");
    printf("Starting network test and mDNS sniffer on Windows...\n");
    printf("IMPORTANT: GeForce Experience or Sunshine must be running on your local network to discover hosts.\n\n");

    // Show local IPs before starting mDNS
    printf("Local IPs detected on this machine:\n");
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        struct addrinfo hints = {0}, *res, *p;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(hostname, NULL, &hints, &res) == 0) {
            for (p = res; p != NULL; p = p->ai_next) {
                struct sockaddr_in *addr = (struct sockaddr_in *)p->ai_addr;
                char ipstr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr->sin_addr, ipstr, sizeof(ipstr));
                printf("  %s\n", ipstr);
            }
            freeaddrinfo(res);
        } else {
            printf("  (Could not get local IP)\n");
        }
    } else {
        printf("  (Could not get local hostname)\n");
    }
    printf("---------------------------------\n");

    clear_servers();
#ifdef _WIN32
    // --- mDNS socket opening on Windows with correct multicast configuration ---
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        printf("ERROR: Could not create mDNS socket\n");
        WSACleanup();
        return 1;
    }
    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse)) < 0) {
        printf("[WARN] Could not activate SO_REUSEADDR\n");
    }
    struct sockaddr_in addr_bind;
    memset(&addr_bind, 0, sizeof(addr_bind));
    addr_bind.sin_family = AF_INET;
    addr_bind.sin_addr.s_addr = htonl(INADDR_ANY);
    addr_bind.sin_port = htons(5353);
    if (bind(sock, (struct sockaddr*)&addr_bind, sizeof(addr_bind)) < 0) {
        printf("ERROR: Could not bind to INADDR_ANY:5353\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq, sizeof(mreq)) < 0) {
        printf("[WARN] Could not join multicast group mDNS (224.0.0.251)\n");
    } else {
        printf("[OK] Unido al grupo multicast mDNS (224.0.0.251)\n");
    }
#else
    int sock = mdns_socket_open_ipv4(NULL);
    if (sock < 0) {
        printf("ERROR: Could not open mDNS socket: %d\n", sock);
        WSACleanup();
        return 1;
    }
#endif

    printf("Sending mDNS query for: _services._dns-sd._udp.local.\n");
    // mdns_discovery_send_service(sock, "_nvstream._tcp.local.");
    printf("Waiting for mDNS responses (10 seconds)...\n");
    char recv_buffer[2048];
    for (int i = 0; i < 200; ++i) {
        int processed;
        do {
            processed = mdns_discovery_recv(sock, recv_buffer, sizeof(recv_buffer), mdns_callback, NULL);
        } while (processed > 0);
        Sleep(50);
    }
    printf("\n--- Discovery Finished ---\n");
    int found = 0;
    for (int i = 0; i < 8; ++i) {
        if (servers[i].has_ptr && servers[i].has_srv && servers[i].has_a) {
            printf("Server Found:\n");
            printf("  Instance: %s\n", servers[i].instance);
            printf("  Host:      %s\n", servers[i].host);
            printf("  IP:        %s\n", servers[i].ip_v4);
            printf("  Port:      %d\n", servers[i].port);
            found = 1;
        }
    }
    if (!found) {
        printf("No GameStream servers found.\n");
    }
    printf("---------------------------------\n\n");
    found = 0;
    for (int i = 0; i < 8; ++i) {
        if (servers[i].has_a) {
            printf("Host with IP detected:\n");
            if (servers[i].instance[0])
                printf("  Instance: %s\n", servers[i].instance);
            if (servers[i].host[0])
                printf("  Host:      %s\n", servers[i].host);
            printf("  IP:        %s\n", servers[i].ip_v4);
            if (servers[i].port)
                printf("  Port:      %d\n", servers[i].port);
            found = 1;
        }
    }
    if (!found) {
        printf("No hosts with IP found via mDNS.\n");
    }
    printf("---------------------------------\n\n");
    mdns_socket_close(sock);
    printf("mDNS socket closed.\n");
    printf("Test finished.\n");
    WSACleanup();
#ifdef _WIN32
    system("pause");
#endif
    return 0;
}
#endif
