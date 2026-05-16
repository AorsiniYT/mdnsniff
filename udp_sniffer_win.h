/*
 * Modular mDNS UDP Sniffer for Windows
 * Detection of Moonlight/Sunshine (GameStream) services on the local network.
 *
 * Author: AorsiniYT
 * Copyright 2025
 */

#ifndef UDP_SNIFFER_WIN_H
#define UDP_SNIFFER_WIN_H
#ifdef __cplusplus
extern "C" {
#endif

/**
 * Callback for Moonlight/Sunshine host detection.
 * @param idx   Detection number (1, 2, ...)
 * @param host  mDNS host name (e.g. "DESKTOP-XXXXXX._nvstream._tcp.local")
 * @param pcname Machine/PC name (target SRV, e.g. "DESKTOP-XXXXXX.local")
 * @param ip    Detected IP address (e.g. "192.168.1.100")
 * @param port TCP port of the GameStream service
 */
typedef void (*moonlight_found_cb_win)(int idx, const char* host, const char* pcname, const char* ip, int port);

/**
 * Registers the callback function to be called when a Moonlight/Sunshine host is detected.
 */
void udp_sniffer_win_set_callback(moonlight_found_cb_win cb);

/**
 * Initializes the mDNS sniffer (opens socket, sends query, etc).
 * Call once before use.
 * Returns 0 if ok, <0 if error.
 */
int udp_sniffer_win_init(void);

/**
 * Processes an mDNS packet if available (non-blocking).
 * Call periodically from the main loop.
 */
void udp_sniffer_win_poll(void);

/**
 * Frees sniffer resources (closes socket, etc).
 */
void udp_sniffer_win_deinit(void);

#ifdef __cplusplus
}
#endif
#endif // UDP_SNIFFER_WIN_H
