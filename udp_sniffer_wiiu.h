/**
 * @file udp_sniffer_wiiu.h
 * @brief UDP mDNS sniffer for Wii U (wut) - Integration API
 *
 * This file defines the API to integrate the Moonlight/Sunshine mDNS sniffer.
 * The sniffer detects GameStream services on the local network and notifies
 * discoveries via callback.
 *
 * Typical usage:
 *   1. Call udp_sniffer_wiiu_set_callback() with your function to receive discoveries.
 *   2. Call udp_sniffer_wiiu_poll() periodically in your main loop.
 */

#ifndef UDP_SNIFFER_WIIU_H
#define UDP_SNIFFER_WIIU_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Callback type for Moonlight/Sunshine host discovery.
 * @param idx   Detection number (1, 2, ...)
 * @param host  mDNS host name (e.g.: "DESKTOP-XXXXXX._nvstream._tcp.local")
 * @param pcname Machine/PC name (SRV target, e.g.: "DESKTOP-XXXXXX.local")
 * @param ip    Detected IP address (e.g.: "192.168.1.100")
 * @param port  TCP port of the GameStream service
 */
typedef void (*moonlight_found_cb)(int idx, const char* host, const char* pcname, const char* ip, int port);

void udp_sniffer_wiiu_set_callback(moonlight_found_cb cb);
void udp_sniffer_wiiu_poll(void);
void udp_sniffer_wiiu_deinit(void);
void udp_sniffer_wiiu_init(void);

#ifdef __cplusplus
}
#endif

#endif // UDP_SNIFFER_WIIU_H
