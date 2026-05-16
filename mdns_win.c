/*
 * mDNS UDP Sniffer for Windows (reference and tests)
 * Detection of Moonlight/Sunshine (GameStream) services on the local network.
 *
 * Author: AorsiniYT
 * Copyright 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define MDNS_PORT 5353
#define MDNS_ADDR "224.0.0.251"

void error(const char *msg) {
    perror(msg);
    exit(1);
}

int main(int argc, char *argv[]) {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in sa;
    struct ip_mreq mreq;
    char buf[1024];
    int recvlen;
    struct sockaddr_in from;
    int fromlen = sizeof(from);

    // Inicializar Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        error("WSAStartup failed");
    }

    // Crear socket UDP
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
        error("socket() failed");
    }

    // Configure socket address
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(MDNS_PORT);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);

    // Bind socket to address
    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR) {
        error("bind() failed");
    }

    // Join mDNS multicast group
    mreq.imr_multiaddr.s_addr = inet_addr(MDNS_ADDR);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) < 0) {
        error("setsockopt() failed");
    }

    printf("Waiting for mDNS packets on %s:%d...\n", MDNS_ADDR, MDNS_PORT);

    // Bucle principal
    while (1) {
        // Recibir datos
        if ((recvlen = recvfrom(sock, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&from, &fromlen)) == SOCKET_ERROR) {
            error("recvfrom() failed");
        }

        // Terminar cadena y mostrar datos recibidos
        buf[recvlen] = '\0';
        printf("Received: %s\n", buf);
    }

    // Close socket and cleanup Winsock (never reached in this example)
    closesocket(sock);
    WSACleanup();

    return 0;
}