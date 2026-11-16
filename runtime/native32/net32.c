/*
 * net32.c - keep a lifted network program on this machine.
 *
 * native32_net_loopback_only() redirects the guest's Winsock imports
 * (wsock32 or ws2_32, by name) to these checks, before the real call:
 *
 *   connect, sendto   refused (WSAENETUNREACH) unless the address is 127/8;
 *   bind              INADDR_ANY becomes 127.0.0.1, so a listening socket
 *                     (a file server, a data port) is never reachable from
 *                     the network and Windows Firewall never asks; any
 *                     other non-loopback address is refused (WSAEADDRNOTAVAIL);
 *   gethostbyname     answers only "localhost" and numeric 127/8 names; any
 *                     other name is not found (WSAHOST_NOT_FOUND), so nothing
 *                     is even looked up in DNS.
 *
 * Each refusal is one line on stderr ("[net] refused ..."). For old
 * clients and servers with known holes that are run only for testing
 * against a local server. AF_INET only: an AF_INET6 address is refused
 * (no 2000-era program uses it). Call before native32_bind.
 * ponytail: WSAAsyncGetHostByName and WSAConnect are not covered; add them
 * here when a program that imports them is lifted.
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "native32.h"

#pragma comment(lib, "ws2_32.lib")

static int loopback(const struct sockaddr* a, int n) {
    if (!a || n < (int)sizeof(struct sockaddr_in) || a->sa_family != AF_INET) return 0;
    return (ntohl(((const struct sockaddr_in*)a)->sin_addr.s_addr) >> 24) == 127;
}

static void refused(const char* what, const struct sockaddr* a) {
    if (a && a->sa_family == AF_INET) {
        const struct sockaddr_in* s = (const struct sockaddr_in*)a;
        unsigned ip = ntohl(s->sin_addr.s_addr);
        fprintf(stderr, "[net] refused %s to %u.%u.%u.%u:%u (loopback only)\n", what,
                ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255, ntohs(s->sin_port));
    } else {
        fprintf(stderr, "[net] refused %s (family %d; loopback only)\n", what, a ? a->sa_family : -1);
    }
}

static int WINAPI g_connect(SOCKET s, const struct sockaddr* a, int n) {
    if (!loopback(a, n)) { refused("connect", a); WSASetLastError(WSAENETUNREACH); return SOCKET_ERROR; }
    return connect(s, a, n);
}

static int WINAPI g_sendto(SOCKET s, const char* b, int len, int fl, const struct sockaddr* a, int n) {
    if (a && !loopback(a, n)) { refused("sendto", a); WSASetLastError(WSAENETUNREACH); return SOCKET_ERROR; }
    return sendto(s, b, len, fl, a, n);
}

static int WINAPI g_bind(SOCKET s, const struct sockaddr* a, int n) {
    if (a && a->sa_family == AF_INET && n >= (int)sizeof(struct sockaddr_in)) {
        struct sockaddr_in in = *(const struct sockaddr_in*)a;
        if (in.sin_addr.s_addr == htonl(INADDR_ANY)) in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (!loopback((struct sockaddr*)&in, sizeof in)) {
            refused("bind", a); WSASetLastError(WSAEADDRNOTAVAIL); return SOCKET_ERROR;
        }
        return bind(s, (struct sockaddr*)&in, sizeof in);
    }
    refused("bind", a); WSASetLastError(WSAEADDRNOTAVAIL); return SOCKET_ERROR;
}

static struct hostent* WINAPI g_gethostbyname(const char* name) {
    unsigned long ip = name ? inet_addr(name) : INADDR_NONE;
    if (name && (!_stricmp(name, "localhost") || (ip != INADDR_NONE && (ntohl(ip) >> 24) == 127)))
        return gethostbyname(!_stricmp(name, "localhost") ? "127.0.0.1" : name);
    fprintf(stderr, "[net] refused lookup of %s (loopback only)\n", name ? name : "(null)");
    WSASetLastError(WSAHOST_NOT_FOUND);
    return NULL;
}

void native32_net_loopback_only(void) {
    native32_redirect("connect", (void*)g_connect);
    native32_redirect("sendto", (void*)g_sendto);
    native32_redirect("bind", (void*)g_bind);
    native32_redirect("gethostbyname", (void*)g_gethostbyname);
}
