/*
 * wsock32.c - WSOCK32 (Winsock 1.1) on BSD sockets.
 *
 * Imported by ordinal as often as by name, so each shim is registered under
 * both ("wsock32.dll#115" and "WSAStartup"). A SOCKET is the host descriptor
 * plus 0x1000 (never 0, never INVALID_SOCKET). Internet sockets are real; IPX
 * (AF_IPX) is refused with WSAEAFNOSUPPORT, as on a Windows with no IPX
 * protocol installed, so a game finds no IPX network and goes on.
 *
 * WSAAsyncSelect is served by hle_ws_poll(), which the message pump calls: a
 * socket that has become readable posts its window message, as Winsock's
 * window-message notification does.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "win32hle.h"

#define SOCK_BASE 0x1000u
#define INVALID_SOCKET 0xFFFFFFFFu
#define SOCKET_ERROR   0xFFFFFFFFu
#define WSAEWOULDBLOCK   10035u
#define WSAEAFNOSUPPORT  10047u
#define WSAENOTSOCK      10038u
#define WSAEINVAL        10022u
#define WSAEADDRINUSE    10048u
#define WSAECONNRESET    10054u
#define WSAHOST_NOT_FOUND 11001u
#define FD_READ  0x01u
#define FD_WRITE 0x02u

static __thread uint32_t g_wsa_error;

static uint32_t wsa_errno(int e) {
    switch (e) {
    case EWOULDBLOCK: return WSAEWOULDBLOCK;
    case EADDRINUSE:  return WSAEADDRINUSE;
    case EINVAL:      return WSAEINVAL;
    case EBADF: case ENOTSOCK: return WSAENOTSOCK;
    case ECONNRESET: case ECONNREFUSED: return WSAECONNRESET;
    case EAFNOSUPPORT: return WSAEAFNOSUPPORT;
    default: return 10000u + (uint32_t)e;
    }
}
static int fd_of(uint32_t s) { return s >= SOCK_BASE && s < SOCK_BASE + 0x10000u ? (int)(s - SOCK_BASE) : -1; }
#define FAIL(n) do { g_wsa_error = wsa_errno(errno); RET(SOCKET_ERROR, n); } while (0)

/* sockaddr_in is laid out the same on both (family is a little-endian u16). */
static void to_host(const uint8_t *g, struct sockaddr_in *h) {
    memset(h, 0, sizeof *h);
    h->sin_family = AF_INET;
    memcpy(&h->sin_port, g + 2, 2);
    memcpy(&h->sin_addr, g + 4, 4);
}
static void to_guest(const struct sockaddr_in *h, uint8_t *g) {
    memset(g, 0, 16);
    g[0] = 2;
    memcpy(g + 2, &h->sin_port, 2);
    memcpy(g + 4, &h->sin_addr, 4);
}

static void w_WSAStartup(void) {                         /* (version, &WSADATA) */
    uint8_t *d = (uint8_t *)APTR(1);
    if (d) {
        memset(d, 0, 400);
        d[0] = 1, d[1] = 1, d[2] = 2, d[3] = 2;          /* wVersion 1.1, wHighVersion 2.2 */
        strcpy((char *)d + 4, "win32hle Winsock");
        strcpy((char *)d + 4 + 257, "Running");
        *(uint16_t *)(d + 4 + 257 + 129) = 100;          /* iMaxSockets */
        *(uint16_t *)(d + 4 + 257 + 129 + 2) = 65467;    /* iMaxUdpDg */
    }
    RET(0, 2);
}
static void w_WSACleanup(void)     { RET(0, 0); }
static void w_WSAGetLastError(void){ RET(g_wsa_error, 0); }
static void w_WSASetLastError(void){ g_wsa_error = A32(0); RETV(1); }

static void w_socket(void) {                             /* (af, type, protocol) */
    int af = (int)A32(0), type = (int)A32(1), proto = (int)A32(2);
    if (af != AF_INET) {
        fprintf(stderr, "[wsock32] socket(af %d): only AF_INET here (no IPX)\n", af);
        g_wsa_error = WSAEAFNOSUPPORT;
        RET(INVALID_SOCKET, 3);
    }
    int fd = socket(AF_INET, type == 2 ? SOCK_DGRAM : SOCK_STREAM, proto);
    if (fd < 0) { g_wsa_error = wsa_errno(errno); RET(INVALID_SOCKET, 3); }
    RET(SOCK_BASE + (uint32_t)fd, 3);
}
static void w_closesocket(void) {
    int fd = fd_of(A32(0));
    if (fd < 0 || close(fd) != 0) { g_wsa_error = WSAENOTSOCK; RET(SOCKET_ERROR, 1); }
    RET(0, 1);
}
static void w_bind(void) {                               /* (s, addr, len) */
    struct sockaddr_in a;
    to_host((const uint8_t *)APTR(1), &a);
    if (bind(fd_of(A32(0)), (struct sockaddr *)&a, sizeof a) != 0) FAIL(3);
    RET(0, 3);
}
static void w_connect(void) {
    struct sockaddr_in a;
    to_host((const uint8_t *)APTR(1), &a);
    if (connect(fd_of(A32(0)), (struct sockaddr *)&a, sizeof a) != 0) FAIL(3);
    RET(0, 3);
}
static void w_listen(void) { if (listen(fd_of(A32(0)), (int)A32(1)) != 0) FAIL(2); RET(0, 2); }
static void w_sendto(void) {                             /* (s, buf, len, flags, to, tolen) */
    struct sockaddr_in a;
    ssize_t n;
    if (A32(4)) { to_host((const uint8_t *)APTR(4), &a); n = sendto(fd_of(A32(0)), APTR(1), A32(2), MSG_NOSIGNAL, (struct sockaddr *)&a, sizeof a); }
    else n = send(fd_of(A32(0)), APTR(1), A32(2), MSG_NOSIGNAL);
    if (n < 0) FAIL(6);
    RET((uint32_t)n, 6);
}
static void w_send(void) { ssize_t n = send(fd_of(A32(0)), APTR(1), A32(2), MSG_NOSIGNAL); if (n < 0) FAIL(4); RET((uint32_t)n, 4); }
static void w_recvfrom(void) {                           /* (s, buf, len, flags, from, &fromlen) */
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    ssize_t n = recvfrom(fd_of(A32(0)), APTR(1), A32(2), MSG_DONTWAIT, (struct sockaddr *)&a, &al);
    if (n < 0) FAIL(6);
    if (A32(4)) to_guest(&a, (uint8_t *)APTR(4));
    if (A32(5)) MEM32(A32(5)) = 16;
    RET((uint32_t)n, 6);
}
static void w_recv(void) { ssize_t n = recv(fd_of(A32(0)), APTR(1), A32(2), MSG_DONTWAIT); if (n < 0) FAIL(4); RET((uint32_t)n, 4); }

/* Socket options: SOL_SOCKET is 0xFFFF on Winsock, and its option numbers are
 * BSD's own (SO_BROADCAST 0x20, SO_REUSEADDR 4, SO_RCVBUF 0x1002, ...). */
static int host_opt(uint32_t level, uint32_t opt, int *hl, int *ho) {
    if (level != 0xFFFFu) { *hl = (int)level, *ho = (int)opt; return 1; }
    *hl = SOL_SOCKET;
    switch (opt) {
    case 0x0004: *ho = SO_REUSEADDR; return 1;
    case 0x0020: *ho = SO_BROADCAST; return 1;
    case 0x1001: *ho = SO_SNDBUF; return 1;
    case 0x1002: *ho = SO_RCVBUF; return 1;
    case 0x1008: *ho = SO_TYPE; return 1;
    case 0x1007: *ho = SO_ERROR; return 1;
    default: return 0;
    }
}
static void w_setsockopt(void) {                         /* (s, level, opt, val, len) */
    int hl, ho, v = A32(3) ? (int)MEM32(A32(3)) : 0;
    if (!host_opt(A32(1), A32(2), &hl, &ho)) RET(0, 5);  /* an option a host lacks: accepted */
    if (setsockopt(fd_of(A32(0)), hl, ho, &v, sizeof v) != 0) FAIL(5);
    RET(0, 5);
}
static void w_getsockopt(void) {                         /* (s, level, opt, val, &len) */
    int hl, ho, v = 0;
    socklen_t l = sizeof v;
    if (host_opt(A32(1), A32(2), &hl, &ho) && getsockopt(fd_of(A32(0)), hl, ho, &v, &l) != 0) FAIL(5);
    if (A32(2) == 0x1008 && v == SOCK_DGRAM) v = 2;
    if (A32(3)) MEM32(A32(3)) = (uint32_t)v;
    if (A32(4)) MEM32(A32(4)) = 4;
    RET(0, 5);
}
static void w_ioctlsocket(void) {                        /* (s, cmd, &arg) */
    int fd = fd_of(A32(0));
    uint32_t cmd = A32(1);
    if (cmd == 0x8004667Eu) {                            /* FIONBIO */
        int fl = fcntl(fd, F_GETFL);
        fcntl(fd, F_SETFL, MEM32(A32(2)) ? fl | O_NONBLOCK : fl & ~O_NONBLOCK);
        RET(0, 3);
    }
    if (cmd == 0x4004667Fu) {                            /* FIONREAD */
        int n = 0;
        ioctl(fd, FIONREAD, &n);
        MEM32(A32(2)) = (uint32_t)n;
        RET(0, 3);
    }
    g_wsa_error = WSAEINVAL;
    RET(SOCKET_ERROR, 3);
}
static void w_getsockname(void) {
    struct sockaddr_in a;
    socklen_t l = sizeof a;
    if (getsockname(fd_of(A32(0)), (struct sockaddr *)&a, &l) != 0) FAIL(3);
    to_guest(&a, (uint8_t *)APTR(1));
    if (A32(2)) MEM32(A32(2)) = 16;
    RET(0, 3);
}

static void w_htonl(void) { RET(htonl(A32(0)), 1); }
static void w_htons(void) { RET(htons((uint16_t)A32(0)), 1); }
static void w_ntohl(void) { RET(ntohl(A32(0)), 1); }
static void w_ntohs(void) { RET(ntohs((uint16_t)A32(0)), 1); }
static void w_inet_addr(void) { RET(ASTR(0) ? inet_addr(ASTR(0)) : 0xFFFFFFFFu, 1); }
static void w_inet_ntoa(void) {                          /* (in_addr by value) */
    static __thread char buf[16];
    uint32_t a = A32(0);
    snprintf(buf, sizeof buf, "%u.%u.%u.%u", a & 255, (a >> 8) & 255, (a >> 16) & 255, a >> 24);
    RETP(buf, 1);
}
static void w_gethostname(void) {
    if (gethostname(ASTR(0), A32(1)) != 0) FAIL(2);
    RET(0, 2);
}
/* hostent, in guest-readable memory: name, aliases, addrtype(2), length(2),
 * addr_list. One per thread, as Winsock's is. */
static void w_gethostbyname(void) {
    static __thread struct { uint32_t name, aliases; uint16_t type, len; uint32_t list; uint32_t lp[9]; uint32_t addr[8]; uint32_t none; char nm[256]; } he;
    struct hostent *h = ASTR(0) ? gethostbyname(ASTR(0)) : NULL;
    if (!h || h->h_addrtype != AF_INET) { g_wsa_error = WSAHOST_NOT_FOUND; RET(0, 1); }
    memset(&he, 0, sizeof he);
    snprintf(he.nm, sizeof he.nm, "%s", h->h_name);
    he.name = (uint32_t)(uintptr_t)he.nm;
    he.aliases = (uint32_t)(uintptr_t)&he.none;
    he.type = 2, he.len = 4;
    he.list = (uint32_t)(uintptr_t)he.lp;
    for (int i = 0; i < 8 && h->h_addr_list[i]; i++) {
        memcpy(&he.addr[i], h->h_addr_list[i], 4);
        he.lp[i] = (uint32_t)(uintptr_t)&he.addr[i];
    }
    RETP(&he, 1);
}

/* ---- WSAAsyncSelect ---- */
#define MAX_ASYNC 32
static struct { uint32_t s, hwnd, msg, events; } g_async[MAX_ASYNC];

static void w_WSAAsyncSelect(void) {                     /* (s, hwnd, msg, events) */
    uint32_t s = A32(0);
    int fd = fd_of(s), slot = -1;
    if (fd < 0) { g_wsa_error = WSAENOTSOCK; RET(SOCKET_ERROR, 4); }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    for (int i = 0; i < MAX_ASYNC; i++) if (g_async[i].s == s || (!g_async[i].s && slot < 0)) { slot = i; if (g_async[i].s == s) break; }
    if (slot < 0) { g_wsa_error = WSAEINVAL; RET(SOCKET_ERROR, 4); }
    g_async[slot].s = A32(3) ? s : 0;
    g_async[slot].hwnd = A32(1), g_async[slot].msg = A32(2), g_async[slot].events = A32(3);
    RET(0, 4);
}
static void w_WSACancelAsyncRequest(void) { g_wsa_error = WSAEINVAL; RET(SOCKET_ERROR, 1); }

/* From the message pump: a readable socket posts its message (once per
 * poll, as level-triggered FD_READ re-posts after each recv). */
void hle_ws_poll(void) {
    for (int i = 0; i < MAX_ASYNC; i++) {
        if (!g_async[i].s || !(g_async[i].events & FD_READ)) continue;
        struct pollfd p = { fd_of(g_async[i].s), POLLIN, 0 };
        if (poll(&p, 1, 0) == 1 && (p.revents & POLLIN))
            hle_post_message(g_async[i].hwnd, g_async[i].msg, g_async[i].s, FD_READ);
    }
}

#define SHIM2(ord, name, fn) { "wsock32.dll#" #ord, fn }, { name, fn }
const win32hle_shim win32hle_wsock32[] = {
    SHIM2(2, "bind", w_bind),
    SHIM2(3, "closesocket", w_closesocket),
    SHIM2(4, "connect", w_connect),
    SHIM2(6, "getsockname", w_getsockname),
    SHIM2(7, "getsockopt", w_getsockopt),
    SHIM2(8, "htonl", w_htonl),
    SHIM2(9, "htons", w_htons),
    SHIM2(10, "inet_addr", w_inet_addr),
    SHIM2(11, "inet_ntoa", w_inet_ntoa),
    SHIM2(12, "ioctlsocket", w_ioctlsocket),
    SHIM2(13, "listen", w_listen),
    SHIM2(14, "ntohl", w_ntohl),
    SHIM2(15, "ntohs", w_ntohs),
    SHIM2(16, "recv", w_recv),
    SHIM2(17, "recvfrom", w_recvfrom),
    SHIM2(19, "send", w_send),
    SHIM2(20, "sendto", w_sendto),
    SHIM2(21, "setsockopt", w_setsockopt),
    SHIM2(23, "socket", w_socket),
    SHIM2(52, "gethostbyname", w_gethostbyname),
    SHIM2(57, "gethostname", w_gethostname),
    SHIM2(101, "WSAAsyncSelect", w_WSAAsyncSelect),
    SHIM2(108, "WSACancelAsyncRequest", w_WSACancelAsyncRequest),
    SHIM2(111, "WSAGetLastError", w_WSAGetLastError),
    SHIM2(112, "WSASetLastError", w_WSASetLastError),
    SHIM2(115, "WSAStartup", w_WSAStartup),
    SHIM2(116, "WSACleanup", w_WSACleanup),
    { 0, 0 }
};
