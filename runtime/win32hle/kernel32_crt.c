/*
 * kernel32_crt.c - the KERNEL32 imports an MSVC C runtime calls on its way from
 * the PE entry point to WinMain and in its locale functions: std handles, the
 * ANSI codepage and locale queries, the environment block, MultiByte/WideChar
 * conversion, the SEH hooks, and threads. Surfaced by running real titles
 * under the permissive host (Fury³ first, then Tiberian Sun).
 *
 * The wide-character locale calls (LCMapStringW, GetStringTypeW, ...) fail
 * with ERROR_CALL_NOT_IMPLEMENTED, as on Windows 95: an MSVC CRT then takes
 * its ANSI paths, which are implemented here for codepage 1252.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include "win32hle.h"

#define ERROR_INSUFFICIENT_BUFFER  122u
#define ERROR_CALL_NOT_IMPLEMENTED 120u
#define ERROR_INVALID_PARAMETER     87u

/* --- threads ---
 * A guest thread runs lifted code, so it enters through hle_call_guest, which
 * takes the machine and gives the thread its own guest stack + TIB. The lifted
 * start routine is stdcall with one argument (lpParameter). */
struct thread_arg { uint32_t start, param; };
static void *thread_trampoline(void *p) {
    struct thread_arg a = *(struct thread_arg *)p; free(p);
    uint32_t args[1] = { a.param };
    hle_call_guest(a.start, 1, args);
    return NULL;
}
static void k_CreateThread(void) {             /* (sa, stack, start, param, flags, &tid) */
    struct thread_arg *a = (struct thread_arg *)malloc(sizeof *a);
    a->start = A32(2); a->param = A32(3);
    pthread_t t;
    if (pthread_create(&t, NULL, thread_trampoline, a) != 0) { free(a); RET(0, 6); }
    pthread_detach(t);
    uint32_t tid = (uint32_t)(uintptr_t)t;
    uint32_t ptid = A32(5); if (ptid) MEM32(ptid) = tid;
    RET(hle_handle_alloc(HLE_H_THREAD, NULL), 6);
}
static void k_SetThreadPriority(void) { RET(1, 2); }
static void k_GetThreadPriority(void) { RET(0, 1); }
static void k_GetCurrentThread(void)  { RET(0xFFFFFFFEu, 0); }

/* --- standard handles --- */
static void k_GetStdHandle(void) {                 /* (nStdHandle) -10..-12 */
    uint32_t n = A32(0);
    RET(n == 0xFFFFFFF6u ? 0x11u : n == 0xFFFFFFF5u ? 0x12u : 0x13u, 1); /* IN/OUT/ERR */
}
static void k_SetStdHandle(void) { RET(1, 2); }
static void k_SetHandleCount(void){ RET(A32(0), 1); }

/* --- codepages --- */
static void k_GetACP(void)  { RET(1252u, 0); }     /* Windows-1252 */
static void k_GetOEMCP(void){ RET(437u, 0); }
static void k_IsValidCodePage(void) { uint32_t cp = A32(0); RET(cp == 1252u || cp == 437u || cp == 0u || cp == 1u, 1); }
static void k_GetCPInfo(void) {                    /* (cp, &CPINFO) */
    uint8_t *ci = (uint8_t *)APTR(1);
    if (ci) { memset(ci, 0, 20); *(uint32_t *)ci = 1; ci[4] = (uint8_t)'?'; } /* MaxCharSize=1, DefaultChar='?' */
    RET(1, 2);
}

/* Character types of Windows-1252 (CT_CTYPE1). */
#define C1_UPPER 0x01u
#define C1_LOWER 0x02u
#define C1_DIGIT 0x04u
#define C1_SPACE 0x08u
#define C1_PUNCT 0x10u
#define C1_CNTRL 0x20u
#define C1_BLANK 0x40u
#define C1_XDIGIT 0x80u
#define C1_ALPHA 0x100u
static uint16_t ctype1(uint8_t c) {
    uint16_t t = 0;
    if (c < 0x20 || c == 0x7F) t |= C1_CNTRL;
    if (c == ' ' || c == '\t') t |= C1_BLANK;
    if ((c >= 9 && c <= 13) || c == ' ') t |= C1_SPACE;
    if (c >= '0' && c <= '9') t |= C1_DIGIT | C1_XDIGIT;
    if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) t |= C1_XDIGIT;
    if ((c >= 'A' && c <= 'Z') || (c >= 0xC0 && c <= 0xDE && c != 0xD7) || c == 0x8A || c == 0x8C || c == 0x8E || c == 0x9F)
        t |= C1_UPPER | C1_ALPHA;
    else if ((c >= 'a' && c <= 'z') || (c >= 0xDF && c != 0xF7) || c == 0x9A || c == 0x9C || c == 0x9E || c == 0x83 || c == 0xAA || c == 0xB5 || c == 0xBA)
        t |= C1_LOWER | C1_ALPHA;
    else if (c > 0x20 && c != 0x7F && !(t & C1_DIGIT) && c != 0x81 && c != 0x8D && c != 0x8F && c != 0x90 && c != 0x9D)
        t |= C1_PUNCT;
    if (c == 0xA0) t = C1_SPACE | C1_BLANK;
    return t;
}
static uint8_t lower1252(uint8_t c) {
    if (c >= 'A' && c <= 'Z') return (uint8_t)(c + 32);
    if (c >= 0xC0 && c <= 0xDE && c != 0xD7) return (uint8_t)(c + 32);
    if (c == 0x8A || c == 0x8C || c == 0x8E) return (uint8_t)(c + 16);
    if (c == 0x9F) return 0xFF;
    return c;
}
static uint8_t upper1252(uint8_t c) {
    if (c >= 'a' && c <= 'z') return (uint8_t)(c - 32);
    if (c >= 0xE0 && c <= 0xFE && c != 0xF7) return (uint8_t)(c - 32);
    if (c == 0x9A || c == 0x9C || c == 0x9E) return (uint8_t)(c - 16);
    if (c == 0xFF) return 0x9F;
    return c;
}

/* GetStringTypeA(lcid, type, src, n, out) */
static void k_GetStringTypeA(void) {
    uint32_t type = A32(1);
    const uint8_t *src = (const uint8_t *)APTR(2);
    int n = (int)A32(3);
    uint16_t *out = (uint16_t *)APTR(4);
    if (!src || !out) { hle_set_last_error(ERROR_INVALID_PARAMETER); RET(0, 5); }
    if (n < 0) n = (int)strlen((const char *)src) + 1;
    for (int i = 0; i < n; i++) out[i] = type == 1 ? ctype1(src[i]) : 0;
    RET(1, 5);
}
static void k_GetStringTypeExA(void) {             /* (lcid, type, src, n, out): same as A */
    uint32_t type = A32(1);
    const uint8_t *src = (const uint8_t *)APTR(2);
    int n = (int)A32(3);
    uint16_t *out = (uint16_t *)APTR(4);
    if (n < 0) n = (int)strlen((const char *)src) + 1;
    for (int i = 0; i < n; i++) out[i] = type == 1 ? ctype1(src[i]) : 0;
    RET(1, 5);
}
static void k_not_implemented_4(void) { hle_set_last_error(ERROR_CALL_NOT_IMPLEMENTED); RET(0, 4); }
static void k_not_implemented_6(void) { hle_set_last_error(ERROR_CALL_NOT_IMPLEMENTED); RET(0, 6); }

/* LCMapStringA(lcid, flags, src, srcN, dst, dstN): case mapping; a sort key
 * (LCMAP_SORTKEY) is the upper-cased string, which orders the same for
 * ASCII. */
static void k_LCMapStringA(void) {
    uint32_t fl = A32(1);
    const uint8_t *src = (const uint8_t *)APTR(2);
    int n = (int)A32(3), dn = (int)A32(5);
    uint8_t *dst = (uint8_t *)APTR(4);
    if (!src) { hle_set_last_error(ERROR_INVALID_PARAMETER); RET(0, 6); }
    if (n < 0) n = (int)strlen((const char *)src) + 1;
    if (!dn) RET((uint32_t)n, 6);
    if (dn < n) { hle_set_last_error(ERROR_INSUFFICIENT_BUFFER); RET(0, 6); }
    for (int i = 0; i < n; i++)
        dst[i] = fl & 0x100u ? lower1252(src[i]) : (fl & 0x600u) ? upper1252(src[i]) : src[i];
    RET((uint32_t)n, 6);
}
/* CompareStringA(lcid, flags, a, an, b, bn) -> 1 less, 2 equal, 3 greater */
static void k_CompareStringA(void) {
    uint32_t fl = A32(1);
    const uint8_t *a = (const uint8_t *)APTR(2), *b = (const uint8_t *)APTR(4);
    int an = (int)A32(3), bn = (int)A32(5);
    if (an < 0) an = (int)strlen((const char *)a);
    if (bn < 0) bn = (int)strlen((const char *)b);
    int i = 0;
    for (; i < an && i < bn; i++) {
        int x = fl & 1u ? lower1252(a[i]) : a[i], y = fl & 1u ? lower1252(b[i]) : b[i];
        if (x != y) RET(x < y ? 1u : 3u, 6);
    }
    RET(an < bn ? 1u : an > bn ? 3u : 2u, 6);
}

/* --- locale: English (United States) --- */
static const char *const g_day[] = { "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday" };
static const char *const g_mon[] = { "January", "February", "March", "April", "May", "June", "July", "August",
                                     "September", "October", "November", "December" };
static const char *locale_info(uint32_t t, char *tmp) {
    t &= 0x0FFFFFFFu;                                   /* NOUSEROVERRIDE, RETURN_NUMBER */
    if (t >= 0x2A && t <= 0x30) return g_day[t - 0x2A];
    if (t >= 0x31 && t <= 0x37) { snprintf(tmp, 8, "%.3s", g_day[t - 0x31]); return tmp; }
    if (t >= 0x38 && t <= 0x43) return g_mon[t - 0x38];
    if (t >= 0x44 && t <= 0x4F) { snprintf(tmp, 8, "%.3s", g_mon[t - 0x44]); return tmp; }
    switch (t) {
    case 0x01: return "0409";                 /* ILANGUAGE */
    case 0x02: return "English";              /* SLANGUAGE */
    case 0x03: return "ENU";                  /* SABBREVLANGNAME */
    case 0x04: return "English";              /* SNATIVELANGNAME */
    case 0x05: return "1";                    /* ICOUNTRY */
    case 0x06: return "United States";        /* SCOUNTRY */
    case 0x07: return "USA";                  /* SABBREVCTRYNAME */
    case 0x08: return "United States";        /* SNATIVECTRYNAME */
    case 0x09: return "0409";                 /* IDEFAULTLANGUAGE */
    case 0x0A: return "1";                    /* IDEFAULTCOUNTRY */
    case 0x0B: return "437";                  /* IDEFAULTCODEPAGE */
    case 0x0C: return ",";                    /* SLIST */
    case 0x0D: return "1";                    /* IMEASURE */
    case 0x0E: return ".";                    /* SDECIMAL */
    case 0x0F: return ",";                    /* STHOUSAND */
    case 0x10: return "3;0";                  /* SGROUPING */
    case 0x11: return "2";                    /* IDIGITS */
    case 0x12: return "1";                    /* ILZERO */
    case 0x14: return "$";                    /* SCURRENCY */
    case 0x15: return "USD";                  /* SINTLSYMBOL */
    case 0x16: return ".";                    /* SMONDECIMALSEP */
    case 0x17: return ",";                    /* SMONTHOUSANDSEP */
    case 0x18: return "3;0";                  /* SMONGROUPING */
    case 0x19: return "2";                    /* ICURRDIGITS */
    case 0x1A: return "2";                    /* IINTLCURRDIGITS */
    case 0x1B: return "0";                    /* ICURRENCY */
    case 0x1C: return "0";                    /* INEGCURR */
    case 0x1D: return "/";                    /* SDATE */
    case 0x1E: return ":";                    /* STIME */
    case 0x1F: return "M/d/yyyy";             /* SSHORTDATE */
    case 0x20: return "dddd, MMMM dd, yyyy";  /* SLONGDATE */
    case 0x21: return "0";                    /* IDATE */
    case 0x22: return "0";                    /* ILDATE */
    case 0x23: return "0";                    /* ITIME: 12-hour */
    case 0x24: return "0";                    /* ICENTURY */
    case 0x25: return "0";                    /* ITLZERO */
    case 0x26: return "0";                    /* IDAYLZERO */
    case 0x27: return "0";                    /* IMONLZERO */
    case 0x28: return "AM";                   /* S1159 */
    case 0x29: return "PM";                   /* S2359 */
    case 0x50: return "";                     /* SPOSITIVESIGN */
    case 0x51: return "-";                    /* SNEGATIVESIGN */
    case 0x1001: return "English";            /* SENGLANGUAGE */
    case 0x1002: return "United States";      /* SENGCOUNTRY */
    case 0x1003: return "h:mm:ss tt";         /* STIMEFORMAT */
    case 0x1004: return "1252";               /* IDEFAULTANSICODEPAGE */
    case 0x1009: return "1";                  /* IDEFAULTEBCDICCODEPAGE.. near enough */
    case 0x100C: return "0";                  /* IFIRSTDAYOFWEEK */
    case 0x59: return "en";                   /* SISO639LANGNAME */
    case 0x5A: return "US";                   /* SISO3166CTRYNAME */
    default: return NULL;
    }
}
static void k_GetLocaleInfoA(void) {               /* (lcid, type, buf, n) */
    char tmp[16];
    const char *v = locale_info(A32(1), tmp);
    char *buf = ASTR(2);
    int n = (int)A32(3), len;
    if (!v) { hle_set_last_error(ERROR_INVALID_PARAMETER); RET(0, 4); }
    len = (int)strlen(v) + 1;
    if (A32(1) & 0x20000000u) {                    /* LOCALE_RETURN_NUMBER: a DWORD */
        if (n < 4) RET(2, 4);
        MEM32(A32(2)) = (uint32_t)strtoul(v, NULL, 10);
        RET(2, 4);
    }
    if (!n) RET((uint32_t)len, 4);
    if (n < len) { hle_set_last_error(ERROR_INSUFFICIENT_BUFFER); RET(0, 4); }
    memcpy(buf, v, (size_t)len);
    RET((uint32_t)len, 4);
}
static void k_GetUserDefaultLCID(void)   { RET(0x0409u, 0); }
static void k_GetSystemDefaultLCID(void) { RET(0x0409u, 0); }
static void k_GetUserDefaultLangID(void) { RET(0x0409u, 0); }
static void k_GetThreadLocale(void)      { RET(0x0409u, 0); }
static void k_IsValidLocale(void)        { RET(A32(0) == 0x0409u || A32(0) == 0x0400u || A32(0) == 0x0800u ? 1u : 0u, 2); }
/* EnumSystemLocalesA(proc, flags): the one locale, to the guest's callback. */
static void k_EnumSystemLocalesA(void) {
    static char loc[] = "00000409";
    uint32_t a[1] = { (uint32_t)(uintptr_t)loc };
    if (A32(0)) hle_call_guest(A32(0), 1, a);
    RET(1, 2);
}

/* GetDateFormatA / GetTimeFormatA (lcid, flags, &SYSTEMTIME or NULL, fmt, buf, n):
 * the picture strings a game passes (or the locale's default). */
static int fmt_picture(const char *f, const uint16_t *st, char *out, int cap) {
    int k = 0;
    while (*f && k < cap - 1) {
        char c = *f;
        int run = 1;
        while (f[run] == c) run++;
        char tmp[64] = "";
        if (c == '\'') {                                /* quoted literal */
            const char *e = strchr(f + 1, '\'');
            int l = e ? (int)(e - f - 1) : (int)strlen(f + 1);
            snprintf(tmp, sizeof tmp, "%.*s", l, f + 1);
            run = l + (e ? 2 : 1);
        } else if (c == 'y') snprintf(tmp, sizeof tmp, run >= 3 ? "%04u" : "%02u", run >= 3 ? st[0] : st[0] % 100);
        else if (c == 'M') {
            if (run >= 4) snprintf(tmp, sizeof tmp, "%s", g_mon[(st[1] + 11) % 12]);
            else if (run == 3) snprintf(tmp, sizeof tmp, "%.3s", g_mon[(st[1] + 11) % 12]);
            else snprintf(tmp, sizeof tmp, run == 2 ? "%02u" : "%u", st[1]);
        } else if (c == 'd') {
            if (run >= 4) snprintf(tmp, sizeof tmp, "%s", g_day[(st[2] + 6) % 7]);
            else if (run == 3) snprintf(tmp, sizeof tmp, "%.3s", g_day[(st[2] + 6) % 7]);
            else snprintf(tmp, sizeof tmp, run == 2 ? "%02u" : "%u", st[3]);
        } else if (c == 'h') snprintf(tmp, sizeof tmp, run == 2 ? "%02u" : "%u", st[4] % 12 ? st[4] % 12 : 12);
        else if (c == 'H') snprintf(tmp, sizeof tmp, run == 2 ? "%02u" : "%u", st[4]);
        else if (c == 'm') snprintf(tmp, sizeof tmp, run == 2 ? "%02u" : "%u", st[5]);
        else if (c == 's') snprintf(tmp, sizeof tmp, run == 2 ? "%02u" : "%u", st[6]);
        else if (c == 't') snprintf(tmp, sizeof tmp, "%.*s", run == 1 ? 1 : 2, st[4] < 12 ? "AM" : "PM");
        else snprintf(tmp, sizeof tmp, "%.*s", run, f);
        for (const char *t = tmp; *t && k < cap - 1; t++) out[k++] = *t;
        f += run;
    }
    out[k] = 0;
    return k + 1;
}
static void now_systemtime(uint16_t *st) {
    time_t s = time(NULL);
    struct tm t;
    localtime_r(&s, &t);
    st[0] = (uint16_t)(t.tm_year + 1900), st[1] = (uint16_t)(t.tm_mon + 1), st[2] = (uint16_t)t.tm_wday;
    st[3] = (uint16_t)t.tm_mday, st[4] = (uint16_t)t.tm_hour, st[5] = (uint16_t)t.tm_min, st[6] = (uint16_t)t.tm_sec, st[7] = 0;
}
static void date_or_time(int is_time) {
    uint16_t now[8];
    const uint16_t *st = (const uint16_t *)APTR(2);
    if (!st) now_systemtime(now), st = now;
    const char *fmt = ASTR(3);
    if (!fmt) fmt = is_time ? "h:mm:ss tt" : (A32(1) & 2u) ? "dddd, MMMM dd, yyyy" : "M/d/yyyy";
    char out[256];
    int len = fmt_picture(fmt, st, out, sizeof out);
    int n = (int)A32(5);
    if (!n) RET((uint32_t)len, 6);
    if (n < len) { hle_set_last_error(ERROR_INSUFFICIENT_BUFFER); RET(0, 6); }
    memcpy(ASTR(4), out, (size_t)len);
    RET((uint32_t)len, 6);
}
static void k_GetDateFormatA(void) { date_or_time(0); }
static void k_GetTimeFormatA(void) { date_or_time(1); }

/* --- environment: the host's, filtered to nothing a game would misread --- */
static char g_env[4096] = "PATH=C:\\WINDOWS\\SYSTEM32;C:\\WINDOWS\0WINDIR=C:\\WINDOWS\0\0";
static size_t env_len(void) { size_t k = 0; while (g_env[k]) k += strlen(g_env + k) + 1; return k + 1; }
static void k_GetEnvironmentStrings(void)   { RETP(g_env, 0); }
static void k_GetEnvironmentStringsW(void)  { hle_set_last_error(ERROR_CALL_NOT_IMPLEMENTED); RET(0, 0); }
static void k_FreeEnvironmentStringsA(void) { RET(1, 1); }
static void k_FreeEnvironmentStringsW(void) { RET(1, 1); }
static void k_GetEnvironmentVariableA(void) {      /* (name, buf, n) */
    const char *name = ASTR(0);
    size_t nl = name ? strlen(name) : 0;
    for (size_t k = 0; name && g_env[k]; k += strlen(g_env + k) + 1)
        if (!strncasecmp(g_env + k, name, nl) && g_env[k + nl] == '=') {
            const char *v = g_env + k + nl + 1;
            uint32_t len = (uint32_t)strlen(v);
            if (len + 1 > A32(2)) RET(len + 1, 3);
            memcpy(ASTR(1), v, len + 1);
            RET(len, 3);
        }
    hle_set_last_error(203u);                       /* ERROR_ENVVAR_NOT_FOUND */
    RET(0, 3);
}
static void k_SetEnvironmentVariableA(void) {      /* (name, value or NULL) */
    const char *name = ASTR(0), *val = ASTR(1);
    char rebuilt[sizeof g_env];
    size_t o = 0, nl = name ? strlen(name) : 0;
    for (size_t k = 0; g_env[k]; k += strlen(g_env + k) + 1)
        if (!(name && !strncasecmp(g_env + k, name, nl) && g_env[k + nl] == '=')) {
            size_t l = strlen(g_env + k) + 1;
            memcpy(rebuilt + o, g_env + k, l), o += l;
        }
    if (name && val && o + nl + strlen(val) + 3 < sizeof rebuilt)
        o += (size_t)sprintf(rebuilt + o, "%s=%s", name, val) + 1;
    rebuilt[o] = 0;
    memcpy(g_env, rebuilt, o + 1);
    (void)env_len;
    RET(1, 2);
}

/* --- unicode conversion: Windows-1252 is Latin-1 plus 0x80..0x9F --- */
static const uint16_t g_cp1252_hi[32] = {
    0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
    0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178 };
static uint16_t to_wide(uint8_t c) { return c >= 0x80 && c < 0xA0 ? g_cp1252_hi[c - 0x80] : c; }
static int to_narrow(uint16_t w) {
    if (w < 0x80 || (w >= 0xA0 && w < 0x100)) return w;
    for (int i = 0; i < 32; i++) if (g_cp1252_hi[i] == w) return 0x80 + i;
    return -1;
}
static void k_MultiByteToWideChar(void) {          /* (cp,fl,src,srcN,dst,dstN) */
    const uint8_t *src = (const uint8_t *)APTR(2);
    int srcN = (int)A32(3), dstN = (int)A32(5);
    uint16_t *dst = (uint16_t *)APTR(4);
    if (!src) { hle_set_last_error(ERROR_INVALID_PARAMETER); RET(0, 6); }
    int n = srcN < 0 ? (int)strlen((const char *)src) + 1 : srcN;
    if (!dstN) RET((uint32_t)n, 6);
    if (dstN < n) { hle_set_last_error(ERROR_INSUFFICIENT_BUFFER); RET(0, 6); }
    for (int i = 0; i < n; i++) dst[i] = to_wide(src[i]);
    RET((uint32_t)n, 6);
}
static void k_WideCharToMultiByte(void) {          /* (cp,fl,src,srcN,dst,dstN,defChar,&usedDef) */
    const uint16_t *src = (const uint16_t *)APTR(2);
    int srcN = (int)A32(3), dstN = (int)A32(5);
    uint8_t *dst = (uint8_t *)APTR(4);
    if (!src) { hle_set_last_error(ERROR_INVALID_PARAMETER); RET(0, 8); }
    int n = 0;
    if (srcN < 0) { while (src[n]) n++; n++; } else n = srcN;
    if (!dstN) RET((uint32_t)n, 8);
    if (dstN < n) { hle_set_last_error(ERROR_INSUFFICIENT_BUFFER); RET(0, 8); }
    int used = 0;
    for (int i = 0; i < n; i++) {
        int c = to_narrow(src[i]);
        if (c < 0) c = A32(6) ? *(const uint8_t *)APTR(6) : '?', used = 1;
        dst[i] = (uint8_t)c;
    }
    if (A32(7)) MEM32(A32(7)) = (uint32_t)used;
    RET((uint32_t)n, 8);
}

/* --- system info --- */
static void k_GlobalMemoryStatus(void) {           /* (&MEMORYSTATUS) 32 bytes */
    uint8_t *m = (uint8_t *)APTR(0);
    if (m) { memset(m, 0, 32); *(uint32_t *)m = 32; m[4] = 50;          /* dwLength, dwMemoryLoad */
             *(uint32_t *)(m + 8)  = 0x40000000u;                       /* dwTotalPhys = 1 GB */
             *(uint32_t *)(m + 12) = 0x20000000u;                       /* dwAvailPhys = 512 MB */
             *(uint32_t *)(m + 16) = 0x40000000u;                       /* page file */
             *(uint32_t *)(m + 20) = 0x20000000u;
             *(uint32_t *)(m + 24) = 0x7FFE0000u;                       /* user address space */
             *(uint32_t *)(m + 28) = 0x60000000u; }
    RETV(1);
}
static void k_GetSystemInfo(void) {                /* SYSTEM_INFO, 36 bytes */
    uint32_t s = A32(0);
    if (s) {
        memset((void *)(uintptr_t)s, 0, 36);
        MEM32(s + 4) = 0x1000u, MEM32(s + 8) = 0x10000u, MEM32(s + 12) = 0x7FFEFFFFu;
        MEM32(s + 16) = 1, MEM32(s + 20) = 1, MEM32(s + 24) = 586, MEM32(s + 28) = 0x10000u;
        MEM16(s + 32) = 6;
    }
    RETV(1);
}
static void k_GetLogicalDrives(void){ RET(0x4u | (1u << 25), 0); } /* C: and Z: */
static void k_GetWindowsDirectoryA(void) { snprintf(ASTR(0), A32(1), "C:\\WINDOWS"); RET(10, 2); }
static void k_GetSystemDirectoryA(void)  { snprintf(ASTR(0), A32(1), "C:\\WINDOWS\\SYSTEM32"); RET(19, 2); }
static void k_GetTempPathA(void) { snprintf(ASTR(1), A32(0), "C:\\WINDOWS\\TEMP\\"); RET(16, 2); }
static void k_GetComputerNameA(void) { if (A32(1) && MEM32(A32(1)) > 5) { strcpy(ASTR(0), "HLEPC"); MEM32(A32(1)) = 5; RET(1, 2); } RET(0, 2); }

/* --- SEH / error hooks: the startup installs these --- */
static void k_SetUnhandledExceptionFilter(void) { RET(0, 1); }
static void k_UnhandledExceptionFilter(void)    { RET(0, 1); }  /* EXCEPTION_CONTINUE_SEARCH */
static void k_RtlUnwind(void)      { RETV(4); }                 /* no guest SEH unwinding yet */
static void k_RaiseException(void) {
    fprintf(stderr, "[win32hle] RaiseException(0x%08X) from guest 0x%08X: guest exceptions are not handled\n",
            A32(0), g_cur_func);
    hle_exit(3);
}
static void k_LoadModule(void)    { RET(2u, 2); }               /* file not found */

const win32hle_shim win32hle_kernel32_crt[] = {
    { "GetStdHandle",                 k_GetStdHandle },
    { "SetStdHandle",                 k_SetStdHandle },
    { "SetHandleCount",               k_SetHandleCount },
    { "GetACP",                       k_GetACP },
    { "GetOEMCP",                     k_GetOEMCP },
    { "IsValidCodePage",              k_IsValidCodePage },
    { "GetCPInfo",                    k_GetCPInfo },
    { "GetStringTypeA",               k_GetStringTypeA },
    { "GetStringTypeExA",             k_GetStringTypeExA },
    { "GetStringTypeW",               k_not_implemented_4 },
    { "LCMapStringA",                 k_LCMapStringA },
    { "LCMapStringW",                 k_not_implemented_6 },
    { "CompareStringA",               k_CompareStringA },
    { "CompareStringW",               k_not_implemented_6 },
    { "GetLocaleInfoA",               k_GetLocaleInfoA },
    { "GetLocaleInfoW",               k_not_implemented_4 },
    { "GetUserDefaultLCID",           k_GetUserDefaultLCID },
    { "GetSystemDefaultLCID",         k_GetSystemDefaultLCID },
    { "GetUserDefaultLangID",         k_GetUserDefaultLangID },
    { "GetThreadLocale",              k_GetThreadLocale },
    { "IsValidLocale",                k_IsValidLocale },
    { "EnumSystemLocalesA",           k_EnumSystemLocalesA },
    { "GetDateFormatA",               k_GetDateFormatA },
    { "GetTimeFormatA",               k_GetTimeFormatA },
    { "GetEnvironmentStrings",        k_GetEnvironmentStrings },
    { "GetEnvironmentStringsA",       k_GetEnvironmentStrings },
    { "GetEnvironmentStringsW",       k_GetEnvironmentStringsW },
    { "FreeEnvironmentStringsA",      k_FreeEnvironmentStringsA },
    { "FreeEnvironmentStringsW",      k_FreeEnvironmentStringsW },
    { "GetEnvironmentVariableA",      k_GetEnvironmentVariableA },
    { "SetEnvironmentVariableA",      k_SetEnvironmentVariableA },
    { "MultiByteToWideChar",          k_MultiByteToWideChar },
    { "WideCharToMultiByte",          k_WideCharToMultiByte },
    { "GlobalMemoryStatus",           k_GlobalMemoryStatus },
    { "GetSystemInfo",                k_GetSystemInfo },
    { "GetLogicalDrives",             k_GetLogicalDrives },
    { "GetWindowsDirectoryA",         k_GetWindowsDirectoryA },
    { "GetSystemDirectoryA",          k_GetSystemDirectoryA },
    { "GetTempPathA",                 k_GetTempPathA },
    { "GetComputerNameA",             k_GetComputerNameA },
    { "SetUnhandledExceptionFilter",  k_SetUnhandledExceptionFilter },
    { "UnhandledExceptionFilter",     k_UnhandledExceptionFilter },
    { "RtlUnwind",                    k_RtlUnwind },
    { "RaiseException",               k_RaiseException },
    { "LoadModule",                   k_LoadModule },
    { "CreateThread",                 k_CreateThread },
    { "SetThreadPriority",            k_SetThreadPriority },
    { "GetThreadPriority",            k_GetThreadPriority },
    { "GetCurrentThread",             k_GetCurrentThread },
    { 0, 0 }
};
