/*
 * kernel32_ext.c - the KERNEL32 file system and .ini profile shims,
 * on POSIX. Files are file descriptors behind typed handles (host_lite.c);
 * paths go through hle_host_path, so a guest's `DATA\RULES.INI` finds
 * `data/rules.ini` on a case-sensitive disk. Also the directory search
 * (FindFirstFileA), attributes, and the FILETIME/SYSTEMTIME conversions a
 * C runtime's stat and time functions are built on.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include "win32hle.h"

#define INVALID_HANDLE  0xFFFFFFFFu
#define ERROR_FILE_NOT_FOUND    2u
#define ERROR_PATH_NOT_FOUND    3u
#define ERROR_ACCESS_DENIED     5u
#define ERROR_INVALID_HANDLE    6u
#define ERROR_NO_MORE_FILES    18u
#define ERROR_HANDLE_EOF       38u
#define ERROR_FILE_EXISTS      80u
#define ERROR_ALREADY_EXISTS  183u
#define ERROR_INVALID_FUNCTION  1u

#define FILE_ATTRIBUTE_READONLY  0x01u
#define FILE_ATTRIBUTE_DIRECTORY 0x10u
#define FILE_ATTRIBUTE_ARCHIVE   0x20u
#define FILE_ATTRIBUTE_NORMAL    0x80u

static uint32_t errno_to_win(int e) {
    switch (e) {
    case ENOENT:  return ERROR_FILE_NOT_FOUND;
    case ENOTDIR: return ERROR_PATH_NOT_FOUND;
    case EEXIST:  return ERROR_FILE_EXISTS;
    case EACCES: case EPERM: case EROFS: return ERROR_ACCESS_DENIED;
    default:      return ERROR_INVALID_FUNCTION;
    }
}

/* ---- file objects ---- */
typedef struct { int fd; } hfile;
static void file_closer(void *o) { hfile *f = (hfile *)o; if (f->fd > 2) close(f->fd); free(f); }

/* The standard handles (kernel32_crt.c's GetStdHandle) are 0x11..0x13. */
static int fd_of(uint32_t h) {
    if (h == 0x11u) return 0;
    if (h == 0x12u) return 1;
    if (h == 0x13u) return 2;
    hfile *f = (hfile *)hle_handle_obj(h, HLE_H_FILE);
    return f ? f->fd : -1;
}

int hle_file_fd(uint32_t h) { return fd_of(h); }   /* a file HANDLE's descriptor, for a host (Bink reads the game's) */

static uint32_t new_file(int fd) {
    static int closer_set;
    if (!closer_set) hle_handle_set_closer(HLE_H_FILE, file_closer), closer_set = 1;
    hfile *f = (hfile *)malloc(sizeof *f);
    f->fd = fd;
    uint32_t h = hle_handle_alloc(HLE_H_FILE, f);
    if (!h) { close(fd); free(f); return INVALID_HANDLE; }
    return h;
}

/* Device names a Windows program may open that a host has no file for. */
static int is_device(const char *p, char *host, size_t n) {
    const char *b = p + strlen(p);
    while (b > p && b[-1] != '\\' && b[-1] != '/' && b[-1] != ':') b--;
    if (!strncmp(p, "\\\\.\\", 4) || !strncasecmp(b, "COM", 3) || !strncasecmp(b, "LPT", 3)) { host[0] = 0; return 1; }
    if (!strcasecmp(b, "NUL")) { snprintf(host, n, "/dev/null"); return 1; }
    if (!strcasecmp(b, "CON")) { snprintf(host, n, "/dev/tty"); return 1; }
    return 0;
}

int hle_filetrace(void) {
    static int on = -1;
    if (on < 0) on = getenv("HLE_FILETRACE") != NULL;
    return on;
}

/* CreateFileA(name,access,share,sa,disp,flags,template). access GENERIC_READ
 * 0x80000000, GENERIC_WRITE 0x40000000; disp CREATE_NEW 1, CREATE_ALWAYS 2,
 * OPEN_EXISTING 3, OPEN_ALWAYS 4, TRUNCATE_EXISTING 5. */
static void k_CreateFileA(void) {
    const char *name = ASTR(0);
    uint32_t access = A32(1), disp = A32(4);
    char path[1024];
    int exists = 0;
    if (!name || !*name) { hle_set_last_error(ERROR_PATH_NOT_FOUND); RET(INVALID_HANDLE, 7); }
    if (is_device(name, path, sizeof path)) {
        if (!path[0]) { hle_set_last_error(ERROR_FILE_NOT_FOUND); RET(INVALID_HANDLE, 7); }
        exists = 1;
    } else if ((access & 0x40000000u) || disp == 1 || disp == 2 || disp == 4) {
        /* a write or a create: under a mod's overlay, into the overlay (a file
         * opened to change in place is copied there first) */
        int keep = (access & 0x40000000u) && (disp == 3 || disp == 4);
        struct stat there;
        hle_host_path_for_write(name, path, sizeof path, keep);
        exists = stat(path, &there) == 0;
    } else {
        exists = hle_host_path(name, path, sizeof path);
    }
    int rd = (access & 0x80000000u) || !(access & 0x40000000u), wr = (access & 0x40000000u) != 0;
    int fl = rd && wr ? O_RDWR : wr ? O_WRONLY : O_RDONLY;
    switch (disp) {
    case 1: fl |= O_CREAT | O_EXCL; break;
    case 2: fl |= O_CREAT | O_TRUNC; break;
    case 4: fl |= O_CREAT; break;
    case 5: fl |= O_TRUNC; break;
    default: break;
    }
    struct stat st;
    if (exists && stat(path, &st) == 0 && S_ISDIR(st.st_mode) && !(A32(5) & 0x02000000u)) {
        hle_set_last_error(ERROR_ACCESS_DENIED);    /* a directory, without FILE_FLAG_BACKUP_SEMANTICS */
        RET(INVALID_HANDLE, 7);
    }
    int fd = open(path, fl | O_CLOEXEC, 0644);
    if (hle_filetrace())
        fprintf(stderr, "[file] CreateFileA \"%s\" -> %s %s\n", name, path, fd >= 0 ? "ok" : strerror(errno));
    if (fd < 0) { hle_set_last_error(errno_to_win(errno)); RET(INVALID_HANDLE, 7); }
    hle_set_last_error(exists && (disp == 2 || disp == 4) ? ERROR_ALREADY_EXISTS : 0);
    RET(new_file(fd), 7);
}

static void k_ReadFile(void) {                           /* (h,buf,n,&read,ovl) */
    int fd = fd_of(A32(0));
    uint8_t *buf = (uint8_t *)APTR(1);
    uint32_t n = A32(2), *pr = (uint32_t *)APTR(3), got = 0;
    if (pr) *pr = 0;
    if (fd < 0) { hle_set_last_error(ERROR_INVALID_HANDLE); RET(0, 5); }
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        got += (uint32_t)r;
    }
    if (pr) *pr = got;
    RET(1, 5);                                           /* EOF is success with 0 read */
}
static void k_WriteFile(void) {                          /* (h,buf,n,&written,ovl) */
    int fd = fd_of(A32(0));
    const uint8_t *buf = (const uint8_t *)APTR(1);
    uint32_t n = A32(2), *pw = (uint32_t *)APTR(3), put = 0;
    if (pw) *pw = 0;
    if (fd < 0) { hle_set_last_error(ERROR_INVALID_HANDLE); RET(0, 5); }
    while (put < n) {
        ssize_t r = write(fd, buf + put, n - put);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        put += (uint32_t)r;
    }
    if (pw) *pw = put;
    RET(put == n ? 1u : 0u, 5);
}
static void k_SetFilePointer(void) {                     /* (h,dist,&distHigh,method) -> new pos */
    int fd = fd_of(A32(0));
    int64_t dist = (int32_t)A32(1);
    uint32_t *hi = (uint32_t *)APTR(2), method = A32(3);
    if (hi) dist = (int64_t)(((uint64_t)*hi << 32) | A32(1));
    off_t r = fd >= 0 ? lseek(fd, (off_t)dist, method == 1 ? SEEK_CUR : method == 2 ? SEEK_END : SEEK_SET) : -1;
    if (r < 0) { hle_set_last_error(fd < 0 ? ERROR_INVALID_HANDLE : 131u /* NEGATIVE_SEEK */); RET(INVALID_HANDLE, 4); }
    if (hi) *hi = (uint32_t)((uint64_t)r >> 32);
    hle_set_last_error(0);
    RET((uint32_t)r, 4);
}
static void k_SetEndOfFile(void) {
    int fd = fd_of(A32(0));
    off_t pos = fd >= 0 ? lseek(fd, 0, SEEK_CUR) : -1;
    RET(pos >= 0 && ftruncate(fd, pos) == 0 ? 1u : 0u, 1);
}
static void k_FlushFileBuffers(void) { int fd = fd_of(A32(0)); RET(fd >= 0 ? 1u : 0u, 1); }
static void k_GetFileSize(void) {                        /* (h,&high) -> low */
    int fd = fd_of(A32(0));
    uint32_t *hi = (uint32_t *)APTR(1);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0) { hle_set_last_error(ERROR_INVALID_HANDLE); RET(INVALID_HANDLE, 2); }
    if (hi) *hi = (uint32_t)((uint64_t)st.st_size >> 32);
    hle_set_last_error(0);
    RET((uint32_t)st.st_size, 2);
}
/* CloseHandle: any kernel object (its type's closer runs); pseudo-handles and
 * the std handles are not objects and close successfully. */
static void k_CloseHandle(void) {
    uint32_t h = A32(0);
    if (hle_handle_close(h) || h == 0xFFFFFFFFu || h == 0xFFFFFFFEu || (h >= 0x11u && h <= 0x13u)) RET(1, 1);
    hle_set_last_error(ERROR_INVALID_HANDLE);
    RET(0, 1);
}
static void k_GetFileType(void) {
    uint32_t h = A32(0);
    if (h >= 0x11u && h <= 0x13u) RET(isatty(fd_of(h)) ? 2u : 1u, 1);   /* CHAR / DISK */
    RET(hle_handle_obj(h, HLE_H_FILE) ? 1u : 0u, 1);
}

/* ---- FILETIME (100 ns since 1601) and SYSTEMTIME ---- */
#define EPOCH_DIFF 11644473600ull
static uint64_t unix_to_ft(time_t s, long ns) { return ((uint64_t)s + EPOCH_DIFF) * 10000000ull + (uint64_t)ns / 100u; }
static void put_ft(uint32_t at, uint64_t ft) { if (at) MEM32(at) = (uint32_t)ft, MEM32(at + 4) = (uint32_t)(ft >> 32); }
static uint64_t get_ft(uint32_t at) { return at ? (uint64_t)MEM32(at) | (uint64_t)MEM32(at + 4) << 32 : 0; }

static void put_systemtime(uint32_t st, const struct tm *t, int ms) {
    uint16_t *w = (uint16_t *)(uintptr_t)st;
    w[0] = (uint16_t)(t->tm_year + 1900), w[1] = (uint16_t)(t->tm_mon + 1), w[2] = (uint16_t)t->tm_wday;
    w[3] = (uint16_t)t->tm_mday, w[4] = (uint16_t)t->tm_hour, w[5] = (uint16_t)t->tm_min;
    w[6] = (uint16_t)t->tm_sec, w[7] = (uint16_t)ms;
}

static void k_GetSystemTime(void) {
    struct timespec ts; struct tm t;
    clock_gettime(CLOCK_REALTIME, &ts);
    gmtime_r(&ts.tv_sec, &t);
    put_systemtime(A32(0), &t, (int)(ts.tv_nsec / 1000000));
    RETV(1);
}
static void k_GetLocalTime(void) {
    struct timespec ts; struct tm t;
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &t);
    put_systemtime(A32(0), &t, (int)(ts.tv_nsec / 1000000));
    RETV(1);
}
static void k_GetSystemTimeAsFileTime(void) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    put_ft(A32(0), unix_to_ft(ts.tv_sec, ts.tv_nsec));
    RETV(1);
}
static void k_FileTimeToSystemTime(void) {               /* (&ft, &st) */
    uint64_t ft = get_ft(A32(0));
    time_t s = (time_t)(ft / 10000000ull - EPOCH_DIFF);
    struct tm t; gmtime_r(&s, &t);
    put_systemtime(A32(1), &t, (int)(ft % 10000000ull / 10000u));
    RET(1, 2);
}
static void k_SystemTimeToFileTime(void) {               /* (&st, &ft) */
    const uint16_t *w = (const uint16_t *)APTR(0);
    struct tm t = { 0 };
    t.tm_year = w[0] - 1900, t.tm_mon = w[1] - 1, t.tm_mday = w[3];
    t.tm_hour = w[4], t.tm_min = w[5], t.tm_sec = w[6];
    time_t s = timegm(&t);
    put_ft(A32(1), unix_to_ft(s, (long)w[7] * 1000000L));
    RET(1, 2);
}
static int32_t tz_bias_s(void) {                         /* local - UTC, seconds */
    time_t now = time(NULL); struct tm t; localtime_r(&now, &t);
    return (int32_t)t.tm_gmtoff;
}
static void k_FileTimeToLocalFileTime(void) { put_ft(A32(1), get_ft(A32(0)) + (int64_t)tz_bias_s() * 10000000); RET(1, 2); }
static void k_LocalFileTimeToFileTime(void) { put_ft(A32(1), get_ft(A32(0)) - (int64_t)tz_bias_s() * 10000000); RET(1, 2); }
static void k_CompareFileTime(void) {
    uint64_t a = get_ft(A32(0)), b = get_ft(A32(1));
    RET(a < b ? 0xFFFFFFFFu : a > b ? 1u : 0u, 2);
}
static void k_DosDateTimeToFileTime(void) {              /* (date, time, &ft) */
    uint32_t d = A32(0) & 0xFFFF, tm_ = A32(1) & 0xFFFF;
    struct tm t = { 0 };
    t.tm_year = (int)(d >> 9) + 80, t.tm_mon = (int)((d >> 5) & 15) - 1, t.tm_mday = (int)(d & 31);
    t.tm_hour = (int)(tm_ >> 11), t.tm_min = (int)((tm_ >> 5) & 63), t.tm_sec = (int)(tm_ & 31) * 2;
    put_ft(A32(2), unix_to_ft(timegm(&t), 0));
    RET(1, 3);
}
static void k_FileTimeToDosDateTime(void) {              /* (&ft, &date, &time) */
    uint64_t ft = get_ft(A32(0));
    time_t s = (time_t)(ft / 10000000ull - EPOCH_DIFF);
    struct tm t; gmtime_r(&s, &t);
    if (A32(1)) MEM16(A32(1)) = (uint16_t)(((t.tm_year - 80) << 9) | ((t.tm_mon + 1) << 5) | t.tm_mday);
    if (A32(2)) MEM16(A32(2)) = (uint16_t)((t.tm_hour << 11) | (t.tm_min << 5) | (t.tm_sec / 2));
    RET(1, 3);
}
static void k_GetTimeZoneInformation(void) {             /* (&TIME_ZONE_INFORMATION) 172 bytes */
    uint8_t *z = (uint8_t *)APTR(0);
    if (z) { memset(z, 0, 172); *(int32_t *)z = -tz_bias_s() / 60; }
    RET(0u, 1);                                          /* TIME_ZONE_ID_UNKNOWN: no DST rule */
}

static void k_GetFileTime(void) {                        /* (h, &create, &access, &write) */
    int fd = fd_of(A32(0));
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0) { hle_set_last_error(ERROR_INVALID_HANDLE); RET(0, 4); }
    put_ft(A32(1), unix_to_ft(st.st_mtim.tv_sec, st.st_mtim.tv_nsec));
    put_ft(A32(2), unix_to_ft(st.st_atim.tv_sec, st.st_atim.tv_nsec));
    put_ft(A32(3), unix_to_ft(st.st_mtim.tv_sec, st.st_mtim.tv_nsec));
    RET(1, 4);
}
static void k_SetFileTime(void) {                        /* (h, &create, &access, &write) */
    int fd = fd_of(A32(0));
    struct timespec ts[2] = { { 0, UTIME_OMIT }, { 0, UTIME_OMIT } };
    for (int i = 0; i < 2; i++) {
        uint32_t at = A32(2 + i);
        if (!at) continue;
        uint64_t ft = get_ft(at);
        ts[i].tv_sec = (time_t)(ft / 10000000ull - EPOCH_DIFF), ts[i].tv_nsec = (long)(ft % 10000000ull) * 100;
    }
    RET(fd >= 0 && futimens(fd, ts) == 0 ? 1u : 0u, 4);
}

static uint32_t attrs_of(const struct stat *st) {
    uint32_t a = S_ISDIR(st->st_mode) ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE;
    if (!(st->st_mode & S_IWUSR)) a |= FILE_ATTRIBUTE_READONLY;
    return a;
}
static void k_GetFileInformationByHandle(void) {         /* (h, &BY_HANDLE_FILE_INFORMATION) 52 bytes */
    int fd = fd_of(A32(0));
    uint32_t o = A32(1);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0) { hle_set_last_error(ERROR_INVALID_HANDLE); RET(0, 2); }
    memset((void *)(uintptr_t)o, 0, 52);
    MEM32(o) = attrs_of(&st);
    put_ft(o + 4, unix_to_ft(st.st_mtim.tv_sec, st.st_mtim.tv_nsec));
    put_ft(o + 12, unix_to_ft(st.st_atim.tv_sec, st.st_atim.tv_nsec));
    put_ft(o + 20, unix_to_ft(st.st_mtim.tv_sec, st.st_mtim.tv_nsec));
    MEM32(o + 28) = (uint32_t)st.st_dev;
    MEM32(o + 32) = (uint32_t)((uint64_t)st.st_size >> 32), MEM32(o + 36) = (uint32_t)st.st_size;
    MEM32(o + 40) = (uint32_t)st.st_nlink;
    MEM32(o + 44) = (uint32_t)((uint64_t)st.st_ino >> 32), MEM32(o + 48) = (uint32_t)st.st_ino;
    RET(1, 2);
}

static void k_GetFileAttributesA(void) {
    char path[1024];
    struct stat st;
    if (!hle_host_path(ASTR(0), path, sizeof path) || stat(path, &st) != 0) {
        hle_set_last_error(ERROR_FILE_NOT_FOUND);
        RET(0xFFFFFFFFu, 1);
    }
    RET(attrs_of(&st), 1);
}
static void k_SetFileAttributesA(void) { char path[1024]; RET(hle_host_path(ASTR(0), path, sizeof path) ? 1u : 0u, 2); }
static void k_CreateDirectoryA(void) {
    char path[1024];
    hle_host_path_for_write(ASTR(0), path, sizeof path, 0);
    if (mkdir(path, 0755) == 0) RET(1, 2);
    hle_set_last_error(errno == EEXIST ? ERROR_ALREADY_EXISTS : errno_to_win(errno));
    RET(0, 2);
}
static void k_RemoveDirectoryA(void) {
    char path[1024];
    hle_host_path(ASTR(0), path, sizeof path);
    if (rmdir(path) == 0) RET(1, 1);
    hle_set_last_error(errno_to_win(errno));
    RET(0, 1);
}
static void k_DeleteFileA(void) {
    char path[1024];
    if (hle_host_path(ASTR(0), path, sizeof path) && unlink(path) == 0) RET(1, 1);
    hle_set_last_error(ERROR_FILE_NOT_FOUND);
    RET(0, 1);
}
static void k_MoveFileA(void) {
    char a[1024], b[1024];
    hle_host_path(ASTR(0), a, sizeof a);
    hle_host_path(ASTR(1), b, sizeof b);
    if (rename(a, b) == 0) RET(1, 2);
    hle_set_last_error(errno_to_win(errno));
    RET(0, 2);
}
static void k_CopyFileA(void) {                          /* (src, dst, failIfExists) */
    char a[1024], b[1024];
    int ok = 0;
    hle_host_path(ASTR(0), a, sizeof a);
    int dst_exists = hle_host_path(ASTR(1), b, sizeof b);
    hle_host_path_for_write(ASTR(1), b, sizeof b, 0);
    if (A32(2) && dst_exists) { hle_set_last_error(ERROR_FILE_EXISTS); RET(0, 3); }
    int in = open(a, O_RDONLY | O_CLOEXEC), out = in >= 0 ? open(b, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644) : -1;
    if (in >= 0 && out >= 0) {
        char buf[65536];
        ssize_t r;
        ok = 1;
        while ((r = read(in, buf, sizeof buf)) > 0)
            if (write(out, buf, (size_t)r) != r) { ok = 0; break; }
    }
    if (in >= 0) close(in);
    if (out >= 0) close(out);
    if (!ok) hle_set_last_error(ERROR_FILE_NOT_FOUND);
    RET((uint32_t)ok, 3);
}

/* ---- FindFirstFileA / FindNextFileA ---- */
/* A directory search. Under a mod's overlay it lists the overlay's directory
 * first (d), then the game's (base) without the names the overlay had. */
typedef struct {
    DIR *d, *base;
    char dir[1024], base_dir[1024], mask[260];
    int dots;
    char (*shown)[260];
    int nshown;
} hfind;
static void find_closer(void *o) {
    hfind *f = (hfind *)o;
    if (f->d) closedir(f->d);
    if (f->base) closedir(f->base);
    free(f->shown);
    free(f);
}

/* Windows wildcard match, without case: * any run, ? one character; "*.*"
 * matches a name with no dot too. */
static int wild(const char *m, const char *s) {
    if (!strcmp(m, "*.*") || !strcmp(m, "*")) return 1;
    for (; *m; m++, s++) {
        if (*m == '*') {
            while (m[1] == '*') m++;
            if (!m[1]) return 1;
            for (; *s; s++) if (wild(m + 1, s)) return 1;
            return !strcmp(m + 1, ".*") || !strcmp(m + 1, ".");
        }
        if (!*s) return !strcmp(m, ".*") || !strcmp(m, ".");
        if (*m != '?' && (*m | 0x20) != (*s | 0x20) && *m != *s) return 0;
    }
    return !*s;
}

/* WIN32_FIND_DATAA: attrs, 3 FILETIMEs, size high/low, 2 reserved,
 * cFileName[260], cAlternateFileName[14]: 320 bytes. */
static void fill_find(uint32_t o, const char *dir, const char *name) {
    char full[1300];
    struct stat st;
    snprintf(full, sizeof full, "%s/%s", dir, name);
    memset((void *)(uintptr_t)o, 0, 320);
    if (stat(full, &st) == 0) {
        MEM32(o) = attrs_of(&st);
        put_ft(o + 4, unix_to_ft(st.st_mtim.tv_sec, st.st_mtim.tv_nsec));
        put_ft(o + 12, unix_to_ft(st.st_atim.tv_sec, st.st_atim.tv_nsec));
        put_ft(o + 20, unix_to_ft(st.st_mtim.tv_sec, st.st_mtim.tv_nsec));
        MEM32(o + 28) = (uint32_t)((uint64_t)st.st_size >> 32), MEM32(o + 32) = (uint32_t)st.st_size;
    }
    strncpy((char *)(uintptr_t)(o + 44), name, 259);
}

static int shown_already(hfind *f, const char *name) {
    for (int i = 0; i < f->nshown; i++)
        if (!strcasecmp(f->shown[i], name)) return 1;
    return 0;
}

static int find_next(hfind *f, uint32_t out) {
    struct dirent *e;
    while (f->d && (e = readdir(f->d))) {
        int dot = !strcmp(e->d_name, ".") || !strcmp(e->d_name, "..");
        if (dot && !f->dots) continue;
        if (!wild(f->mask, e->d_name)) continue;
        if (f->base) {                                   /* remember it: the game's copy is hidden */
            if (f->nshown % 64 == 0) f->shown = realloc(f->shown, sizeof *f->shown * (size_t)(f->nshown + 64));
            snprintf(f->shown[f->nshown++], 260, "%s", e->d_name);
        }
        fill_find(out, f->dir, e->d_name);
        return 1;
    }
    while (f->base && (e = readdir(f->base))) {
        if (!wild(f->mask, e->d_name) || shown_already(f, e->d_name)) continue;
        fill_find(out, f->base_dir, e->d_name);
        return 1;
    }
    return 0;
}

static void k_FindFirstFileA(void) {                     /* (pattern, &data) */
    static int closer_set;
    if (!closer_set) hle_handle_set_closer(HLE_H_FIND, find_closer), closer_set = 1;
    const char *pat = ASTR(0);
    const char *sl = pat ? pat + strlen(pat) : NULL;
    if (!pat) RET(INVALID_HANDLE, 2);
    while (sl > pat && sl[-1] != '\\' && sl[-1] != '/' && sl[-1] != ':') sl--;
    hfind *f = (hfind *)calloc(1, sizeof *f);
    char gdir[1024];
    snprintf(gdir, sizeof gdir, "%.*s", (int)(sl - pat), pat);
    if (!gdir[0]) snprintf(gdir, sizeof gdir, ".");
    hle_host_path_base(gdir, f->dir, sizeof f->dir);
    char overlay_dir[1024];
    if (hle_overlay_of(f->dir, overlay_dir, sizeof overlay_dir) == 1 && (f->base = opendir(f->dir))) {
        snprintf(f->base_dir, sizeof f->base_dir, "%s", f->dir);
        snprintf(f->dir, sizeof f->dir, "%s", overlay_dir);
    }
    snprintf(f->mask, sizeof f->mask, "%s", sl);
    f->dots = strchr(f->mask, '*') || strchr(f->mask, '?');
    /* no wildcard: the one name, found without case */
    if (!f->dots) {
        char one[1024];
        struct stat st;
        if (hle_host_path(pat, one, sizeof one) && stat(one, &st) == 0) {
            char *b = strrchr(one, '/');                 /* the overlay's or the game's, wherever it is */
            if (b) *b = 0;
            fill_find(A32(1), b ? (one[0] ? one : "/") : ".", b ? b + 1 : one);
            uint32_t h = hle_handle_alloc(HLE_H_FIND, f);
            RET(h ? h : INVALID_HANDLE, 2);
        }
        free(f);
        hle_set_last_error(ERROR_FILE_NOT_FOUND);
        RET(INVALID_HANDLE, 2);
    }
    f->d = opendir(f->dir);
    if (!f->d || !find_next(f, A32(1))) {
        find_closer(f);
        hle_set_last_error(ERROR_FILE_NOT_FOUND);
        RET(INVALID_HANDLE, 2);
    }
    if (hle_filetrace()) fprintf(stderr, "[file] FindFirstFileA \"%s\" in %s\n", pat, f->dir);
    uint32_t h = hle_handle_alloc(HLE_H_FIND, f);
    RET(h ? h : INVALID_HANDLE, 2);
}
static void k_FindNextFileA(void) {
    hfind *f = (hfind *)hle_handle_obj(A32(0), HLE_H_FIND);
    if (f && find_next(f, A32(1))) RET(1, 2);
    hle_set_last_error(ERROR_NO_MORE_FILES);
    RET(0, 2);
}
static void k_FindClose(void) { RET(hle_handle_close(A32(0)) ? 1u : 0u, 1); }

/* ---- disks and volumes ---- */
static void k_GetDiskFreeSpaceA(void) {                  /* (root, &spc, &bps, &free, &total) */
    /* At most 2 GB free: a 1990s game multiplies these in 32 bits. */
    if (A32(1)) MEM32(A32(1)) = 8;
    if (A32(2)) MEM32(A32(2)) = 512;
    if (A32(3)) MEM32(A32(3)) = 0x7FFFFu;
    if (A32(4)) MEM32(A32(4)) = 0xFFFFFu;
    RET(1, 5);
}
static void k_GetVolumeInformationA(void) {              /* (root, name, nameN, &serial, &maxComp, &flags, fs, fsN) */
    char *name = ASTR(1), *fs = ASTR(6);
    if (name && A32(2)) snprintf(name, A32(2), "%s", "HLE");
    if (A32(3)) MEM32(A32(3)) = 0x1234ABCDu;
    if (A32(4)) MEM32(A32(4)) = 255;
    if (A32(5)) MEM32(A32(5)) = 0x3u;                    /* case-sensitive search, case-preserved names */
    if (fs && A32(7)) snprintf(fs, A32(7), "%s", "NTFS");
    RET(1, 8);
}
/* DRIVE_FIXED for a mapped drive (and Z:), DRIVE_NO_ROOT_DIR otherwise: so a
 * scan for a CD-ROM finds none. */
static void k_GetDriveTypeA(void) {
    const char *r = ASTR(0);
    char path[16], host[1024];
    if (!r || !*r) RET(3u, 1);
    snprintf(path, sizeof path, "%c:\\", r[0]);
    RET(hle_host_path(path, host, sizeof host) && host[0] ? 3u : 1u, 1);
}

/* ---- .ini profile: a minimal reader/writer over a flat key=value file ----
 * Enough for a game remembering settings; sections are honoured on read. */
static FILE *ini_open(const char *file, const char *mode) {
    char path[1024];
    if (!file) return NULL;
    hle_host_path(file, path, sizeof path);
    return fopen(path, mode);
}
static int ini_find_section(FILE *f, const char *section) {
    char line[512]; char want[256];
    snprintf(want, sizeof want, "[%s]", section);
    rewind(f);
    while (fgets(line, sizeof line, f))
        if (line[0] == '[' && !strncasecmp(line, want, strlen(want))) return 1;
    return 0;
}
static void k_GetPrivateProfileStringA(void) {           /* (sec,key,def,buf,size,file) */
    const char *sec = ASTR(0), *key = ASTR(1), *def = ASTR(2);
    char *buf = ASTR(3); uint32_t size = A32(4); const char *file = ASTR(5);
    const char *val = def ? def : "";
    char line[512];
    FILE *f = ini_open(file, "r");
    if (f && sec && key && ini_find_section(f, sec)) {
        size_t kl = strlen(key);
        while (fgets(line, sizeof line, f)) {
            if (line[0] == '[') break;                   /* next section */
            if (!strncasecmp(line, key, kl) && line[kl] == '=') {
                char *v = line + kl + 1, *nl = strpbrk(v, "\r\n"); if (nl) *nl = 0;
                static char out[512]; strncpy(out, v, sizeof out - 1); val = out; break;
            }
        }
    }
    if (f) fclose(f);
    if (buf && size) { strncpy(buf, val, size - 1); buf[size - 1] = 0; }
    RET(buf ? (uint32_t)strlen(buf) : 0u, 6);
}
static void k_GetPrivateProfileIntA(void) {              /* (sec,key,def,file) */
    char buf[64] = "", def[16];
    snprintf(def, sizeof def, "%d", (int)A32(2));
    const char *sec = ASTR(0), *key = ASTR(1), *file = ASTR(3);
    FILE *f = ini_open(file, "r"); char line[512]; int got = 0;
    if (f && sec && key && ini_find_section(f, sec)) {
        size_t kl = strlen(key);
        while (fgets(line, sizeof line, f)) {
            if (line[0] == '[') break;
            if (!strncasecmp(line, key, kl) && line[kl] == '=') { strncpy(buf, line + kl + 1, 63); got = 1; break; }
        }
    }
    if (f) fclose(f);
    RET((uint32_t)atoi(got ? buf : def), 4);
}
/* WritePrivateProfileStringA: append the key under a (possibly new) section;
 * the reader takes the first match. A title that rewrites keys gets the
 * in-place version when it needs it. */
static void k_WritePrivateProfileStringA(void) {         /* (sec,key,val,file) */
    const char *sec = ASTR(0), *key = ASTR(1), *val = ASTR(2), *file = ASTR(3);
    if (file && sec && key) {
        FILE *f = ini_open(file, "a");
        if (f) { fprintf(f, "[%s]\n%s=%s\n", sec, key, val ? val : ""); fclose(f); }
    }
    RET(1, 4);
}

const win32hle_shim win32hle_kernel32_ext[] = {
    { "CreateFileA",                k_CreateFileA },
    { "ReadFile",                   k_ReadFile },
    { "WriteFile",                  k_WriteFile },
    { "SetFilePointer",             k_SetFilePointer },
    { "SetEndOfFile",               k_SetEndOfFile },
    { "FlushFileBuffers",           k_FlushFileBuffers },
    { "GetFileSize",                k_GetFileSize },
    { "GetFileType",                k_GetFileType },
    { "CloseHandle",                k_CloseHandle },
    { "GetFileTime",                k_GetFileTime },
    { "SetFileTime",                k_SetFileTime },
    { "GetFileInformationByHandle", k_GetFileInformationByHandle },
    { "GetFileAttributesA",         k_GetFileAttributesA },
    { "SetFileAttributesA",         k_SetFileAttributesA },
    { "CreateDirectoryA",           k_CreateDirectoryA },
    { "RemoveDirectoryA",           k_RemoveDirectoryA },
    { "DeleteFileA",                k_DeleteFileA },
    { "MoveFileA",                  k_MoveFileA },
    { "CopyFileA",                  k_CopyFileA },
    { "FindFirstFileA",             k_FindFirstFileA },
    { "FindNextFileA",              k_FindNextFileA },
    { "FindClose",                  k_FindClose },
    { "GetDiskFreeSpaceA",          k_GetDiskFreeSpaceA },
    { "GetVolumeInformationA",      k_GetVolumeInformationA },
    { "GetDriveTypeA",              k_GetDriveTypeA },
    { "GetSystemTime",              k_GetSystemTime },
    { "GetLocalTime",               k_GetLocalTime },
    { "GetSystemTimeAsFileTime",    k_GetSystemTimeAsFileTime },
    { "FileTimeToSystemTime",       k_FileTimeToSystemTime },
    { "SystemTimeToFileTime",       k_SystemTimeToFileTime },
    { "FileTimeToLocalFileTime",    k_FileTimeToLocalFileTime },
    { "LocalFileTimeToFileTime",    k_LocalFileTimeToFileTime },
    { "CompareFileTime",            k_CompareFileTime },
    { "DosDateTimeToFileTime",      k_DosDateTimeToFileTime },
    { "FileTimeToDosDateTime",      k_FileTimeToDosDateTime },
    { "GetTimeZoneInformation",     k_GetTimeZoneInformation },
    { "GetPrivateProfileStringA",   k_GetPrivateProfileStringA },
    { "GetPrivateProfileIntA",      k_GetPrivateProfileIntA },
    { "WritePrivateProfileStringA", k_WritePrivateProfileStringA },
    { 0, 0 }
};
