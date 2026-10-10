/*
 * hle_path.c - Windows paths on a POSIX file system.
 *
 * A guest names files the Windows way: `C:\Westwood\Sun\SCORES.MIX`,
 * `..\Movies`, `data\rules.ini`, in any case. The host's files are on a
 * case-sensitive file system in whatever case they were installed in. So:
 *
 *   - a drive letter maps to a host directory (hle_set_drive; Z: is "/", as
 *     under Wine), and a path without one is relative to the host's cwd;
 *   - '\\' and '/' both separate;
 *   - each component that does not exist as spelled is looked up in its
 *     directory without regard to case.
 *
 * The reverse (a host directory as the guest should see it) is
 * hle_guest_path, for GetCurrentDirectoryA and GetModuleFileNameA.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include "win32hle.h"

static char *g_drive[26];

void hle_set_drive(char letter, const char *host_root) {
    int i = (letter | 0x20) - 'a';
    if (i < 0 || i >= 26) return;
    free(g_drive[i]);
    g_drive[i] = host_root ? realpath(host_root, NULL) : NULL;
}

static const char *drive_root(int i) {
    if (g_drive[i]) return g_drive[i];
    return i == 'z' - 'a' ? "" : NULL;          /* Z: is the host's root */
}

/* Append one component to out (which holds an existing directory, or ""
 * for the cwd), matching it without case if it is not there as spelled.
 * Returns 1 if the result exists. */
static int join_component(char *out, size_t n, const char *comp, size_t clen) {
    size_t len = strlen(out);
    if (clen == 1 && comp[0] == '.') return 1;
    if (clen == 2 && comp[0] == '.' && comp[1] == '.') {
        if (!len || !strcmp(out, ".") ) { snprintf(out, n, ".."); return 1; }
        char *slash = strrchr(out, '/');
        if (slash && strcmp(slash + 1, "..")) { if (slash == out) slash[1] = 0; else *slash = 0; return 1; }
        snprintf(out + len, n - len, "%s..", len && out[len - 1] != '/' ? "/" : "");
        return 1;
    }
    char want[512];
    if (clen >= sizeof want) clen = sizeof want - 1;
    memcpy(want, comp, clen), want[clen] = 0;
    const char *sep = len && out[len - 1] != '/' ? "/" : "";
    snprintf(out + len, n - len, "%s%s", sep, want);
    struct stat st;
    if (lstat(out[0] ? out : ".", &st) == 0) return 1;
    out[len] = 0;
    DIR *d = opendir(len ? out : ".");
    int found = 0;
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)))
            if (!strcasecmp(e->d_name, want)) { snprintf(out + len, n - len, "%s%s", sep, e->d_name); found = 1; break; }
        closedir(d);
    }
    if (!found) snprintf(out + len, n - len, "%s%s", sep, want);
    return found;
}

/* ---- an overlay: a mod's folder laid over the game's ----
 *
 * With hle_set_overlay(base, overlay), a file under base is looked for in
 * overlay first (at the same relative path, without case), so a mod's
 * rules.ini or map is read instead of the game's. Writes to files under base
 * go to the overlay (hle_host_path_for_write), so playing a mod never changes
 * the game's own files; FindFirstFileA lists both, the overlay's first. */
static char *g_overlay_base, *g_overlay;

void hle_set_overlay(const char *base, const char *overlay) {
    free(g_overlay_base), free(g_overlay);
    g_overlay_base = base && overlay ? realpath(base, NULL) : NULL;
    g_overlay = base && overlay ? realpath(overlay, NULL) : NULL;
    if (!g_overlay_base || !g_overlay) free(g_overlay_base), free(g_overlay), g_overlay_base = g_overlay = NULL;
}

/* host as an absolute path, if it is relative (to the cwd). */
static void absolute(const char *host, char *out, size_t n) {
    char cwd[768];
    if (host[0] == '/' || !getcwd(cwd, sizeof cwd)) snprintf(out, n, "%s", host);
    else snprintf(out, n, "%s/%s", cwd, strcmp(host, ".") ? host : "");
    size_t l = strlen(out);
    while (l > 1 && out[l - 1] == '/') out[--l] = 0;
}

static int under(const char *path, const char *dir) {
    size_t l = strlen(dir);
    return !strncmp(path, dir, l) && (path[l] == '/' || !path[l]);
}

int hle_overlay_of(const char *host, char *out, size_t n) {
    char abs[1024];
    out[0] = 0;
    if (!g_overlay) return -1;
    absolute(host, abs, sizeof abs);
    if (under(abs, g_overlay) || !under(abs, g_overlay_base)) return -1;
    snprintf(out, n, "%s", g_overlay);
    const char *p = abs + strlen(g_overlay_base);
    int exists = 1;
    while (*p) {
        while (*p == '/') p++;
        const char *e = p;
        while (*e && *e != '/') e++;
        if (e > p) exists = join_component(out, n, p, (size_t)(e - p)) && exists;
        p = e;
    }
    return exists;
}

/* The path a write to guest should go to: the overlay's copy when the file is
 * the game's (its directories made; with keep, the game's file copied there
 * first, so a write into the middle of it keeps the rest). */
int hle_host_path_for_write(const char *guest, char *out, size_t n, int keep) {
    int exists = hle_host_path(guest, out, n);
    char ov[1024];
    if (hle_overlay_of(out, ov, sizeof ov) < 0) return exists;
    for (char *s = ov + strlen(g_overlay); *s && (s = strchr(s + 1, '/')); ) {   /* mkdir -p its directory */
        *s = 0;
        mkdir(ov, 0755);
        *s = '/';
    }
    if (keep && exists) {
        FILE *in = fopen(out, "rb"), *to = in ? fopen(ov, "wb") : NULL;
        char buf[65536];
        size_t r;
        while (to && (r = fread(buf, 1, sizeof buf, in)) > 0) fwrite(buf, 1, r, to);
        if (in) fclose(in);
        if (to) fclose(to);
    }
    snprintf(out, n, "%s", ov);
    return keep && exists;
}

static int host_path_plain(const char *guest, char *out, size_t n);

int hle_host_path(const char *guest, char *out, size_t n) {
    int exists = host_path_plain(guest, out, n);
    char ov[1024];
    struct stat st;
    /* A file only: a directory stays the game's (the cwd is set through here,
     * and FindFirstFileA lists both) */
    if (g_overlay && hle_overlay_of(out, ov, sizeof ov) == 1 && stat(ov, &st) == 0 && !S_ISDIR(st.st_mode)) {
        snprintf(out, n, "%s", ov);
        return 1;
    }
    return exists;
}

/* The game's own path for guest, ignoring any overlay. */
int hle_host_path_base(const char *guest, char *out, size_t n) { return host_path_plain(guest, out, n); }

static int host_path_plain(const char *guest, char *out, size_t n) {
    out[0] = 0;
    if (!guest) return 0;
    const char *p = guest;
    if (((p[0] | 0x20) >= 'a' && (p[0] | 0x20) <= 'z') && p[1] == ':') {
        const char *root = drive_root((p[0] | 0x20) - 'a');
        if (!root) return 0;
        snprintf(out, n, "%s", *root ? root : "/");
        p += 2;
        while (*p == '\\' || *p == '/') p++;
    } else if (*p == '\\' || *p == '/') {
        /* rooted without a drive: the C: drive's root, if there is one */
        const char *root = drive_root(2);
        snprintf(out, n, "%s", root && *root ? root : "/");
        while (*p == '\\' || *p == '/') p++;
    }
    int exists = 1;
    while (*p) {
        const char *e = p;
        while (*e && *e != '\\' && *e != '/') e++;
        if (e > p) exists = join_component(out, n, p, (size_t)(e - p)) && exists;
        p = e;
        while (*p == '\\' || *p == '/') p++;
    }
    if (!out[0]) snprintf(out, n, ".");
    return exists;
}

/* A host path (absolute) as the guest sees it: under a mapped drive, that
 * drive; otherwise Z: and the whole path. Backslashes. */
void hle_guest_path(const char *host, char *out, size_t n) {
    char abs[1024];
    if (host[0] != '/') {
        char cwd[768];
        if (!getcwd(cwd, sizeof cwd)) cwd[0] = 0;
        snprintf(abs, sizeof abs, "%s/%s", cwd, host);
    } else {
        snprintf(abs, sizeof abs, "%s", host);
    }
    char *real = realpath(abs, NULL);
    const char *h = real ? real : abs;
    int best = -1;
    size_t best_len = 0;
    for (int i = 0; i < 26; i++) {
        const char *r = g_drive[i];
        size_t l = r ? strlen(r) : 0;
        if (r && !strncmp(h, r, l) && (h[l] == '/' || !h[l]) && l >= best_len) best = i, best_len = l;
    }
    const char *rest = best >= 0 ? h + best_len : h;
    snprintf(out, n, "%c:%s", best >= 0 ? 'A' + best : 'Z', *rest ? "" : "\\");
    size_t k = strlen(out);
    for (; *rest && k + 1 < n; rest++) out[k++] = *rest == '/' ? '\\' : *rest;
    out[k] = 0;
    free(real);
}
