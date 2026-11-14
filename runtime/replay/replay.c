/* See replay.h. Single-threaded queue; replay_log may be called from any
 * thread (one fprintf per line). */
#include "replay.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <direct.h>
#define getcwd _getcwd
#else
#include <unistd.h>
#endif

typedef struct { uint32_t at; char ev[248]; } rp_ev;
static rp_ev *g_q;
static int g_n, g_cap, g_i;
static FILE *g_rec;
static char g_cwd[512], g_path[1024];

static void push(uint32_t at, const char *ev, size_t len) {
    if (g_n == g_cap) g_q = realloc(g_q, (g_cap = g_cap ? g_cap * 2 : 64) * sizeof *g_q);
    if (len >= sizeof g_q->ev) len = sizeof g_q->ev - 1;
    g_q[g_n].at = at;
    memcpy(g_q[g_n].ev, ev, len);
    g_q[g_n++].ev[len] = 0;
}

static int by_frame(const void *a, const void *b) {       /* stable: ties keep file order */
    const rp_ev *x = a, *y = b;
    return x->at != y->at ? (x->at < y->at ? -1 : 1) : (x < y ? -1 : 1);
}

int replay_init(const char *record, const char *replay, const char *keys) {
    if (!record) record = getenv("RECOMP_RECORD");
    if (!replay) replay = getenv("RECOMP_REPLAY");
    if (!keys) keys = getenv("RECOMP_FKEYS");
    if (!getcwd(g_cwd, sizeof g_cwd)) g_cwd[0] = 0;
    if (replay && *replay) {
        FILE *f = fopen(replay, "r");
        char line[300];
        if (!f) fprintf(stderr, "[replay] cannot open %s\n", replay);
        while (f && fgets(line, sizeof line, f)) {
            char *e;
            uint32_t at = strtoul(line, &e, 10);
            if (e == line || *line == '#') continue;
            while (*e == ' ' || *e == '\t') e++;
            push(at, e, strcspn(e, "\r\n"));
        }
        if (f) fclose(f);
    }
    for (const char *s = keys; s && *s;) {             /* f120:enter,f300:shot x.bmp */
        char *e;
        if (*s == 'f' || *s == 'F') s++;
        uint32_t at = strtoul(s, &e, 10);
        if (*e != ':') { fprintf(stderr, "[replay] bad key item at '%s'\n", s); break; }
        s = e + 1;
        size_t len = strcspn(s, ",");
        push(at, s, len);
        s += len + (s[len] == ',');
    }
    qsort(g_q, g_n, sizeof *g_q, by_frame);
    if (record && *record && !(g_rec = fopen(record, "w"))) fprintf(stderr, "[replay] cannot write %s\n", record);
    if (g_rec) setvbuf(g_rec, NULL, _IOLBF, 4096);
    if (g_n) fprintf(stderr, "[replay] %d events, last at frame %u\n", g_n, g_q[g_n - 1].at);
    return g_n > 0;
}

void replay_log(uint32_t frame, const char *fmt, ...) {
    if (!g_rec) return;
    char ev[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(ev, sizeof ev, fmt, ap);
    va_end(ap);
    fprintf(g_rec, "%u %s\n", frame, ev);
    fflush(g_rec);
}

const char *replay_due(uint32_t frame) {
    return g_i < g_n && g_q[g_i].at <= frame ? g_q[g_i++].ev : NULL;
}

const char *replay_path(const char *name) {
    int abs = name[0] == '/' || name[0] == '\\' || (name[0] && name[1] == ':');
    snprintf(g_path, sizeof g_path, abs || !g_cwd[0] ? "%s" : "%s/%s", abs ? name : g_cwd, name);
    return g_path;
}

uint32_t replay_hash(const void *p, size_t n) {
    uint32_t h = 2166136261u;
    for (const uint8_t *b = p; n--; ) h = (h ^ *b++) * 16777619u;
    return h;
}

#ifdef REPLAY_SELFTEST   /* cc -DREPLAY_SELFTEST replay.c && ./a.out */
#include <assert.h>
int main(void) {
    const char *rec = "replay_selftest.txt";
    replay_init(rec, NULL, "");
    replay_log(5, "key %02x", 0x1c);
    replay_log(9, "shot a.bmp");
    replay_log(9, "end");
    fclose(g_rec); g_rec = NULL;
    g_n = g_i = 0;
    assert(replay_init(NULL, rec, "f7:enter,f1:shot b.bmp"));
    assert(!strcmp(replay_due(0) ? "x" : "none", "none"));
    assert(!strcmp(replay_due(3), "shot b.bmp") && !replay_due(3));
    assert(!strcmp(replay_due(100), "key 1c"));         /* late frames still get every event, in order */
    assert(!strcmp(replay_due(100), "enter"));
    assert(!strcmp(replay_due(100), "shot a.bmp") && !strcmp(replay_due(100), "end") && !replay_due(100));
    assert(replay_hash("a", 1) == 0xe40c292cu);
    assert(!strcmp(replay_path("C:/x.bmp"), "C:/x.bmp"));
    remove(rec);
    puts("replay selftest ok");
    return 0;
}
#endif
