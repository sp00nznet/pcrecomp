/*
 * win16_impl.c - Real implementations of the init-path Win16 shims.
 *
 * These override the generated stubs in win16_stubs.c (gen_win16_stubs.py skips
 * any name defined here). Calling convention: the lifter reaches each shim via
 *   push cs; push 0; NAME(cpu);
 * so on entry the stack is [sp]=retIP(0), [sp+2]=retCS, [sp+4]=last PASCAL arg
 * (lowest address). Each shim reads args with a16/a32 and cleans up like the
 * real __far __pascal routine's RETF would: ret(cpu, purge_bytes).
 *
 * Memory model: a Win16 HANDLE == our flat selector. GlobalAlloc backs at least
 * a full 64K segment per selector, so GlobalLock is just sel:0000 and
 * GlobalReAlloc never has to move a block (a selector addresses <=64K anyway).
 */
#include "runtime_api.h"
#include "ne_resources.h"
#include "recomp_game.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <windows.h>

#ifdef RECOMP_TRACE_WIN16
#define IMPL_LOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define IMPL_LOG(...) ((void)0)
#endif

/* arg word `off` bytes above the first (lowest) arg slot at sp+4 */
static inline uint16_t a16(CPU *cpu, int off) {
    return mem_read16(cpu, cpu->ss, (uint16_t)(cpu->sp + 4 + off));
}
static inline uint32_t a32(CPU *cpu, int off) {
    return (uint32_t)a16(cpu, off) | ((uint32_t)a16(cpu, off + 2) << 16);
}
/* far retaddr (4) + PASCAL arg bytes */
static inline void ret(CPU *cpu, int purge) { cpu->sp += 4 + purge; }

static void read_asciiz(CPU *cpu, uint16_t seg, uint16_t off, char *out, int max) {
    int i = 0;
    for (; i < max - 1; i++) {
        uint8_t c = mem_read8(cpu, seg, (uint16_t)(off + i));
        if (!c) break;
        out[i] = (char)c;
    }
    out[i] = 0;
}

/* ===== KERNEL: memory (handle == selector) =====
 * A real free-list allocator over the flat heap, NOT a pure bump allocator: the
 * Borland RTL startup probes free memory by GlobalAlloc'ing 4K blocks until
 * failure, then GlobalFree's them all and allocates its real heap. Without
 * reclaiming freed blocks the probe permanently drains the heap and the next
 * allocation (in _setargv) fails. Per-selector size lets GlobalSize be exact
 * and GlobalReAlloc copy. Freed blocks are reused first-fit (uniform probe
 * blocks reuse perfectly); no splitting (fine for bring-up). */
static uint32_t g_sel_size[0x10000];   /* requested size per live selector */
static uint32_t g_sel_base[0x10000];   /* flat base per selector (for free)   */
#define MAX_FREE 16384
static uint32_t fl_base[MAX_FREE], fl_size[MAX_FREE];
static int      fl_n;

static uint16_t galloc(CPU *cpu, uint32_t bytes) {
    if (bytes == 0) bytes = 1;
    uint32_t need = (bytes + 0xF) & ~0xFu;
    /* first-fit over freed blocks */
    for (int i = 0; i < fl_n; i++) {
        if (fl_size[i] >= need) {
            uint32_t base = fl_base[i], bsz = fl_size[i];
            fl_base[i] = fl_base[--fl_n]; fl_size[i] = fl_size[fl_n];
            if (cpu->next_sel == 0) return 0;
            uint16_t s = cpu->next_sel++;
            cpu->sel_base[s] = base; g_sel_base[s] = base; g_sel_size[s] = bsz;
            /* Blocks off the free list still hold the previous tenant's bytes.
               Real KERNEL grows the heap with fresh (zero) pages, and this
               engine leans on that: XApt's on-screen rect at +0xE8 is read by
               XApt::UpdateSprites before anything writes it, so a dirty block
               seeded the frame's update rect with whatever text had been there
               ('ss' -> 29555). That rect drove the draw port's origin, the
               source rect went negative, and XCopyBits' clip shifted the
               destination by the difference -- stamping the pet at a wrong
               offset that changed every frame. Hand back clean memory. */
            if (base < cpu->mem_size) {
                uint32_t n = bsz;
                if (n > cpu->mem_size - base) n = cpu->mem_size - base;
                memset(cpu->mem + base, 0, n);
            }
            return s;
        }
    }
    uint16_t s = cpu_alloc_selector(cpu, need);   /* bump fresh */
    if (s) { g_sel_base[s] = cpu->sel_base[s]; g_sel_size[s] = need; }
    else { static int told; if (!told++) fprintf(stderr,
        "[win16] galloc(%u) FAILED: next_sel=%04X heap_next=%u heap_end=%u freelist=%d\n",
        (unsigned)bytes, cpu->next_sel, (unsigned)cpu->heap_next,
        (unsigned)cpu->heap_end, fl_n); }
    return s;
}

/* GMEM_ZEROINIT. The engine relies on it: ball records are accumulated into
 * (`add es:[bx+0x1A], ax`), never assigned, so a block handed back off the free
 * list still holding a previous tenant's bytes yields plausible-looking but
 * wrong geometry rather than an obvious failure. The Borland RTL's startup
 * free-memory probe allocates and frees 4 KB blocks, so the free list is
 * already dirty by the time the engine allocates anything. */
#define GMEM_ZEROINIT 0x0040

static void gzero(CPU *cpu, uint16_t sel) {
    if (!sel) return;
    uint32_t base = g_sel_base[sel], n = g_sel_size[sel];
    if (base >= cpu->mem_size) return;
    if (n > cpu->mem_size - base) n = cpu->mem_size - base;
    memset(cpu->mem + base, 0, n);
}

static void gfree(CPU *cpu, uint16_t sel) {
    if (!sel || !g_sel_size[sel]) return;
    if (fl_n < MAX_FREE) { fl_base[fl_n] = g_sel_base[sel]; fl_size[fl_n] = g_sel_size[sel]; fl_n++; }
    IMPL_LOG("[win16] GlobalFree(%04X) freelist=%d\n", sel, fl_n);
    g_sel_size[sel] = 0;
}

void KERNEL_GLOBALALLOC(CPU *cpu) {
    uint16_t wFlags = a16(cpu, 4);
    uint32_t bytes  = a32(cpu, 0);
    uint16_t sel    = galloc(cpu, bytes);
    if (wFlags & GMEM_ZEROINIT) gzero(cpu, sel);
    IMPL_LOG("[win16] GlobalAlloc(flags=%04X, %u) -> %04X\n", wFlags, bytes, sel);
    cpu->ax = sel;                          /* handle */
    if (sel) cpu->flags &= ~FLAG_CF; else cpu->flags |= FLAG_CF;
    ret(cpu, 6);
}

void KERNEL_GLOBALREALLOC(CPU *cpu) {
    uint16_t hMem  = a16(cpu, 6);
    uint32_t bytes = a32(cpu, 2);
    if (bytes == 0) bytes = 1;
    uint32_t old = (hMem ? g_sel_size[hMem] : 0);
    if (bytes <= old) {                     /* fits: keep handle */
        cpu->ax = hMem;
    } else {                                /* grow: new block, copy, free old */
        uint16_t nsel = galloc(cpu, bytes);
        if (nsel && hMem) {
            for (uint32_t i = 0; i < old; i++)
                mem_write8(cpu, nsel, (uint16_t)i, mem_read8(cpu, hMem, (uint16_t)i));
            gfree(cpu, hMem);
        }
        cpu->ax = nsel;
    }
    if (cpu->ax) cpu->flags &= ~FLAG_CF; else cpu->flags |= FLAG_CF;
    ret(cpu, 8);
}

void KERNEL_GLOBALFREE(CPU *cpu) {
    uint16_t hMem = a16(cpu, 0);
    gfree(cpu, hMem);
    cpu->ax = 0;                            /* NULL == success */
    ret(cpu, 2);
}

void KERNEL_GLOBALLOCK(CPU *cpu) {          /* -> far ptr DX:AX = handle:0000 */
    uint16_t hMem = a16(cpu, 0);
    cpu->dx = hMem; cpu->ax = 0;
    ret(cpu, 2);
}

void KERNEL_GLOBALUNLOCK(CPU *cpu) { cpu->ax = 0; ret(cpu, 2); }

/* GetFreeSpace(flags) -> DX:AX bytes free in the global heap. A game checks it
 * at startup (SimAnt: "not enough memory to run" on 0): report 16 MB, a
 * well-equipped 1993 machine, not the host's gigabytes, which a 32-bit
 * DWORD would wrap or a game might multiply. */
void KERNEL_GETFREESPACE(CPU *cpu) { cpu->dx = 0x0100; cpu->ax = 0; ret(cpu, 2); }

/* GlobalCompact(dwMinFree) -> the largest free block, the same 16 MB. SimAnt
 * calls it after loading its art and stops with "Fatal Error" on 0. */
void KERNEL_GLOBALCOMPACT(CPU *cpu) { cpu->dx = 0x0100; cpu->ax = 0; ret(cpu, 4); }

/* LockSegment(seg) -> the segment, locked; -1 means the caller's DS. Nothing
 * moves here, so there is nothing to lock. */
void KERNEL_LOCKSEGMENT(CPU *cpu) {
    uint16_t s = a16(cpu, 0);
    cpu->ax = s == 0xFFFF ? cpu->ds : s;
    ret(cpu, 2);
}

void KERNEL_GLOBALSIZE(CPU *cpu) {          /* -> DWORD size in DX:AX */
    uint16_t hMem = a16(cpu, 0);
    uint32_t sz = (hMem ? g_sel_size[hMem] : 0);
    cpu->ax = (uint16_t)sz; cpu->dx = (uint16_t)(sz >> 16);
    ret(cpu, 2);
}

void KERNEL_GLOBALHANDLE(CPU *cpu) {        /* -> DX:AX = selector:handle (same) */
    uint16_t sel = a16(cpu, 0);
    cpu->dx = sel; cpu->ax = sel;
    ret(cpu, 2);
}

/* ===== KERNEL/USER: modules, string table & resources =====
 * Backed by the original NE binaries (ne_resources.c). The engine LoadLibrary's
 * CATZREZX.DLL (a pure resource container) and reads its config-key names from
 * CATZDLL's STRINGTABLE; without these it throws KatzError "CATZREZX.DLL did not
 * load" at startup. */

static int map_guest_path(const char *g, char *host, int hostsz);

void KERNEL_LOADLIBRARY(CPU *cpu) {         /* LoadLibrary(lpLibFileName) */
    char name[128]; read_asciiz(cpu, a16(cpu, 2), a16(cpu, 0), name, sizeof name);
    /* A name with a directory is a file the game ships somewhere in its tree
       (Oddballz: EGGZ\DYNAROO\DYNAROO.ODD); resolve it like any guest path. */
    char host[320];
    const char *hp = NULL;
    if ((strchr(name, '\\') || strchr(name, '/')) && map_guest_path(name, host, sizeof host)
        && GetFileAttributesA(host) != INVALID_FILE_ATTRIBUTES)
        hp = host;
    uint16_t h = ne_loadlib(name, hp);
    if (!h) h = 0x0040;                     /* benign handle for DLLs w/o resources (WIN87EM) */
    IMPL_LOG("[win16] LoadLibrary(%s) -> %04X\n", name, h);
    cpu->ax = h;                            /* >32 == success */
    ret(cpu, 4);
}

void KERNEL_GETPROCADDRESS(CPU *cpu) {      /* GetProcAddress(hModule, lpProcName) */
    uint16_t noff = a16(cpu, 0), nseg = a16(cpu, 2), hmod = a16(cpu, 4);
    char name[128] = "";
    uint16_t seg = 0, off = 0;
    int ok;
    if (nseg) {                             /* by name */
        read_asciiz(cpu, nseg, noff, name, sizeof name);
        ok = ne_proc_address(hmod, name, 0, &seg, &off);
    } else {                                /* MAKEINTRESOURCE ordinal */
        snprintf(name, sizeof name, "@%u", noff);
        ok = ne_proc_address(hmod, NULL, noff, &seg, &off);
    }
    if (!ok && recomp_game.proc_address)    /* not lifted: the game may answer it */
        ok = recomp_game.proc_address(hmod, nseg ? name : NULL, nseg ? 0 : noff, &seg, &off);
    fprintf(stderr, "[win16] GetProcAddress(%04X, %s) -> %04X:%04X%s\n", hmod, name,
            seg, off, ok ? "" : "  (not a lifted export)");
    cpu->dx = ok ? seg : 0;
    cpu->ax = ok ? off : 0;
    ret(cpu, 6);
}

/* MakeProcInstance(lpProc, hInst): the thunk it built only loaded the module's
 * DGROUP into AX before jumping to lpProc. Here a callback gets its module's
 * DGROUP from recomp_dgroup_of_seg when it is entered, so the procedure's own
 * address is the right answer. Returning 0 registered Oddballz's window class
 * with a null WNDPROC. */
void KERNEL_MAKEPROCINSTANCE(CPU *cpu) {
    cpu->ax = a16(cpu, 2);                  /* offset of lpProc */
    cpu->dx = a16(cpu, 4);                  /* selector of lpProc */
    ret(cpu, 6);
}
void KERNEL_FREEPROCINSTANCE(CPU *cpu) { ret(cpu, 4); }

void KERNEL_FREELIBRARY(CPU *cpu) { cpu->ax = 1; ret(cpu, 2); }
void KERNEL_FREERESOURCE(CPU *cpu) { cpu->ax = 0; ret(cpu, 2); }  /* FALSE == still in use, ok */

void USER_LOADSTRING(CPU *cpu) {           /* LoadString(hInst,uID,lpBuf,nMax) */
    uint16_t hinst = a16(cpu, 8), id = a16(cpu, 6);
    uint16_t boff = a16(cpu, 2), bseg = a16(cpu, 4);
    int nmax = (int)a16(cpu, 0);
    char s[256];
    int n = ne_load_string(hinst, id, s, sizeof s);
    int k = 0;
    if (nmax > 0) {
        for (; k < n && k < nmax - 1; k++) mem_write8(cpu, bseg, (uint16_t)(boff + k), (uint8_t)s[k]);
        mem_write8(cpu, bseg, (uint16_t)(boff + k), 0);
    }
    IMPL_LOG("[win16] LoadString(%04X,%u) -> \"%s\" (%d)\n", hinst, id, n ? s : "", k);
    cpu->ax = (uint16_t)k;
    ret(cpu, 10);
}

/* Read a FindResource lpName/lpType arg: MAKEINTRESOURCE (seg==0) gives an int
 * id in `off`, otherwise it's a far asciiz string. */
static int res_arg(CPU *cpu, int off_idx, char *strbuf, int strmax) {
    uint16_t off = a16(cpu, off_idx), seg = a16(cpu, off_idx + 2);
    if (seg == 0) { strbuf[0] = 0; return (int)off; }   /* integer id */
    read_asciiz(cpu, seg, off, strbuf, strmax);
    return -1;                                          /* string in strbuf */
}

void KERNEL_FINDRESOURCE(CPU *cpu) {        /* FindResource(hInst,lpName,lpType) */
    uint16_t hinst = a16(cpu, 8);
    char tstr[64], nstr[64];
    int tint = res_arg(cpu, 0, tstr, sizeof tstr);   /* lpType @0/2 */
    int nint = res_arg(cpu, 4, nstr, sizeof nstr);   /* lpName @4/6 */
    uint16_t hrsrc = ne_find_resource(hinst, tint, tstr, nint, nstr);
    IMPL_LOG("[win16] FindResource(hInst=%04X type=%d/%s name=%d/%s) -> %04X\n",
             hinst, tint, tstr, nint, nstr, hrsrc);
    /* A resource the engine cannot find is never harmless -- it surfaces as a
       missing dialog or a blank bitmap much later. Report each miss once. */
    if (!hrsrc) {
        static struct { uint16_t h; int t, n; } told[32]; static int ntold;
        int seen = 0;
        for (int i = 0; i < ntold; i++)
            if (told[i].h == hinst && told[i].t == tint && told[i].n == nint) { seen = 1; break; }
        if (!seen) {
            if (ntold < 32) { told[ntold].h = hinst; told[ntold].t = tint;
                              told[ntold].n = nint; ntold++; }
            fprintf(stderr, "[res] FindResource MISS hInst=%04X type=%d/%s name=%d/%s\n",
                    hinst, tint, tstr, nint, nstr);
        }
    }
    cpu->ax = hrsrc;
    ret(cpu, 10);
}

void KERNEL_LOADRESOURCE(CPU *cpu) {        /* LoadResource(hInst,hResInfo) -> HGLOBAL */
    uint16_t hrsrc = a16(cpu, 0);
    uint32_t len = 0;
    const uint8_t *bytes = ne_resource_bytes(hrsrc, &len);
    if (!bytes) { cpu->ax = 0; ret(cpu, 4); return; }
    uint16_t sel = galloc(cpu, len);
    /* One contiguous copy: a block over 64 KB is tiled across consecutive
       selectors over one flat range (cpu_alloc_selector), and a per-byte write
       through `sel` with a 16-bit offset wrapped every resource past 64 KB --
       Oddballz's sounds -- back over its own first segment. */
    if (sel && cpu->sel_base[sel] + len <= cpu->mem_size)
        memcpy(cpu->mem + cpu->sel_base[sel], bytes, len);
    IMPL_LOG("[win16] LoadResource(hrsrc=%04X) -> sel=%04X (%u bytes)\n", hrsrc, sel, len);
    cpu->ax = sel;
    ret(cpu, 4);
}

void KERNEL_LOCKRESOURCE(CPU *cpu) {        /* LockResource(hResData) -> far ptr */
    uint16_t sel = a16(cpu, 0);
    cpu->dx = sel; cpu->ax = 0;             /* sel:0000 */
    ret(cpu, 2);
}

void KERNEL_SIZEOFRESOURCE(CPU *cpu) {      /* SizeofResource(hInst,hResInfo) -> DWORD */
    uint16_t hrsrc = a16(cpu, 0);
    uint32_t len = 0;
    ne_resource_bytes(hrsrc, &len);
    cpu->ax = (uint16_t)len;
    cpu->dx = (uint16_t)(len >> 16);        /* a DWORD: Oddballz's sounds pass 64K */
    ret(cpu, 4);
}

static uint16_t lfile_add(FILE *f);

/* AccessResource(hInst, hResInfo): a read-only file handle positioned at the
 * resource's bytes in its module. Stubbed, it returned 0 and Oddballz read a
 * size of 1 GB out of whatever handle 0 was. */
void KERNEL_ACCESSRESOURCE(CPU *cpu) {
    uint16_t hrsrc = a16(cpu, 0);
    char path[512]; uint32_t off = 0;
    FILE *f = ne_resource_file(hrsrc, path, sizeof path, &off) ? fopen(path, "rb") : NULL;
    if (f && fseek(f, (long)off, SEEK_SET) != 0) { fclose(f); f = NULL; }
    cpu->ax = f ? lfile_add(f) : 0xFFFF;    /* HFILE_ERROR */
    ret(cpu, 4);
}

/* ===== WING: WinG offscreen DIB blitting (the engine's render surface) =====
 * The engine WinGCreateDC()s a memory DC, WinGCreateBitmap()s an 8bpp DIB and
 * draws the pet into its pixel buffer, then WinGStretchBlt()s it to the window.
 * We give it a real guest-memory pixel buffer; presentation to the real window
 * is a no-op for now (gets the engine into its render loop). */
/* Every WinGCreateDC used to return the SAME handle, and the blit sourced from
 * whichever surface had been created last. The engine keeps several surfaces
 * live (the 1024x640 backdrop, a 640x480, a 168x333, a 288x288 ...) and picks
 * one per blit by selecting it into its DC, so "newest" was almost always the
 * wrong one -- the blitted surface held nothing but its clear colour. Hand out a
 * distinct DC per call and track which bitmap is selected into each. */
#define WING_DC_HANDLE 0x0DC0
/* One surface per live draw port. Six exist before the playpen even settles,
 * so a table of eight ran out after the player picked up two toys: further
 * surfaces got a handle but no slot, and every blit naming one silently fell
 * back to whichever surface was current. */
#define WING_DC_MAX    64
static struct { uint16_t hbm, sel; int w, h, bpp, topdown; uint8_t pal[256 * 4]; }
    g_wing[64];
static int g_wing_cur = -1;          /* last surface selected into any WinG DC */
static int g_nwing;
static uint16_t g_wingdc_sel[WING_DC_MAX];   /* WinG DC -> selected hbm */
static int g_nwingdc;

static int wing_index_of(uint16_t hbm) {
    for (int i = 0; i < g_nwing && i < (int)(sizeof g_wing / sizeof g_wing[0]); i++)
        if (g_wing[i].hbm == hbm) return i;
    return -1;
}

/* SelectObject routes here for WinG handles; returns the previous selection. */
uint16_t wing_select(uint16_t hdc, uint16_t hbm) {
    int d = (int)hdc - WING_DC_HANDLE;
    if (d < 0 || d >= WING_DC_MAX) return 0;
    uint16_t prev = g_wingdc_sel[d];
    g_wingdc_sel[d] = hbm;
    int i = wing_index_of(hbm);
    if (i >= 0) g_wing_cur = i;
    return prev;
}

/* Drawing GDI primitives onto a WinG surface.
 *
 * The engine draws its picture sprites -- the milk bottle, the cat's thought
 * cloud -- with Ellipse and Polygon aimed at a WinG DC. A WinG DC handle is not
 * in the host handle table, so every one of those calls resolved to a NULL HDC
 * and was thrown away: the bottle came off the shelf and simply was not there.
 *
 * A WinG surface is raw bytes inside guest memory, which GDI cannot draw on
 * directly. Keep a host memory DC over a matching DIB section per WinG DC, copy
 * the affected rectangle in before the call and back out after. Syncing only
 * that rectangle keeps it cheap -- these are twenty-pixel shapes. The DC
 * persists, so pens and brushes selected into it stay selected. */
static struct { HDC dc; HBITMAP bm; void *bits; HGDIOBJ obm; int i, w, h; }
    g_wdib[WING_DC_MAX];

static HDC wing_host_dc(CPU *cpu, uint16_t gdc, int *out_i) {
    int d = (int)gdc - WING_DC_HANDLE;
    if (d < 0 || d >= WING_DC_MAX) return NULL;
    /* The DC has to exist before any surface is selected into it: the engine
       selects its font and measures strings against a bare WinG DC, and with
       nothing to hand back those calls were lost -- GetTextExtent returned zero
       for every string, so the panel's menu bar was laid out zero columns wide
       and DrawText clipped "&Options" and "&Help" away to their underlines. */
    if (!g_wdib[d].dc) {
        g_wdib[d].dc = CreateCompatibleDC(NULL);
        g_wdib[d].i  = -1;
        if (!g_wdib[d].dc) return NULL;
    }
    int i = wing_index_of(g_wingdc_sel[d]);
    if (i < 0) return g_wdib[d].dc;            /* no surface yet: state only */
    if (out_i) *out_i = i;
    if (g_wdib[d].i == i) return g_wdib[d].dc;
    if (g_wdib[d].bm) {                        /* rebind to the new surface */
        SelectObject(g_wdib[d].dc, g_wdib[d].obm);
        DeleteObject(g_wdib[d].bm);
        g_wdib[d].bm = NULL; g_wdib[d].bits = NULL; g_wdib[d].i = -1;
    }
    if (g_wing[i].bpp != 8) return g_wdib[d].dc;
    unsigned char bi[sizeof(BITMAPINFOHEADER) + 256 * 4];
    memset(bi, 0, sizeof bi);
    BITMAPINFOHEADER *h = (BITMAPINFOHEADER *)bi;
    h->biSize = sizeof(BITMAPINFOHEADER);
    h->biWidth = g_wing[i].w; h->biHeight = -g_wing[i].h;
    h->biPlanes = 1; h->biBitCount = 8; h->biCompression = BI_RGB;
    h->biClrUsed = 256;
    memcpy(bi + sizeof(BITMAPINFOHEADER), g_wing[i].pal, 256 * 4);
    HDC dc = g_wdib[d].dc;
    void *bits = NULL;
    HBITMAP bm = CreateDIBSection(dc, (const BITMAPINFO *)bi, DIB_RGB_COLORS,
                                  &bits, NULL, 0);
    if (!bm || !bits) { if (bm) DeleteObject(bm); return dc; }
    g_wdib[d].obm  = SelectObject(dc, bm);
    g_wdib[d].bm   = bm;   g_wdib[d].bits = bits;
    g_wdib[d].i    = i;    g_wdib[d].w  = g_wing[i].w; g_wdib[d].h = g_wing[i].h;
    /* Give the DC the surface's own palette. The engine specifies its colours
       as PALETTEINDEX values, which resolve against the DC's logical palette --
       with none selected they landed on whatever GDI's default holds, and the
       shelf panel came out framed in blue. */
    {   struct { LOGPALETTE lp; PALETTEENTRY rest[255]; } p;
        p.lp.palVersion = 0x300; p.lp.palNumEntries = 256;
        for (int c = 0; c < 256; c++) {
            PALETTEENTRY *e = &p.lp.palPalEntry[c];
            e->peRed   = g_wing[i].pal[c * 4 + 2];
            e->peGreen = g_wing[i].pal[c * 4 + 1];
            e->peBlue  = g_wing[i].pal[c * 4 + 0];
            e->peFlags = 0;
        }
        HPALETTE hp = CreatePalette(&p.lp);
        if (hp) { SelectPalette(dc, hp, FALSE); RealizePalette(dc); }
    }
    return dc;
}

/* Copy one rectangle between the guest surface and the DIB the host DC draws on.
   `in` non-zero copies guest -> DIB, zero copies DIB -> guest. */
static void wing_sync(CPU *cpu, int d, const RECT *r, int in) {
    int i = g_wdib[d].i;
    uint32_t gst = (((uint32_t)g_wing[i].w * 8 + 31) / 32) * 4;
    uint32_t dst = (((uint32_t)g_wdib[d].w * 8 + 31) / 32) * 4;
    uint8_t *g = cpu->mem + seg_off(cpu, g_wing[i].sel, 0);
    uint8_t *b = (uint8_t *)g_wdib[d].bits;
    int x0 = r->left  < 0 ? 0 : r->left,  y0 = r->top    < 0 ? 0 : r->top;
    int x1 = r->right  > g_wdib[d].w ? g_wdib[d].w : r->right;
    int y1 = r->bottom > g_wdib[d].h ? g_wdib[d].h : r->bottom;
    for (int y = y0; y < y1; y++) {
        uint8_t *gp = g + (uint32_t)y * gst + x0;
        uint8_t *bp = b + (uint32_t)y * dst + x0;
        if (x1 > x0) memcpy(in ? bp : gp, in ? gp : bp, (size_t)(x1 - x0));
    }
}

/* State-only calls (SelectObject for a pen or brush, SetBkColor and friends)
   need the host DC but touch no pixels, so they need no sync. */
HDC wing_state_dc(CPU *cpu, uint16_t gdc) { return wing_host_dc(cpu, gdc, NULL); }

/* Public entry points used by the GDI shims. bounds is inflated by the caller
   to cover the pen width. Returns NULL when this is not a WinG DC. */
HDC wing_draw_begin(CPU *cpu, uint16_t gdc, const RECT *bounds) {
    int i = -1;
    HDC dc = wing_host_dc(cpu, gdc, &i);
    int d = (int)gdc - WING_DC_HANDLE;
    if (!dc || d < 0 || d >= WING_DC_MAX || !g_wdib[d].bits) return NULL;
    wing_sync(cpu, (int)gdc - WING_DC_HANDLE, bounds, 1);
    return dc;
}

void wing_draw_end(CPU *cpu, uint16_t gdc, const RECT *bounds) {
    int d = (int)gdc - WING_DC_HANDLE;
    if (d < 0 || d >= WING_DC_MAX || !g_wdib[d].bits) return;
    wing_sync(cpu, d, bounds, 0);
}

int wing_is_dc(uint16_t h)  { return h >= WING_DC_HANDLE && h < WING_DC_HANDLE + WING_DC_MAX; }
int wing_is_bmp(uint16_t h) { return wing_index_of(h) >= 0; }

void WING_WINGCREATEDC(CPU *cpu) {          /* WinGCreateDC(void) -> HDC */
    cpu->ax = (uint16_t)(WING_DC_HANDLE +
                         (g_nwingdc < WING_DC_MAX ? g_nwingdc++ : WING_DC_MAX - 1));
    IMPL_LOG("[win16] WinGCreateDC -> %04X\n", cpu->ax);
    ret(cpu, 0);
}

void WING_WINGRECOMMENDDIBFORMAT(CPU *cpu) {/* WinGRecommendDIBFormat(BITMAPINFO*) */
    uint16_t off = a16(cpu, 0), seg = a16(cpu, 2);
    /* Fill a top-down 8bpp BI_RGB BITMAPINFOHEADER. biHeight=-1 signals top-down. */
    mem_write32(cpu, seg, off + 0,  40);    /* biSize */
    mem_write32(cpu, seg, off + 4,  1);     /* biWidth (probe) */
    mem_write32(cpu, seg, off + 8,  (uint32_t)-1); /* biHeight = -1 -> top-down */
    mem_write16(cpu, seg, off + 12, 1);     /* biPlanes */
    mem_write16(cpu, seg, off + 14, 8);     /* biBitCount */
    mem_write32(cpu, seg, off + 16, 0);     /* biCompression = BI_RGB */
    cpu->ax = 1;
    ret(cpu, 4);
}

/* ===== palette =====
 * The engine builds its logical palette by first asking the system for the
 * current hardware palette, then handing the result to CreatePalette. Both were
 * stubs, so the LOGPALETTE it created was entirely zero -- every colour black,
 * which is what rendered the pet as a grey and black blob. It also leaves the
 * colour table in the BITMAPINFO it passes to WinGCreateBitmap blank and relies
 * on the realized palette instead, so that is the authoritative one here. */
static uint8_t g_active_pal[256 * 4];       /* RGBQUAD order: B,G,R,0 */
static int     g_have_pal;

#define MAXPAL 16
typedef struct { uint16_t h; uint8_t rgbq[256 * 4]; } GuestPalette;
static GuestPalette g_pals[MAXPAL];
static int g_npal;

/* A modern desktop is not palettised and Win32's own GetSystemPaletteEntries
 * returns nothing, so synthesise the classic 256-colour layout: 10 system
 * colours, a 6x6x6 colour cube, 10 more system colours. */
/* The game's own 256-colour palette ships as PALT 10256 (resource type 0x7F03,
 * 256 RGB triples) and its artwork is authored against it. On a real 256-colour
 * Win3.1 the system palette at this point already holds those colours; we cannot
 * reproduce that history, so serve the game's palette as the system palette --
 * without it the engine seeds from a generic ramp and every sprite comes out the
 * wrong colour. Falls back to the synthetic layout if the resource is missing. */
static uint8_t g_game_pal[256 * 3];
static int     g_game_pal_ok = -1;          /* -1 = not tried */

static int game_palette(void) {
    if (g_game_pal_ok >= 0) return g_game_pal_ok;
    g_game_pal_ok = 0;
    if (!recomp_game.palette_type) return 0;
    uint16_t hr = ne_find_resource(0, recomp_game.palette_type, NULL, recomp_game.palette_id, NULL);
    uint32_t len = 0;
    const uint8_t *p = hr ? ne_resource_bytes(hr, &len) : NULL;
    if (p && len >= 256 * 3) {
        memcpy(g_game_pal, p, 256 * 3);
        g_game_pal_ok = 1;
        fprintf(stderr, "[%s] using the game's own palette (resource %04X/%u)\n",
                recomp_game.title, recomp_game.palette_type, recomp_game.palette_id);
    }
    return g_game_pal_ok;
}

static void sys_palette_entry(unsigned i, uint8_t *r, uint8_t *g, uint8_t *b) {
    if (game_palette() && i < 256) {
        *r = g_game_pal[i * 3 + 0];
        *g = g_game_pal[i * 3 + 1];
        *b = g_game_pal[i * 3 + 2];
        return;
    }
    static const uint8_t sys[20][3] = {
        {0,0,0},{128,0,0},{0,128,0},{128,128,0},{0,0,128},{128,0,128},
        {0,128,128},{192,192,192},{192,220,192},{166,202,240},
        {255,251,240},{160,160,164},{128,128,128},{255,0,0},{0,255,0},
        {255,255,0},{0,0,255},{255,0,255},{0,255,255},{255,255,255},
    };
    if (i < 10)   { *r = sys[i][0];     *g = sys[i][1];     *b = sys[i][2];     return; }
    if (i >= 246) { *r = sys[i-236][0]; *g = sys[i-236][1]; *b = sys[i-236][2]; return; }
    unsigned c = i - 10;
    if (c < 216) {
        static const uint8_t lv[6] = {0, 51, 102, 153, 204, 255};
        *r = lv[(c / 36) % 6]; *g = lv[(c / 6) % 6]; *b = lv[c % 6];
    } else {
        uint8_t v = (uint8_t)(((c - 216) * 255) / 19);
        *r = *g = *b = v;
    }
}

void GDI_GETSYSTEMPALETTEENTRIES(CPU *cpu) { /* (hdc@8, iStart@6, n@4, lppe@0/2) */
    uint16_t start = a16(cpu, 6), n = a16(cpu, 4);
    uint16_t off = a16(cpu, 0), seg = a16(cpu, 2);
    uint16_t got = 0;
    if (seg) {
        for (; got < n && (unsigned)(start + got) < 256; got++) {
            uint8_t r, g, b;
            sys_palette_entry((unsigned)(start + got), &r, &g, &b);
            uint16_t e = (uint16_t)(off + got * 4);
            mem_write8(cpu, seg, e, r);
            mem_write8(cpu, seg, (uint16_t)(e + 1), g);
            mem_write8(cpu, seg, (uint16_t)(e + 2), b);
            mem_write8(cpu, seg, (uint16_t)(e + 3), 0);
        }
    }
    cpu->ax = got;
    ret(cpu, 10);
}

void GDI_GETSYSTEMPALETTEUSE(CPU *cpu) {     /* (hdc@0) -> SYSPAL_STATIC */
    cpu->ax = 1;
    ret(cpu, 2);
}

/* Win16 LOGPALETTE: palVersion@0(2) palNumEntries@2(2) then PALETTEENTRY[]
 * {peRed, peGreen, peBlue, peFlags}. GDI wants RGBQUAD {B,G,R,0}. */
void GDI_CREATEPALETTE(CPU *cpu) {           /* (lpLogPalette@0/2) */
    uint16_t off = a16(cpu, 0), seg = a16(cpu, 2);
    uint16_t handle = 0;
    if (seg && g_npal < MAXPAL) {
        unsigned n = mem_read16(cpu, seg, (uint16_t)(off + 2));
        if (n > 256) n = 256;
        GuestPalette *p = &g_pals[g_npal];
        memset(p->rgbq, 0, sizeof p->rgbq);
        for (unsigned c = 0; c < n; c++) {
            uint16_t e = (uint16_t)(off + 4 + c * 4);
            p->rgbq[c * 4 + 2] = mem_read8(cpu, seg, e);                   /* R */
            p->rgbq[c * 4 + 1] = mem_read8(cpu, seg, (uint16_t)(e + 1));   /* G */
            p->rgbq[c * 4 + 0] = mem_read8(cpu, seg, (uint16_t)(e + 2));   /* B */
        }
        handle = (uint16_t)(0x0E00 + (++g_npal));
        p->h = handle;
        if (getenv("RECOMP_LOG_PAL")) {     /* what the guest asked for, flags included */
            unsigned flags[4] = { 0 };
            for (unsigned c = 0; c < n; c++) {
                uint8_t f = mem_read8(cpu, seg, (uint16_t)(off + 4 + c * 4 + 3));
                flags[f & 1 ? 1 : f & 2 ? 2 : f & 4 ? 3 : 0]++;
            }
            fprintf(stderr, "[pal] CreatePalette %04X: %u entries; flags none=%u "
                    "RESERVED=%u EXPLICIT=%u NOCOLLAPSE=%u; first:", handle, n,
                    flags[0], flags[1], flags[2], flags[3]);
            for (unsigned c = 0; c < n && c < 12; c++)
                fprintf(stderr, " %02X%02X%02X/%X", p->rgbq[c * 4 + 2], p->rgbq[c * 4 + 1],
                        p->rgbq[c * 4], mem_read8(cpu, seg, (uint16_t)(off + 4 + c * 4 + 3)));
            fprintf(stderr, "\n");
        }
        /* Adopt the first one immediately so a surface created before any
           SelectPalette still gets real colours. */
        if (!g_have_pal) { memcpy(g_active_pal, p->rgbq, sizeof g_active_pal); g_have_pal = 1; }
        IMPL_LOG("[win16] CreatePalette(%u entries) -> %04X\n", n, handle);
    }
    cpu->ax = handle;
    ret(cpu, 4);
}

void USER_SELECTPALETTE(CPU *cpu) {          /* (hdc@4, hpal@2, bForceBkgd@0) */
    uint16_t h = a16(cpu, 2);
    for (int i = 0; i < g_npal; i++)
        if (g_pals[i].h == h) {
            /* Surfaces snapshot the palette when they are created, so a later
               palette swap leaves every existing surface holding a stale colour
               table while the engine draws indices meant for the new one. Say so
               if the contents actually change. */
            if (g_have_pal && memcmp(g_active_pal, g_pals[i].rgbq,
                                     sizeof g_active_pal) != 0) {
                static int n;
                fprintf(stderr, "[pal] active palette REPLACED (%04X), change #%d\n", h, ++n);
            }
            memcpy(g_active_pal, g_pals[i].rgbq, sizeof g_active_pal);
            g_have_pal = 1;
            break;
        }
    cpu->ax = 0;
    ret(cpu, 6);
}

void USER_REALIZEPALETTE(CPU *cpu) {         /* (hdc@0) */
    cpu->ax = 0;
    ret(cpu, 2);
}

/* A scratch guest block for marshalling host structures the engine expects to
 * read through a far pointer (WM_DRAWITEM's DRAWITEMSTRUCT, so far). One
 * segment is enough: each use is consumed inside a single WNDPROC call. */
/* SetDIBitsToDevice. This was a stub returning 0, and it is how the adoption
 * dialog paints each breed's portrait: the five buttons are owner-drawn, so the
 * engine answers WM_DRAWITEM by pushing a DIB straight at the button's DC. With
 * it doing nothing the five panels came up blank and there was nothing to pick.
 *
 * Win16 args (PASCAL, last pushed at offset 0):
 *   wUsage@0 lpbmi@2(4) lpBits@6(4) nNumScans@10 nStartScan@12
 *   YSrc@14 XSrc@16 nHeight@18 nWidth@20 YDest@22 XDest@24 hdc@26 */
void GDI_SETDIBITSTODEVICE(CPU *cpu) {
    uint16_t usage = a16(cpu, 0);
    uint16_t bmio = a16(cpu, 2),  bmis = a16(cpu, 4);
    uint16_t bito = a16(cpu, 6),  bits = a16(cpu, 8);
    uint16_t nscans = a16(cpu, 10), start = a16(cpu, 12);
    int ysrc = (int16_t)a16(cpu, 14), xsrc = (int16_t)a16(cpu, 16);
    int hgt  = (int16_t)a16(cpu, 18), wid  = (int16_t)a16(cpu, 20);
    int ydst = (int16_t)a16(cpu, 22), xdst = (int16_t)a16(cpu, 24);
    uint16_t ghdc = a16(cpu, 26);

    extern HDC recomp_real_hdc(uint16_t);
    HDC dc = recomp_real_hdc(ghdc);
    if (!dc || !bmis || !bits) { cpu->ax = 0; ret(cpu, 28); return; }

    unsigned char bi[sizeof(BITMAPINFOHEADER) + 256 * 4];
    memset(bi, 0, sizeof bi);
    for (unsigned k = 0; k < sizeof(BITMAPINFOHEADER); k++)
        bi[k] = mem_read8(cpu, bmis, (uint16_t)(bmio + k));
    BITMAPINFOHEADER *h = (BITMAPINFOHEADER *)bi;
    if (h->biSize != sizeof(BITMAPINFOHEADER) || h->biBitCount == 0) {
        cpu->ax = 0; ret(cpu, 28); return;
    }
    uint8_t *tab = bi + sizeof(BITMAPINFOHEADER);
    if (h->biBitCount <= 8) {
        unsigned n = h->biClrUsed ? h->biClrUsed : (1u << h->biBitCount);
        if (n > 256) n = 256;
        if (usage == 1) {                 /* DIB_PAL_COLORS: 16-bit palette indices */
            for (unsigned c = 0; c < n; c++) {
                unsigned idx = mem_read16(cpu, bmis,
                                          (uint16_t)(bmio + 40 + c * 2)) & 0xFF;
                memcpy(tab + c * 4, g_active_pal + idx * 4, 4);
            }
            h->biClrUsed = n;
        } else {
            int any = 0;
            for (unsigned c = 0; c < n * 4; c++)
                if ((tab[c] = mem_read8(cpu, bmis, (uint16_t)(bmio + 40 + c)))) any = 1;
            /* Same story as the WinG surfaces: the engine leaves the table blank
               and relies on the palette it realized. */
            if (!any && g_have_pal) memcpy(tab, g_active_pal, n * 4);
        }
    }
    int r = SetDIBitsToDevice(dc, xdst, ydst, (DWORD)wid, (DWORD)hgt,
                              xsrc, ysrc, start, nscans,
                              cpu->mem + seg_off(cpu, bits, bito),
                              (const BITMAPINFO *)bi,
                              usage == 1 ? DIB_PAL_COLORS : DIB_RGB_COLORS);
    IMPL_LOG("[win16] SetDIBitsToDevice %dx%d at (%d,%d) -> %d\\n", wid, hgt, xdst, ydst, r);
    cpu->ax = (uint16_t)r;
    ret(cpu, 28);
}

uint16_t recomp_guest_scratch(CPU *cpu, uint32_t bytes) {
    static uint16_t sel; static uint32_t have;
    if (!sel || have < bytes) { sel = galloc(cpu, bytes < 256 ? 256 : bytes);
                                have = bytes < 256 ? 256 : bytes; }
    return sel;
}

void WING_WINGCREATEBITMAP(CPU *cpu) {      /* WinGCreateBitmap(HDC,BITMAPINFO*,void**) */
    uint16_t ppoff = a16(cpu, 0), ppseg = a16(cpu, 2);   /* ppBits (void FAR* FAR*) */
    uint16_t hoff  = a16(cpu, 4), hseg  = a16(cpu, 6);   /* pHeader */
    int w = (int)mem_read32(cpu, hseg, hoff + 4);
    int h = (int)mem_read32(cpu, hseg, hoff + 8);
    int bpp = mem_read16(cpu, hseg, hoff + 14); if (!bpp) bpp = 8;
    if (h < 0) h = -h;
    if (w <= 0) w = 1; if (h <= 0) h = 1;
    uint32_t stride = (((uint32_t)w * bpp + 31) / 32) * 4;
    uint32_t size = stride * (uint32_t)h;
    uint16_t sel = galloc(cpu, size ? size : 1);
    /* write the DIB pixel pointer (sel:0000) into *ppBits */
    if (ppseg || ppoff) { mem_write16(cpu, ppseg, ppoff, 0); mem_write16(cpu, ppseg, (uint16_t)(ppoff + 2), sel); }
    uint16_t hbm = (uint16_t)(0x0B00 + (++g_nwing));
    if (g_nwing <= (int)(sizeof g_wing / sizeof g_wing[0])) {
        int i = g_nwing - 1;
        g_wing[i].hbm = hbm; g_wing[i].sel = sel;
        g_wing[i].w = w; g_wing[i].h = h; g_wing[i].bpp = bpp;
        g_wing[i].topdown = ((int)mem_read32(cpu, hseg, hoff + 8) < 0);
        /* The colour table follows the 40-byte header in the caller's
         * BITMAPINFO — WinG has no SetDIBColorTable import, so this is the only
         * place the palette is handed to us. Without it the blit is grey mush. */
        if (bpp <= 8) {
            /* Prefer the realized palette: the engine leaves this BITMAPINFO's
               table blank and supplies its colours through CreatePalette.
               Testing the caller's table for "empty" is not enough -- stale
               bytes further into the buffer make it look populated while the
               entries that matter are all black. */
            if (getenv("RECOMP_LOG_PAL")) {
                fprintf(stderr, "[pal] WinGCreateBitmap %dx%d: guest table first:", w, h);
                for (unsigned c = 0; c < 12; c++)
                    fprintf(stderr, " %02X%02X%02X", mem_read8(cpu, hseg, (uint16_t)(hoff + 40 + c * 4 + 2)),
                            mem_read8(cpu, hseg, (uint16_t)(hoff + 41 + c * 4)),
                            mem_read8(cpu, hseg, (uint16_t)(hoff + 40 + c * 4)));
                fprintf(stderr, "  (active palette %s)\n", g_have_pal ? "used" : "absent");
            }
            /* ...but only when the caller's table is not a real one. An
               identity table for an 8-bit WinG surface starts with the ten
               Windows static colours; a table that does is what the art is
               indexed against. Oddballz passes exactly that, with a DIFFERENT
               logical palette selected (its entry 10 is black where the art's
               is white), and preferring the logical palette recoloured every
               sprite. Catz passes a blank table, so it still falls through. */
            static const uint8_t STATIC10[10][3] = {
                {0x00,0x00,0x00},{0x80,0x00,0x00},{0x00,0x80,0x00},{0x80,0x80,0x00},
                {0x00,0x00,0x80},{0x80,0x00,0x80},{0x00,0x80,0x80},{0xC0,0xC0,0xC0},
                {0xC0,0xDC,0xC0},{0xA6,0xCA,0xF0} };
            int identity = bpp == 8;
            for (unsigned c = 0; identity && c < 10; c++)
                identity = mem_read8(cpu, hseg, (uint16_t)(hoff + 42 + c * 4)) == STATIC10[c][0]
                        && mem_read8(cpu, hseg, (uint16_t)(hoff + 41 + c * 4)) == STATIC10[c][1]
                        && mem_read8(cpu, hseg, (uint16_t)(hoff + 40 + c * 4)) == STATIC10[c][2];
            if (identity) {
                for (unsigned c = 0; c < 256; c++)
                    for (int b = 0; b < 4; b++)
                        g_wing[i].pal[c * 4 + b] =
                            mem_read8(cpu, hseg, (uint16_t)(hoff + 40 + c * 4 + b));
            } else if (g_have_pal) {
                memcpy(g_wing[i].pal, g_active_pal, sizeof g_wing[i].pal);
            } else {
                unsigned n = 1u << bpp;
                for (unsigned c = 0; c < n && c < 256; c++)
                    for (int b = 0; b < 4; b++)
                        g_wing[i].pal[c * 4 + b] =
                            mem_read8(cpu, hseg, (uint16_t)(hoff + 40 + c * 4 + b));
            }
        }
        g_wing_cur = i;                 /* newest bitmap is the active surface */
    }
    IMPL_LOG("[win16] WinGCreateBitmap %dx%dx%d -> hbm=%04X bits=%04X:0000 (%u B)\n", w, h, bpp, hbm, sel, size);
    cpu->ax = hbm;
    ret(cpu, 10);
}

/* WinGStretchBlt(hdcDest, xDest, yDest, wDest, hDest,
 *                hdcSrc,  xSrc,  ySrc,  wSrc,  hSrc) -> BOOL
 * The source is the WinG DC with a WinG bitmap selected into it; that bitmap's
 * pixels live in guest memory at sel:0000, so the "blit" is StretchDIBits from
 * guest memory straight onto the real destination DC. This is the engine's
 * only path to the screen — it was a no-op returning TRUE, which is why the
 * window stayed blank even when the engine was drawing. */
/* What the window has been shown.
 *
 * A Win16 app repaints only what changed and assumes the window keeps the rest;
 * Windows makes no such promise. Anything that exposes the frame -- another
 * window passing over it, an activation, a restore -- leaves those pixels
 * undefined, and the engine will not redraw them because as far as it is
 * concerned they are already correct. Over the static parts of the playpen that
 * is never, so the exposed area simply stays black until something happens to
 * move across it. Keep every blit here as well, and paint it back on demand. */
#define PRESENT_W 1024
#define PRESENT_H 768
static uint8_t g_present[PRESENT_H][PRESENT_W];
static uint8_t g_present_pal[256 * 4];
static int     g_present_live;
static int     g_present_w, g_present_h;   /* how much has ever been drawn */

void recomp_present_paint(void *hdc) {
    if (!g_present_live) return;
    unsigned char bi[sizeof(BITMAPINFOHEADER) + 256 * 4];
    memset(bi, 0, sizeof bi);
    BITMAPINFOHEADER *h = (BITMAPINFOHEADER *)bi;
    h->biSize = sizeof(BITMAPINFOHEADER);
    h->biWidth = PRESENT_W; h->biHeight = -PRESENT_H;
    h->biPlanes = 1; h->biBitCount = 8; h->biCompression = BI_RGB;
    h->biClrUsed = 256;
    memcpy(bi + sizeof(BITMAPINFOHEADER), g_present_pal, 256 * 4);
    int pw = g_present_w, ph = g_present_h;
    if (pw <= 0 || ph <= 0) return;
    SetStretchBltMode((HDC)hdc, COLORONCOLOR);
    /* Source y is measured from the bottom for a bottom-up DIB; ours is stored
       top-down (negative height), so the rows line up directly. */
    StretchDIBits((HDC)hdc, 0, 0, pw, ph, 0, 0, pw, ph,
                  g_present, (const BITMAPINFO *)bi, DIB_RGB_COLORS, SRCCOPY);
    /* Belt and braces: if the client is somehow larger than anything the engine
       has drawn, fill the remainder with the backdrop's own colour rather than
       leaving raw black there. */
    HWND ow = WindowFromDC((HDC)hdc);
    RECT cr;
    if (ow && GetClientRect(ow, &cr)
        && (cr.right > pw || cr.bottom > ph)) {
        uint8_t idx = g_present[ph - 1][pw - 1];
        HBRUSH b = CreateSolidBrush(RGB(g_present_pal[idx * 4 + 2],
                                        g_present_pal[idx * 4 + 1],
                                        g_present_pal[idx * 4 + 0]));
        if (b) {
            RECT r;
            if (cr.right > pw) {
                r.left = pw; r.top = 0; r.right = cr.right; r.bottom = cr.bottom;
                FillRect((HDC)hdc, &r, b);
            }
            if (cr.bottom > ph) {
                r.left = 0; r.top = ph; r.right = cr.right; r.bottom = cr.bottom;
                FillRect((HDC)hdc, &r, b);
            }
            DeleteObject(b);
        }
    }
}

/* RECOMP_DUMP_WIN=<n>: replay every blit into a private canvas and write it out
   after n blits -- exactly what reaches the window, without screen capture. */
static uint8_t g_canvas[768][1024];
static uint8_t g_canvas_pal[256 * 4];
/* RECOMP_DIFF=<n>: dump what changed on a surface between consecutive blits of
   it -- i.e. exactly what the moving sprite drew, with its bounding box. */
static void surf_diff(CPU *cpu, int i, int nth) {
    static uint8_t *prev; static int prev_i = -1; static int seen;
    uint32_t st = (((uint32_t)g_wing[i].w * g_wing[i].bpp + 31) / 32) * 4;
    uint32_t nb = st * (uint32_t)g_wing[i].h;
    const uint8_t *cur = cpu->mem + seg_off(cpu, g_wing[i].sel, 0);
    if (prev_i != i) { free(prev); prev = malloc(nb); prev_i = i; seen = 0;
                       if (prev) memcpy(prev, cur, nb); return; }
    if (!prev) return;
    int l = g_wing[i].w, t = g_wing[i].h, r = -1, b = -1;
    unsigned nd = 0;
    for (int y = 0; y < g_wing[i].h; y++)
        for (int x = 0; x < g_wing[i].w; x++)
            if (cur[(uint32_t)y * st + x] != prev[(uint32_t)y * st + x]) {
                nd++;
                if (x < l) l = x; if (x > r) r = x;
                if (y < t) t = y; if (y > b) b = y;
            }
    if (nd && ++seen == nth) {
        fprintf(stderr, "[diff] surf%d %u px changed, bbox (%d,%d)-(%d,%d) %dx%d\n",
                i, nd, l, t, r, b, r - l + 1, b - t + 1);
        int w = r - l + 1, h = b - t + 1;
        uint32_t ost = ((uint32_t)w + 3) & ~3u, nbits = ost * (uint32_t)h;
        uint8_t *img = calloc(nbits, 1);
        if (img) {
            for (int y = 0; y < h; y++)
                for (int x = 0; x < w; x++) {
                    uint8_t c = cur[(uint32_t)(t + y) * st + (l + x)];
                    if (c != prev[(uint32_t)(t + y) * st + (l + x)]) img[(uint32_t)y * ost + x] = c;
                }
            char path[512];
            snprintf(path, sizeof path, "%s/diff.bmp",
                     getenv("RECOMP_DUMP_DIR") ? getenv("RECOMP_DUMP_DIR") : ".");
            FILE *f = fopen(path, "wb");
            if (f) {
                uint32_t offb = 14 + 40 + 256 * 4, fsz = offb + nbits;
                uint8_t fh[14] = {'B','M'};
                memcpy(fh + 2, &fsz, 4); memcpy(fh + 10, &offb, 4);
                BITMAPINFOHEADER ih; memset(&ih, 0, sizeof ih);
                ih.biSize = 40; ih.biWidth = w; ih.biHeight = -h; ih.biPlanes = 1;
                ih.biBitCount = 8; ih.biCompression = BI_RGB;
                ih.biSizeImage = nbits; ih.biClrUsed = 256;
                fwrite(fh, 1, 14, f); fwrite(&ih, 1, 40, f);
                fwrite(g_wing[i].pal, 1, 256 * 4, f);
                fwrite(img, 1, nbits, f); fclose(f);
                fprintf(stderr, "[diff] wrote %s\n", path);
            }
            free(img);
        }
    }
    memcpy(prev, cur, nb);
}

/* RECOMP_STALE=<n>: age map over the composited canvas. Every blit stamps the
   pixels it covers with the current blit number; after 2n blits we write out
   only the pixels that have NOT been rewritten in the last n blits. Anything
   showing there is screen content the engine has stopped repainting -- i.e.
   the trail -- and its position says which region is being missed. */
static int g_age[768][1024];
static void stale_dump(int nblt, int win) {
    char path[512];
    snprintf(path, sizeof path, "%s/stale.bmp",
             getenv("RECOMP_DUMP_DIR") ? getenv("RECOMP_DUMP_DIR") : ".");
    FILE *f = fopen(path, "wb");
    if (!f) return;
    static uint8_t img[768][1024];
    unsigned nstale = 0;
    for (int y = 0; y < 768; y++)
        for (int x = 0; x < 1024; x++) {
            int fresh = (nblt - g_age[y][x]) <= win;
            img[y][x] = (!fresh && g_canvas[y][x]) ? g_canvas[y][x] : 0;
            if (img[y][x]) nstale++;
        }
    uint32_t nbits = 1024u * 768u, offb = 14 + 40 + 256 * 4, fsz = offb + nbits;
    uint8_t fh[14] = {'B','M'};
    memcpy(fh + 2, &fsz, 4); memcpy(fh + 10, &offb, 4);
    BITMAPINFOHEADER ih; memset(&ih, 0, sizeof ih);
    ih.biSize = 40; ih.biWidth = 1024; ih.biHeight = -768; ih.biPlanes = 1;
    ih.biBitCount = 8; ih.biCompression = BI_RGB; ih.biSizeImage = nbits;
    ih.biClrUsed = 256;
    fwrite(fh, 1, 14, f); fwrite(&ih, 1, 40, f);
    fwrite(g_canvas_pal, 1, 256 * 4, f);
    fwrite(img, 1, nbits, f); fclose(f);
    fprintf(stderr, "[stale] %u px not repainted in the last %d blits -> %s\n",
            nstale, win, path);
}

static void canvas_dump(int tag) {
    char path[512];
    snprintf(path, sizeof path, "%s/win%d.bmp",
             getenv("RECOMP_DUMP_DIR") ? getenv("RECOMP_DUMP_DIR") : ".", tag);
    FILE *f = fopen(path, "wb");
    if (!f) return;
    uint32_t nbits = 1024u * 768u, offb = 14 + 40 + 256 * 4, fsz = offb + nbits;
    uint8_t fh[14] = {'B','M'};
    memcpy(fh + 2, &fsz, 4); memcpy(fh + 10, &offb, 4);
    BITMAPINFOHEADER ih; memset(&ih, 0, sizeof ih);
    ih.biSize = 40; ih.biWidth = 1024; ih.biHeight = -768; ih.biPlanes = 1;
    ih.biBitCount = 8; ih.biCompression = BI_RGB; ih.biSizeImage = nbits;
    ih.biClrUsed = 256;
    fwrite(fh, 1, 14, f); fwrite(&ih, 1, 40, f);
    fwrite(g_canvas_pal, 1, 256 * 4, f);
    fwrite(g_canvas, 1, nbits, f);
    fclose(f);
    fprintf(stderr, "[win] wrote %s\n", path);
}

void WING_WINGSTRETCHBLT(CPU *cpu);
/* GDI StretchBlt. This was a stub returning 0, and it is how the engine puts the
 * saved backdrop back over the pet's old position -- a WinG surface onto another
 * WinG surface, which never went near a real HDC. With it doing nothing, the
 * previous frame was never erased and the pet smeared across the playpen.
 *
 * Win16 args (PASCAL, so the last pushed sits at offset 0):
 *   dwRop@0(4) hSrc@4 wSrc@6 ySrc@8 xSrc@10 hdcSrc@12
 *   hDest@14 wDest@16 yDest@18 xDest@20 hdcDest@22
 * Re-frame them as WinGStretchBlt's 20-byte list and reuse that path: bumping sp
 * by 4 first leaves it popping exactly the 24 bytes StretchBlt owes. */
/* BitBlt is StretchBlt with the source and destination the same size, so give
 * it the same treatment -- including the surface-to-surface path, since the
 * engine aims these at WinG DCs too.
 *
 * Win16 args: dwRop@0(4) nYSrc@4 nXSrc@6 hdcSrc@8 nHeight@10 nWidth@12
 *             nYDest@14 nXDest@16 hdcDest@18 */
void GDI_BITBLT(CPU *cpu) {
    uint16_t a[10];
    a[9] = a16(cpu, 18); a[8] = a16(cpu, 16); a[7] = a16(cpu, 14);  /* hdc x y  */
    a[6] = a16(cpu, 12); a[5] = a16(cpu, 10);                       /* w h dest */
    a[4] = a16(cpu, 8);  a[3] = a16(cpu, 6);  a[2] = a16(cpu, 4);   /* hdc x y  */
    a[1] = a16(cpu, 12); a[0] = a16(cpu, 10);                       /* w h src  */
    cpu->sp += 0;
    for (int k = 0; k < 10; k++)
        mem_write16(cpu, cpu->ss, (uint16_t)(cpu->sp + 4 + k * 2), a[k]);
    WING_WINGSTRETCHBLT(cpu);            /* pops 4 + 20, which is what we owe */
}

void GDI_STRETCHBLT(CPU *cpu) {
    if (getenv("RECOMP_LOG_ROP")) { static int n; if (n++ < 40)
        fprintf(stderr, "[rop] StretchBlt rop=%08lX\n",
                (unsigned long)a32(cpu, 0)); }
    uint16_t a[10];
    a[9] = a16(cpu, 22); a[8] = a16(cpu, 20); a[7] = a16(cpu, 18);   /* hdcDest x y */
    a[6] = a16(cpu, 16); a[5] = a16(cpu, 14);                        /* wDest hDest */
    a[4] = a16(cpu, 12); a[3] = a16(cpu, 10); a[2] = a16(cpu, 8);    /* hdcSrc x y  */
    a[1] = a16(cpu, 6);  a[0] = a16(cpu, 4);                         /* wSrc  hSrc  */
    cpu->sp += 4;
    for (int k = 0; k < 10; k++)
        mem_write16(cpu, cpu->ss, (uint16_t)(cpu->sp + 4 + k * 2), a[k]);
    WING_WINGSTRETCHBLT(cpu);            /* pops 4 + 20, i.e. our 4 + 24 total */
}

void WING_WINGSTRETCHBLT(CPU *cpu) {
    int hSrc  = (int16_t)a16(cpu, 0),  wSrc  = (int16_t)a16(cpu, 2);
    int ySrc  = (int16_t)a16(cpu, 4),  xSrc  = (int16_t)a16(cpu, 6);
    int hDest = (int16_t)a16(cpu, 10), wDest = (int16_t)a16(cpu, 12);
    int yDest = (int16_t)a16(cpu, 14), xDest = (int16_t)a16(cpu, 16);
    uint16_t hdcDest = a16(cpu, 18);
    uint16_t hdcSrc  = a16(cpu, 8);

    extern HDC recomp_real_hdc(uint16_t);

    int i = -1;
    {   int d = (int)hdcSrc - WING_DC_HANDLE;
        if (d >= 0 && d < WING_DC_MAX) i = wing_index_of(g_wingdc_sel[d]);
    }
    if (i < 0) {
        /* Falling back to "whichever surface was selected last anywhere" is a
           guess, and with more than one sprite live it is usually the wrong
           one. Count it so the guess is not invisible. */
        static long nfb; static int told;
        nfb++;
        if (getenv("RECOMP_LOG_FALLBACK") && told < 12) { told++;
            fprintf(stderr, "[fallback] blit src hdc=%04X has no surface; using surf%d (%ld so far)\n", hdcSrc, g_wing_cur, nfb); }
        i = g_wing_cur;
    }
    if (i < 0) { cpu->ax = 0; ret(cpu, 20); return; }

    /* Surface-to-surface. The engine restores the saved backdrop by blitting one
     * WinG surface onto another, and a WinG DC handle is not in the host handle
     * table, so recomp_real_hdc gave NULL and every one of those copies was thrown
     * away. Nothing ever erased the previous frame, so the pet accumulated in
     * the scene surface and smeared across the playpen. Copy the pixels here. */
    {   int d = (int)hdcDest - WING_DC_HANDLE, j = -1;
        if (d >= 0 && d < WING_DC_MAX) j = wing_index_of(g_wingdc_sel[d]);
        if (j >= 0) {
            uint32_t ss = (((uint32_t)g_wing[i].w * g_wing[i].bpp + 31) / 32) * 4;
            uint32_t ds = (((uint32_t)g_wing[j].w * g_wing[j].bpp + 31) / 32) * 4;
            const uint8_t *sp = cpu->mem + seg_off(cpu, g_wing[i].sel, 0);
            uint8_t *dp = cpu->mem + seg_off(cpu, g_wing[j].sel, 0);
            /* Scrolling a surface onto itself overlaps, so walk each axis away
             * from the destination the way memmove would; copying forward
             * through an overlap combs the image into vertical stripes. */
            if (getenv("RECOMP_LOG_EDGE")) {
                int so = (xSrc < 0 || ySrc < 0 ||
                          xSrc + wSrc > g_wing[i].w || ySrc + hSrc > g_wing[i].h);
                int do_ = (xDest < 0 || yDest < 0 ||
                           xDest + wDest > g_wing[j].w || yDest + hDest > g_wing[j].h);
                if (so || do_) { static long n; n++;
                    if (n < 12 || (n % 200) == 0)
                        fprintf(stderr, "[edge-s2s] %s surf%d(%d,%d %dx%d)[%dx%d] -> surf%d(%d,%d %dx%d)[%dx%d] n=%ld\n",
                            so && do_ ? "both" : so ? "src" : "dst",
                            i, xSrc, ySrc, wSrc, hSrc, g_wing[i].w, g_wing[i].h,
                            j, xDest, yDest, wDest, hDest, g_wing[j].w, g_wing[j].h, n); }
            }
            int ydn = !(i == j && yDest > ySrc), xdn = !(i == j && xDest > xSrc);
            for (int k = 0; k < hDest && hSrc > 0; k++) {
                int dy = ydn ? k : hDest - 1 - k;
                int oy = yDest + dy;
                if (oy < 0 || oy >= g_wing[j].h) continue;
                int sy = ySrc + (int)((long)dy * hSrc / hDest);
                if (sy < 0 || sy >= g_wing[i].h) continue;
                for (int m = 0; m < wDest && wSrc > 0; m++) {
                    int dx = xdn ? m : wDest - 1 - m;
                    int ox = xDest + dx;
                    if (ox < 0 || ox >= g_wing[j].w) continue;
                    int sx = xSrc + (int)((long)dx * wSrc / wDest);
                    if (sx < 0 || sx >= g_wing[i].w) continue;
                    dp[(uint32_t)oy * ds + ox] = sp[(uint32_t)sy * ss + sx];
                }
            }
            if (getenv("RECOMP_LOG_S2S")) { static int n;
                if (n++ < atoi(getenv("RECOMP_LOG_S2S")))
                    fprintf(stderr, "[s2s] %4d surf%d(%d,%d %dx%d) -> surf%d(%d,%d %dx%d)\n",
                            n, i, xSrc, ySrc, wSrc, hSrc, j, xDest, yDest, wDest, hDest); }
            cpu->ax = 1;
            ret(cpu, 20);
            return;
        }
    }

    HDC dst = recomp_real_hdc(hdcDest);
    if (!dst) { cpu->ax = 0; ret(cpu, 20); return; }
    /* BITMAPINFOHEADER + 256-entry palette, laid out as GDI32 wants it. */
    unsigned char bi[sizeof(BITMAPINFOHEADER) + 256 * 4];
    memset(bi, 0, sizeof bi);
    BITMAPINFOHEADER *h = (BITMAPINFOHEADER *)bi;
    h->biSize   = sizeof(BITMAPINFOHEADER);
    h->biWidth  = g_wing[i].w;
    /* Negative height = top-down, which is what WinG surfaces are. */
    h->biHeight = g_wing[i].topdown ? -g_wing[i].h : g_wing[i].h;
    h->biPlanes = 1;
    h->biBitCount = (WORD)g_wing[i].bpp;
    h->biCompression = BI_RGB;
    if (g_wing[i].bpp <= 8)
        memcpy(bi + sizeof(BITMAPINFOHEADER), g_wing[i].pal, 256 * 4);

    /* RECOMP_DUMP_BLIT=<n>: write the nth source surface out as a .bmp so the
       actual pixels and colour table can be inspected directly. Diagnostic. */
    {
        static int seen = 0;
        static uint16_t dumped[16]; static int ndumped;
        const char *want = getenv("RECOMP_DUMP_BLIT");
        int nth = want ? atoi(want) : -1;
        int all = want && want[0] == 'a';    /* RECOMP_DUMP_BLIT=all: one per surface */
        int go = 0;
        int snap = want && want[0] == 's';   /* RECOMP_DUMP_BLIT=snapN: all surfaces at blit N */
        if (snap) {
            static int fired = 0;
            int at = atoi(want + 4);
            if (!fired && seen++ >= at) {
                fired = 1;
                for (int q = 0; q < g_nwing && q < (int)(sizeof g_wing / sizeof g_wing[0]); q++) {
                    uint32_t st = (((uint32_t)g_wing[q].w * g_wing[q].bpp + 31) / 32) * 4;
                    uint32_t nb = st * (uint32_t)g_wing[q].h;
                    unsigned nz = 0; unsigned char seenv[256]; unsigned distinct = 0;
                    memset(seenv, 0, sizeof seenv);
                    const uint8_t *pp = cpu->mem + seg_off(cpu, g_wing[q].sel, 0);
                    for (uint32_t k = 0; k < nb; k++) {
                        if (pp[k]) nz++;
                        if (!seenv[pp[k]]) { seenv[pp[k]] = 1; distinct++; }
                    }
                    {   uint32_t ncol2 = (g_wing[q].bpp <= 8) ? (1u << g_wing[q].bpp) : 0;
                        uint32_t offb2 = 14 + 40 + ncol2 * 4, fsz2 = offb2 + nb;
                        uint8_t fh2[14] = {'B','M'};
                        memcpy(fh2 + 2, &fsz2, 4); memcpy(fh2 + 10, &offb2, 4);
                        BITMAPINFOHEADER ih2; memset(&ih2, 0, sizeof ih2);
                        ih2.biSize = 40; ih2.biWidth = g_wing[q].w;
                        ih2.biHeight = -g_wing[q].h; ih2.biPlanes = 1;
                        ih2.biBitCount = (WORD)g_wing[q].bpp; ih2.biCompression = BI_RGB;
                        ih2.biSizeImage = nb; ih2.biClrUsed = ncol2;
                        char pth[512];
                        snprintf(pth, sizeof pth, "%s/surf%d.bmp",
                                 getenv("RECOMP_DUMP_DIR") ? getenv("RECOMP_DUMP_DIR") : ".", q);
                        FILE *ff = fopen(pth, "wb");
                        if (ff) { fwrite(fh2,1,14,ff); fwrite(&ih2,1,40,ff);
                                  if (ncol2) fwrite(g_wing[q].pal,1,ncol2*4,ff);
                                  fwrite(pp,1,nb,ff); fclose(ff); } }
                    fprintf(stderr, "[snap] surf%d hbm=%04X %dx%d sel=%04X nonzero=%u of %u distinct=%u\n",
                            q, g_wing[q].hbm, g_wing[q].w, g_wing[q].h, g_wing[q].sel, nz, nb, distinct);
                }
            }
            go = 0;
        } else if (all) {
            go = 1;
            for (int k = 0; k < ndumped; k++) if (dumped[k] == g_wing[i].hbm) go = 0;
            if (go && ndumped < 16) dumped[ndumped++] = g_wing[i].hbm;
            nth = g_wing[i].hbm;
        } else {
            go = (nth >= 0 && seen++ == nth);
        }
        if (go) {
            uint32_t stride = (((uint32_t)g_wing[i].w * g_wing[i].bpp + 31) / 32) * 4;
            uint32_t nbits = stride * (uint32_t)g_wing[i].h;
            uint32_t ncol = (g_wing[i].bpp <= 8) ? (1u << g_wing[i].bpp) : 0;
            uint32_t offb = 14 + 40 + ncol * 4;
            uint8_t fh[14] = {'B','M'};
            uint32_t fsz = offb + nbits;
            memcpy(fh + 2, &fsz, 4);
            memcpy(fh + 10, &offb, 4);
            BITMAPINFOHEADER ih; memset(&ih, 0, sizeof ih);
            ih.biSize = 40; ih.biWidth = g_wing[i].w;
            ih.biHeight = -g_wing[i].h;      /* stored top-down */
            ih.biPlanes = 1; ih.biBitCount = (WORD)g_wing[i].bpp;
            ih.biCompression = BI_RGB; ih.biSizeImage = nbits;
            ih.biClrUsed = ncol;
            char path[512];
            snprintf(path, sizeof path, "%s/blit%d.bmp",
                     getenv("RECOMP_DUMP_DIR") ? getenv("RECOMP_DUMP_DIR") : ".", nth);
            FILE *f = fopen(path, "wb");
            if (f) {
                fwrite(fh, 1, 14, f);
                fwrite(&ih, 1, 40, f);
                if (ncol) fwrite(g_wing[i].pal, 1, ncol * 4, f);
                fwrite(cpu->mem + seg_off(cpu, g_wing[i].sel, 0), 1, nbits, f);
                fclose(f);
            }
            /* And a histogram of the pixel indices actually present. */
            unsigned hist[256]; memset(hist, 0, sizeof hist);
            const uint8_t *px = cpu->mem + seg_off(cpu, g_wing[i].sel, 0);
            for (uint32_t k = 0; k < nbits; k++) hist[px[k]]++;
            fprintf(stderr, "[blitdump] %s %dx%dx%d top indices:",
                    path, g_wing[i].w, g_wing[i].h, g_wing[i].bpp);
            for (int t = 0; t < 8; t++) {
                int best = 0;
                for (int c = 1; c < 256; c++) if (hist[c] > hist[best]) best = c;
                fprintf(stderr, " %d=%u(%02X%02X%02X)", best, hist[best],
                        g_wing[i].pal[best*4+2], g_wing[i].pal[best*4+1],
                        g_wing[i].pal[best*4+0]);
                hist[best] = 0;
            }
            fprintf(stderr, "\n");
        }
    }
    {   /* Keep the frame's own copy up to date on every blit. */
        uint32_t pst = (((uint32_t)g_wing[i].w * g_wing[i].bpp + 31) / 32) * 4;
        const uint8_t *psp = cpu->mem + seg_off(cpu, g_wing[i].sel, 0);
        if (g_wing[i].bpp == 8) {
            memcpy(g_present_pal, g_wing[i].pal, sizeof g_present_pal);
            for (int dy = 0; dy < hDest && hSrc > 0; dy++) {
                int oy = yDest + dy;
                if (oy < 0 || oy >= PRESENT_H) continue;
                int sy = ySrc + (int)((long)dy * hSrc / hDest);
                if (sy < 0 || sy >= g_wing[i].h) continue;
                for (int dx = 0; dx < wDest && wSrc > 0; dx++) {
                    int ox = xDest + dx;
                    if (ox < 0 || ox >= PRESENT_W) continue;
                    int sx = xSrc + (int)((long)dx * wSrc / wDest);
                    if (sx < 0 || sx >= g_wing[i].w) continue;
                    g_present[oy][ox] = psp[(uint32_t)sy * pst + (uint32_t)sx];
                }
            }
            if (xDest + wDest > g_present_w) g_present_w = xDest + wDest;
            if (yDest + hDest > g_present_h) g_present_h = yDest + hDest;
            if (g_present_w > PRESENT_W) g_present_w = PRESENT_W;
            if (g_present_h > PRESENT_H) g_present_h = PRESENT_H;
            g_present_live = 1;
        }
    }
    {   const char *cw = getenv("RECOMP_DUMP_WIN");
        if (cw) {
            static int nblt;
            /* RECOMP_DUMP_WIN_FROM: ignore everything before blit N, so the
               canvas shows only recent frames and a trail is distinguishable
               from art that was legitimately drawn once at startup. */
            { static int from = -1;
              if (from < 0) { const char *f = getenv("RECOMP_DUMP_WIN_FROM");
                              from = f ? atoi(f) : 0; }
              if (nblt++ < from) goto skip_canvas; }
            uint32_t st = (((uint32_t)g_wing[i].w * g_wing[i].bpp + 31) / 32) * 4;
            const uint8_t *sp = cpu->mem + seg_off(cpu, g_wing[i].sel, 0);
            memcpy(g_canvas_pal, g_wing[i].pal, sizeof g_canvas_pal);
            for (int dy = 0; dy < hDest && hSrc > 0; dy++) {
                int oy = yDest + dy;
                if (oy < 0 || oy >= 768) continue;
                int sy = ySrc + (int)((long)dy * hSrc / hDest);
                if (sy < 0 || sy >= g_wing[i].h) continue;
                for (int dx = 0; dx < wDest && wSrc > 0; dx++) {
                    int ox = xDest + dx;
                    if (ox < 0 || ox >= 1024) continue;
                    int sx = xSrc + (int)((long)dx * wSrc / wDest);
                    if (sx < 0 || sx >= g_wing[i].w) continue;
                    g_canvas[oy][ox] = sp[(uint32_t)sy * st + (uint32_t)sx];
                    g_age[oy][ox] = nblt;
                }
            }
            { const char *sv = getenv("RECOMP_STALE");
              if (sv && nblt == atoi(sv) * 2) stale_dump(nblt, atoi(sv)); }
            if (nblt == atoi(cw)) canvas_dump(1);
            if (nblt == atoi(cw) * 2) canvas_dump(2);
            skip_canvas: ;
        }
    }
    {   /* RECOMP_SRCDUMP=<n>: write out the exact source region of pet-sized
           blits n and n+1, to see whether the scratch is fully repainted. */
        const char *sd = getenv("RECOMP_SRCDUMP");
        if (sd && hSrc > 100 && hSrc < 260 && wSrc > 60 && wSrc < 200) {
            static int seen; int want = atoi(sd);
            if (seen == want || seen == want + 1) {
                uint32_t st = (((uint32_t)g_wing[i].w * g_wing[i].bpp + 31) / 32) * 4;
                const uint8_t *sp = cpu->mem + seg_off(cpu, g_wing[i].sel, 0);
                uint32_t ost = ((uint32_t)wSrc + 3) & ~3u, nb = ost * (uint32_t)hSrc;
                uint8_t *img = calloc(nb, 1);
                char path[512];
                snprintf(path, sizeof path, "%s/src%d.bmp",
                         getenv("RECOMP_DUMP_DIR") ? getenv("RECOMP_DUMP_DIR") : ".",
                         seen - want);
                FILE *f = fopen(path, "wb");
                if (img && f) {
                    for (int yy = 0; yy < hSrc; yy++)
                        for (int xx = 0; xx < wSrc; xx++)
                            img[(uint32_t)yy * ost + xx] =
                                sp[(uint32_t)(ySrc + yy) * st + (xSrc + xx)];
                    uint32_t offb = 14 + 40 + 256 * 4, fsz = offb + nb;
                    uint8_t fh[14] = {'B','M'};
                    memcpy(fh + 2, &fsz, 4); memcpy(fh + 10, &offb, 4);
                    BITMAPINFOHEADER ih; memset(&ih, 0, sizeof ih);
                    ih.biSize = 40; ih.biWidth = wSrc; ih.biHeight = -hSrc;
                    ih.biPlanes = 1; ih.biBitCount = 8; ih.biCompression = BI_RGB;
                    ih.biSizeImage = nb; ih.biClrUsed = 256;
                    fwrite(fh, 1, 14, f); fwrite(&ih, 1, 40, f);
                    fwrite(g_wing[i].pal, 1, 256 * 4, f);
                    fwrite(img, 1, nb, f);
                    fprintf(stderr, "[src] %s src(%d,%d %dx%d) -> dst(%d,%d %dx%d)\n",
                            path, xSrc, ySrc, wSrc, hSrc, xDest, yDest, wDest, hDest);
                }
                if (f) fclose(f);
                free(img);
            }
            seen++;
        }
    }
    {   const char *lb = getenv("RECOMP_LOG_BLT");
        if (lb) { static int nb;
            int at = atoi(lb);
            static int px = -9999, py, pw, ph, ps = -1, shown;
            if ((xDest != px || yDest != py || wDest != pw || hDest != ph || i != ps)
                && shown < at) {
                shown++;
                fprintf(stderr, "[blt] %4d surf%d src(%d,%d %dx%d) -> dst(%d,%d %dx%d)\n",
                        nb, i, xSrc, ySrc, wSrc, hSrc, xDest, yDest, wDest, hDest);
                px = xDest; py = yDest; pw = wDest; ph = hDest; ps = i;
            }
            nb++;
        }
    }
    {   /* RECOMP_CHECK_TRIG: snapshot the DLL's sin/cos tables on the first blit
           and re-verify on every later one; report the first entry that changes. */
        if (getenv("RECOMP_CHECK_TRIG")) {
            static int done;
            if (!done) {
                uint32_t cb = seg_off(cpu, 59, 0x4004), sb = seg_off(cpu, 59, 0x4408);
                for (int k = -128; k <= 128 && !done; k++) {
                    int32_t cv, sv;
                    memcpy(&cv, cpu->mem + cb + k * 4, 4);
                    memcpy(&sv, cpu->mem + sb + k * 4, 4);
                    long wc = lround(256.0 * cos(k * 3.14159265358979 / 128.0));
                    long ws = lround(256.0 * sin(k * 3.14159265358979 / 128.0));
                    if (labs((long)cv - wc) > 2 || labs((long)sv - ws) > 2) {
                        fprintf(stderr, "[trigchk] index %d: cos=%ld (want %ld)  sin=%ld (want %ld)\n",
                                k, (long)cv, wc, (long)sv, ws);
                        done = 1;
                    }
                }
            }
        }
    }
    {   /* RECOMP_EXIT_BLITS=<n>: quit after n screen blits, so a run is a fixed
           amount of work and can be timed. */
        static const char *eb; static int inited, nleft;
        if (!inited) { inited = 1; eb = getenv("RECOMP_EXIT_BLITS");
                       nleft = eb ? atoi(eb) : 0; }
        if (eb && --nleft <= 0) { fflush(stderr); _exit(0); }
    }
    {   const char *cd = getenv("RECOMP_DIFF");
        if (cd && i == 0) surf_diff(cpu, i, atoi(cd));
    }
    const void *bits = cpu->mem + seg_off(cpu, g_wing[i].sel, 0);
    SetStretchBltMode(dst, COLORONCOLOR);
    /* A blit that reaches here has a valid DC and correct pixels, so if the
       window still does not show it the loss is on this side. Report the DC
       it went to and whether GDI accepted it. */
    if (getenv("RECOMP_LOG_DEST")) {
        extern HWND g_main_hwnd_of(void);
        extern HWND g_screen_hwnd_of(void);
        static int n; static HWND lastw; static uint16_t lastg;
        HWND ow = WindowFromDC(dst);
        if (n < 8 || ow != lastw || hdcDest != lastg) {
            if (n < 40) fprintf(stderr,
                "[dest] blit %d ghdc=%u dc=%p window=%p (main=%p screen=%p)\n",
                n, hdcDest, (void *)dst, (void *)ow,
                (void *)g_main_hwnd_of(), (void *)g_screen_hwnd_of());
            n++; lastw = ow; lastg = hdcDest;
        }
    }
    int r = StretchDIBits(dst, xDest, yDest, wDest, hDest,
                          xSrc, ySrc, wSrc, hSrc,
                          bits, (const BITMAPINFO *)bi, DIB_RGB_COLORS, SRCCOPY);
    IMPL_LOG("[wing] StretchBlt %dx%d@%d,%d <- %dx%d@%d,%d src=%04X -> %d\n",
             wDest, hDest, xDest, yDest, wSrc, hSrc, xSrc, ySrc, g_wing[i].sel, r);
    /* RECOMP_WATCH_BLACK: report any blit that paints a substantial area of the
       window solid background-index. That is what "it turns black" looks
       like from this side, and catching the blit that does it names the
       surface and the rectangle it came from. Silent when nothing does it. */
    /* The other way a blit comes out black is with correct pixels and a dead
       colour table: the engine leaves the table in its BITMAPINFO blank and
       supplies colours through CreatePalette, so a surface created before it
       realizes one keeps an all-zero table and everything drawn from it is
       black however good the indices are. Checked always, not just under the
       watch, because it is cheap and there is no benign case. */
    if (g_wing[i].bpp == 8) {
        static int told[16];
        int live = 0;
        for (int c = 1; c < 256 && !live; c++)
            if (g_wing[i].pal[c * 4] | g_wing[i].pal[c * 4 + 1]
                                    | g_wing[i].pal[c * 4 + 2]) live = 1;
        if (!live && i < 16 && !told[i]) {
            told[i] = 1;
            fprintf(stderr, "[palette] surf%d has an all-black colour table; everything blitted from it will be black\n", i);
        }
    }
    if (getenv("RECOMP_WATCH_BLACK") && g_wing[i].bpp == 8
        && wDest >= 24 && hDest >= 24) {
        uint32_t st = (((uint32_t)g_wing[i].w * 8 + 31) / 32) * 4;
        const uint8_t *sp = cpu->mem + seg_off(cpu, g_wing[i].sel, 0);
        long zero = 0, seen = 0;
        for (int yy = 0; yy < hSrc; yy += 2) {
            int sy = ySrc + yy;
            if (sy < 0 || sy >= g_wing[i].h) continue;
            for (int xx = 0; xx < wSrc; xx += 2) {
                int sx = xSrc + xx;
                if (sx < 0 || sx >= g_wing[i].w) continue;
                seen++;
                if (sp[(uint32_t)sy * st + sx] == 0) zero++;
            }
        }
        int fullscreen = (xDest <= 0 && yDest <= 0 && wDest >= 256 && hDest >= 200);
        /* A big blit that is even a third empty is worth hearing about: the
           reports are of an area going black, not the whole window. */
        int big = (wDest >= 100 && hDest >= 100);
        int bar = big ? 3 : 9;          /* tenths of the sampled area */
        if (seen > 32 && zero * 10 >= seen * bar && !fullscreen) {
            static long n; n++;
            if (n < 20 || (n % 50) == 0)
                fprintf(stderr, "[black] blit %ld%s%ld%% empty: surf%d src(%d,%d %dx%d) -> dst(%d,%d %dx%d) n=%ld\n",
                        n, " painted ", zero * 100 / seen, i, xSrc, ySrc, wSrc, hSrc,
                        xDest, yDest, wDest, hDest, n);
        }
    }
    /* Sprites that reach the edge of the playpen produce rects that hang off
       the surface. Count those separately: the user reports the ball turning
       its whole area black exactly when it bounces off a wall. */
    if (getenv("RECOMP_LOG_EDGE")) {
        int sx2 = xSrc + wSrc, sy2 = ySrc + hSrc;
        if (xSrc < 0 || ySrc < 0 || sx2 > g_wing[i].w || sy2 > g_wing[i].h) {
            static long n; n++;
            if (n < 12 || (n % 100) == 0)
                fprintf(stderr, "[edge] src(%d,%d %dx%d) outside surf%d (%dx%d), n=%ld\n",
                        xSrc, ySrc, wSrc, hSrc, i, g_wing[i].w, g_wing[i].h, n);
        }
    }
    /* A blit that gets this far has a valid DC and correct pixels, so a
       rejection here is content the window silently never receives. */
    if (r == 0 || r == GDI_ERROR) {
        static long nbad, ntot;
        nbad++;
        if (nbad == 1 || (nbad % 200) == 0)
            fprintf(stderr, "[blitfail] StretchDIBits rejected %ld blits (last %dx%d at %d,%d, r=%d)\n",
                    nbad, wDest, hDest, xDest, yDest, r);
        (void)ntot;
    }
    cpu->ax = (uint16_t)(r != GDI_ERROR);
    ret(cpu, 20);
}

/* ===== KERNEL: local heap =====
 * LocalInit(uSegment, uStart, uEnd) registers a segment's local heap with the
 * kernel and returns nonzero on success. Borland's RTL near-malloc (used by
 * _setargv etc.) keys off this succeeding; a stub returning 0 made startup
 * report "Out of memory in _setargv". */
void KERNEL_LOCALINIT(CPU *cpu) {
    uint16_t uEnd = a16(cpu, 0), uStart = a16(cpu, 2), uSeg = a16(cpu, 4);
    IMPL_LOG("[win16] LocalInit(seg=%04X, start=%04X, end=%04X) ds=%04X\n",
             uSeg, uStart, uEnd, cpu->ds);
    cpu->ax = 1;                            /* TRUE - heap initialized */
    ret(cpu, 6);
}

/* ===== KERNEL: task startup =====
 * InitTask is called once at the very start of a Win16 EXE (Borland C0, MS C
 * crt0). It returns the startup register block the runtime needs; a stub
 * returning AX=0 makes the startup abort. CX is the stack size from the NE
 * header, as Windows returns it: MS C's crt0 adds its 256-byte slop and
 * gives up on a carry, so anything near 0xFFFF makes it exit 255. */
void KERNEL_INITTASK(CPU *cpu) {
    uint16_t hinst = RECOMP_AUTO_DATA_SEG;   /* fake hInstance == WAD DGROUP sel */
    /* Empty command line in the (fake) PSP at DGROUP:0080: length byte 0, CR. */
    mem_write8(cpu, hinst, 0x80, 0);
    mem_write8(cpu, hinst, 0x81, 0x0D);
    cpu->ax = 1;                 /* success (nonzero) */
    cpu->cx = RECOMP_MODULES[RECOMP_NUM_MODULES - 1].stack;   /* the host's, last in load order */
    cpu->dx = 1;                 /* nCmdShow = SW_SHOWNORMAL */
    cpu->si = 0;                 /* hPrevInstance = none */
    cpu->di = hinst;             /* hInstance */
    cpu->es = hinst; cpu->bx = 0x0080;   /* ES:BX -> command line */
    cpu->bp = 0;
    ret(cpu, 0);
}

/* ===== KERNEL: module / version / task ===== */

void KERNEL_GETWINFLAGS(CPU *cpu) {         /* DX:AX: WF_PMODE|WF_CPU386|WF_ENHANCED */
    cpu->dx = 0; cpu->ax = 0x0029;
    ret(cpu, 0);
}

void KERNEL_GETVERSION(CPU *cpu) {          /* Windows 3.10 (AX), DOS 5.00 (DX) */
    cpu->ax = 0x0A03; cpu->dx = 0x0005;
    ret(cpu, 0);
}

void KERNEL_GETCURRENTTASK(CPU *cpu) {      /* nonzero fake HTASK */
    cpu->ax = 0x00FF;
    ret(cpu, 0);
}

void KERNEL_GETMODULEUSAGE(CPU *cpu) { cpu->ax = 1; ret(cpu, 2); }

void KERNEL_GETMODULEFILENAME(CPU *cpu) {
    uint16_t nSize = a16(cpu, 0), off = a16(cpu, 2), seg = a16(cpu, 4);
    /* hModule is the module's DGROUP selector here; anything else (0 = the
       task) answers with the host. */
    const RecompModule *m = recomp_module_of_hinst(a16(cpu, 6));
    if (!m) m = &RECOMP_MODULES[RECOMP_NUM_MODULES - 1];
    char path[160];
    snprintf(path, sizeof path, "%s\\%s", recomp_game.guest_dir, m->file);
    uint16_t i = 0;
    for (; path[i] && i + 1 < nSize; i++)
        mem_write8(cpu, seg, (uint16_t)(off + i), (uint8_t)path[i]);
    mem_write8(cpu, seg, (uint16_t)(off + i), 0);
    cpu->ax = i;
    ret(cpu, 8);
}

/* ===== USER: init-path window/message ===== */

void USER_MESSAGEBOX(CPU *cpu) {
    /* args (sp+4 up): uType@0, lpCaption off@2/seg@4, lpText off@6/seg@8, hWnd@10 */
    uint16_t toff = a16(cpu, 6),  tseg = a16(cpu, 8);    /* lpText */
    uint16_t coff = a16(cpu, 2),  cseg = a16(cpu, 4);    /* lpCaption */
    char text[256] = "", cap[128] = "";
    read_asciiz(cpu, tseg, toff, text, sizeof(text));
    read_asciiz(cpu, cseg, coff, cap, sizeof(cap));
    fprintf(stderr, "[MessageBox] \"%s\" | \"%s\"\n", cap, text);
    /* The engine reports its own fatal conditions through MessageBox, so a
       matching caption is the only notice we get. Match case-insensitively and
       include "error" -- the RTL's math diagnostics ("sqrt: DOMAIN error")
       arrive this way and were previously invisible. */
    char low[256];
    for (unsigned i = 0; i < sizeof low; i++) low[i] = (char)tolower((unsigned char)text[i]);
    low[sizeof low - 1] = 0;
    if (strstr(low, "memory") || strstr(low, "abnormal") || strstr(low, "abort")
            || strstr(low, "error") || strstr(low, "assert")) {
        extern const char *g_fn_ring[]; extern unsigned g_fn_ring_pos;
        fprintf(stderr, "[abort] recent 120 fns:");
        for (int i = 120; i > 0; i--) { const char *r = g_fn_ring[(g_fn_ring_pos-(unsigned)i) & ((1u<<12)-1)]; if (r) fprintf(stderr, " %s", r+3); }
        fprintf(stderr, "\n");
        dump_guest_stack(cpu, 40);
    }
    cpu->ax = 1;                            /* IDOK */
    ret(cpu, 12);
}

void USER_ENUMTASKWINDOWS(CPU *cpu) {
    /* Return TRUE without invoking the callback: the engine is enumerating to
     * detect an existing instance window; finding none keeps it on the normal
     * first-run path instead of the "already running" branch. */
    cpu->ax = 1;
    ret(cpu, 10);
}

/* One clock for the whole shim layer: USER.GetTickCount and MMSYSTEM.timeGetTime
 * must agree or the engine's frame pacing sees time run backwards. Monotonic and
 * always advancing so the engine's calibration waits terminate. */
uint32_t recomp_tick_ms(void) {
    static uint32_t t = 0;
    t += 16;
    return t;
}

void USER_GETTICKCOUNT(CPU *cpu) {          /* DX:AX ms, monotonic so waits end */
    uint32_t t = recomp_tick_ms();
    cpu->ax = (uint16_t)t; cpu->dx = (uint16_t)(t >> 16);
    ret(cpu, 0);
}

void USER_MESSAGEBEEP(CPU *cpu) { cpu->ax = 1; ret(cpu, 2); }

/* OutputDebugString(LPCSTR): surface the engine's own debug trace. */
void KERNEL_OUTPUTDEBUGSTRING(CPU *cpu) {
    uint16_t off = a16(cpu, 0), seg = a16(cpu, 2);
    char s[256]; read_asciiz(cpu, seg, off, s, sizeof(s));
    /* The engine's own log is the best window into what it thinks it is doing,
     * and right now the lifted Borland formatter mangles it — so dump the bytes
     * around the buffer too, which is what showed the output is a TAIL of the
     * intended string ("alled" for " called"). */
    IMPL_LOG("[OutputDebugString] %04X:%04X [", seg, off);
    for (int i = -6; i < 18; i++)
        IMPL_LOG("%c%02X", i == 0 ? '|' : ' ', mem_read8(cpu, seg, (uint16_t)(off + i)));
    IMPL_LOG(" ]");
    fprintf(stderr, "[OutputDebugString] %s", s);
    /* RECOMP_TRAP=<substring>: when the engine logs a failure, print the calls
       that led there. Its own log names the source line but not the path. */
    {   const char *trap = getenv("RECOMP_TRAP");
        if (trap && strstr(s, trap)) {
            extern void dump_guest_stack(CPU *, int);
            fprintf(stderr, "\n[trap] %s\n", s);
            /* RECOMP_TRAP_RING: the recently executed functions rather than the
               call stack. The RTL's string formatter runs for every one of
               these log lines and would bury everything else, so its
               segments can be left out with RECOMP_TRAP_SKIP. */
            if (getenv("RECOMP_TRAP_RING")) {
                extern const char *g_fn_ring[]; extern unsigned g_fn_ring_pos;
                int want = atoi(getenv("RECOMP_TRAP_RING"));
                if (want <= 0 || want > 4000) want = 400;
                fprintf(stderr, "[ring] last %d non-RTL functions:\n", want);
                for (int k = want; k > 0; k--) {
                    const char *nm = g_fn_ring[(g_fn_ring_pos - (unsigned)k)
                                              & (RECOMP_FN_RING_SIZE - 1)];
                    /* RECOMP_TRAP_SKIP=001,048: segments to leave out
                       (on Catz, the RTL's formatter and allocator). */
                    const char *skip = getenv("RECOMP_TRAP_SKIP");
                    char sn[4] = { 0 };
                    if (nm && strlen(nm) > 6) memcpy(sn, nm + 3, 3);
                    if (nm && !(skip && strstr(skip, sn)))
                        fprintf(stderr, " %s", nm);
                }
                fprintf(stderr, "\n");
            } else {
                dump_guest_stack(cpu, 64);
            }
            fflush(stderr);
        }
    }
    cpu->ax = 0; ret(cpu, 4);
}

/* InitApp(hInstance): create the app message queue. Return nonzero on success. */
void USER_INITAPP(CPU *cpu) { cpu->ax = 1; ret(cpu, 2); }

/* WaitEvent(hTask): yield to the event system. No-op (return). */
void KERNEL_WAITEVENT(CPU *cpu) { cpu->ax = 0; ret(cpu, 2); }

/* ===== USER/GDI: window setup (sane fake handles for now) =====
 * Enough to get the host past window creation; replaced with real Win32-backed
 * windows + a WndProc bridge when we wire actual rendering. Screen modeled as
 * 640x480x8 (the Catz target). */
#define FAKE_HWND   0x0CA7
#define FAKE_HDC    0x0DC1
#define FAKE_HANDLE 0x00F0   /* generic non-null GDI/icon/cursor/menu handle */

static void write_rect(CPU *cpu, uint16_t seg, uint16_t off, int l, int t, int r, int b) {
    mem_write16(cpu, seg, (uint16_t)(off + 0), (uint16_t)l);
    mem_write16(cpu, seg, (uint16_t)(off + 2), (uint16_t)t);
    mem_write16(cpu, seg, (uint16_t)(off + 4), (uint16_t)r);
    mem_write16(cpu, seg, (uint16_t)(off + 6), (uint16_t)b);
}

/* USER_REGISTERCLASS, USER_CREATEWINDOW: real Win32 in win32_backend.c */
void USER_GETSYSTEMMENU(CPU *cpu)  { cpu->ax = FAKE_HANDLE; ret(cpu, 4); }
void USER_LOADICON(CPU *cpu)       { cpu->ax = FAKE_HANDLE; ret(cpu, 6); }
void USER_GETSYSTEMMETRICS(CPU *cpu) {     /* index@0 */
    uint16_t i = a16(cpu, 0);
    int v;
    switch (i) {
        case 0:  v = 640; break;  /* SM_CXSCREEN */
        case 1:  v = 480; break;  /* SM_CYSCREEN */
        case 2:  v = 16;  break;  /* SM_CXVSCROLL */
        case 3:  v = 16;  break;  /* SM_CYHSCROLL */
        case 4:  v = 18;  break;  /* SM_CYCAPTION */
        case 5:  v = 1;   break;  /* SM_CXBORDER */
        case 6:  v = 1;   break;  /* SM_CYBORDER */
        case 7:  v = 2;   break;  /* SM_CXDLGFRAME */
        case 8:  v = 2;   break;  /* SM_CYDLGFRAME */
        case 15: v = 18;  break;  /* SM_CYMENU */
        case 16: v = 640; break;  /* SM_CXFULLSCREEN */
        case 17: v = 462; break;  /* SM_CYFULLSCREEN */
        case 32: v = 2;   break;  /* SM_CXFRAME */
        case 33: v = 2;   break;  /* SM_CYFRAME */
        default: v = 0;   break;
    }
    cpu->ax = (uint16_t)v; ret(cpu, 2);
}
void USER_SETMESSAGEQUEUE(CPU *cpu){ cpu->ax = 1; ret(cpu, 2); }
void KERNEL_GETWINDOWSDIRECTORY(CPU *cpu) {   /* LPSTR off@2/seg@4, UINT@0 */
    uint16_t nSize = a16(cpu, 0), off = a16(cpu, 2), seg = a16(cpu, 4);
    const char *p = "C:\\WINDOWS";
    uint16_t i = 0;
    for (; p[i] && i + 1 < nSize; i++) mem_write8(cpu, seg, (uint16_t)(off + i), (uint8_t)p[i]);
    mem_write8(cpu, seg, (uint16_t)(off + i), 0);
    cpu->ax = i; ret(cpu, 6);
}

int w32_client_rect(uint16_t g, RECT *r);    /* win32_backend.c: RecompGame.real_windows */
int w32_window_rect(uint16_t g, RECT *r);
int w32_client_to_screen(uint16_t g, POINT *p);

void USER_GETWINDOWRECT(CPU *cpu) {        /* HWND@4, LPRECT off@0/seg@2 */
    RECT r = { 0, 0, 640, 480 };
    if (recomp_game.real_windows) w32_window_rect(a16(cpu, 4), &r);
    write_rect(cpu, a16(cpu, 2), a16(cpu, 0), r.left, r.top, r.right, r.bottom);
    cpu->ax = 1; ret(cpu, 6);
}
/* Rect utilities. OffsetRect and InflateRect were stubs that returned without
 * touching the rect, so every rect the engine translated stayed where it was --
 * including the one that says where the pet's saved background comes from.
 *
 * ClientToScreen is deliberately the identity: GetDC(NULL) hands back the
 * playpen window's DC (see win32_backend.c), so the window's client area IS the
 * engine's screen. GetClientRect reports 0,0,640,480 for the same reason. All
 * three have to agree or the pet's background is fetched from the wrong place. */
void USER_OFFSETRECT(CPU *cpu) {           /* (lpRect@4/6, dx@2, dy@0) */
    uint16_t off = a16(cpu, 4), seg = a16(cpu, 6);
    int dx = (int16_t)a16(cpu, 2), dy = (int16_t)a16(cpu, 0);
    if (seg) {
        for (int i = 0; i < 4; i++) {
            uint16_t p = (uint16_t)(off + i * 2);
            int v = (int16_t)mem_read16(cpu, seg, p) + ((i & 1) ? dy : dx);
            mem_write16(cpu, seg, p, (uint16_t)v);
        }
    }
    cpu->ax = 1;
    ret(cpu, 8);
}

void USER_INFLATERECT(CPU *cpu) {          /* (lpRect@4/6, dx@2, dy@0) */
    uint16_t off = a16(cpu, 4), seg = a16(cpu, 6);
    int dx = (int16_t)a16(cpu, 2), dy = (int16_t)a16(cpu, 0);
    if (seg) {
        write_rect(cpu, seg, off,
                   (int16_t)mem_read16(cpu, seg, off) - dx,
                   (int16_t)mem_read16(cpu, seg, (uint16_t)(off + 2)) - dy,
                   (int16_t)mem_read16(cpu, seg, (uint16_t)(off + 4)) + dx,
                   (int16_t)mem_read16(cpu, seg, (uint16_t)(off + 6)) + dy);
    }
    cpu->ax = 1;
    ret(cpu, 8);
}

void USER_CLIENTTOSCREEN(CPU *cpu) {       /* (hwnd@4, lpPoint@0/2): identity, or real_windows */
    if (recomp_game.real_windows) {
        uint16_t po = a16(cpu, 0), ps = a16(cpu, 2);
        POINT p = { (int16_t)mem_read16(cpu, ps, po), (int16_t)mem_read16(cpu, ps, (uint16_t)(po + 2)) };
        if (w32_client_to_screen(a16(cpu, 4), &p)) {
            mem_write16(cpu, ps, po, (uint16_t)p.x);
            mem_write16(cpu, ps, (uint16_t)(po + 2), (uint16_t)p.y);
        }
    }
    cpu->ax = 1;
    ret(cpu, 6);
}

void USER_GETCLIENTRECT(CPU *cpu) {        /* (hwnd@4, lpRect@0/2) */
    RECT r = { 0, 0, 640, 480 };
    if (recomp_game.real_windows) w32_client_rect(a16(cpu, 4), &r);
    write_rect(cpu, a16(cpu, 2), a16(cpu, 0), r.left, r.top, r.right, r.bottom);
    cpu->ax = 1; ret(cpu, 6);
}

void GDI_GETDEVICECAPS(CPU *cpu) {         /* HDC@2, index@0 */
    uint16_t idx = a16(cpu, 0);
    int v = 0;
    switch (idx) {
        case 8:  v = 640; break;   /* HORZRES   */
        case 10: v = 480; break;   /* VERTRES   */
        case 12: v = 8;   break;   /* BITSPIXEL */
        case 14: v = 1;   break;   /* PLANES    */
        case 24: v = 256; break;   /* NUMCOLORS */
        case 104:v = 256; break;   /* SIZEPALETTE */
        case 38: v = 0x0100; break;/* RASTERCAPS: RC_PALETTE */
        default: v = 0;   break;
    }
    cpu->ax = (uint16_t)v; ret(cpu, 4);
}
void GDI_CREATEIC(CPU *cpu)         { cpu->ax = FAKE_HDC; ret(cpu, 16); }

void CTL3DV2_CTL3DREGISTER(CPU *cpu)       { cpu->ax = 1; ret(cpu, 2); }
void CTL3DV2_CTL3DAUTOSUBCLASS(CPU *cpu)   { cpu->ax = 1; ret(cpu, 2); }

/* ===== INT 21h (DOS services occasionally used by the Borland startup) ===== */

/* ===== read-only DOS file I/O backed by the extracted game data tree =====
 * The engine opens data files by absolute guest path (e.g.
 * "C:\CATZ\ptzfiles\cat\resource\catsnd.txt"). We anchor on the "ptzfiles"
 * component and remap it under RECOMP_DATA_DIR on the host. */
#ifndef RECOMP_DATA_DIR
#define RECOMP_DATA_DIR "game"
#endif
static FILE *g_dosfiles[64];          /* DOS handle h (>=5) -> host FILE* (slot h-5) */

/* Map a guest DOS path to a host path under RECOMP_DATA_DIR. */
static int map_guest_path(const char *g, char *host, int hostsz) {
    if (!g[0]) return 0;
    char low[192]; int i = 0;
    for (; g[i]; i++) low[i] = (g[i] >= 'A' && g[i] <= 'Z') ? (char)(g[i] + 32) : g[i];
    low[i] = 0;
    char *p = recomp_game.path_anchor ? strstr(low, recomp_game.path_anchor) : NULL;
    if (p) {
        snprintf(host, hostsz, "%s/%s", RECOMP_DATA_DIR, g + (p - low));
    } else {
        /* Everything else the engine opens by absolute guest path, and the guest
         * drive and directory are whatever the original install used. Matching on
         * the leaf alone threw the subdirectory away, so the playpen's background
         * art -- "\\playpenz\\CARPET.BMP" and friends, which live in PLAYPENZ/ --
         * was looked for in the install root and never found. That is what failed
         * right after adopting a cat, and the engine spun on it. Walk the path
         * from the left and take the longest tail that actually exists. */
        const char *seg[16]; int nseg = 0;
        seg[nseg++] = g;
        for (const char *q = g; *q && nseg < 16; q++)
            if ((*q == '\\' || *q == '/') && q[1]) seg[nseg++] = q + 1;
        int found = 0;
        for (int k = 0; k < nseg && !found; k++) {
            char cand[256];
            snprintf(cand, sizeof cand, "%s/%s", RECOMP_DATA_DIR, seg[k]);
            for (char *q = cand; *q; q++) if (*q == '\\') *q = '/';
            /* GetFileAttributes, not fopen: a directory has to resolve too,
               or FindFirst on "C:\GAME\EGGZ\*.*" lists the install root. */
            if (GetFileAttributesA(cand) != INVALID_FILE_ATTRIBUTES) {
                snprintf(host, hostsz, "%s", cand); found = 1; }
        }
        if (!found) {                    /* report the leaf, as before */
            const char *leaf = seg[nseg - 1];
            if (!*leaf) return 0;
            snprintf(host, hostsz, "%s/%s", RECOMP_DATA_DIR, leaf);
        }
    }
    for (char *q = host; *q; q++) if (*q == '\\') *q = '/';
    return 1;
}

/* sndPlaySound(lpszSoundName@2/4, uFlags@0).
 *
 * This was a stub returning 0, which is why the game has been silent: the
 * engine routes nearly every effect through here -- its own log says
 * "Playing sound via boring windows sounds" each time -- rather than through
 * the SOS driver it also imports. The files are RIFF/WAV even though most of
 * them carry a .WVV extension, so they need no conversion.
 *
 * Win16 flag values match Win32's, and the engine asks for SND_ASYNC; honour
 * that, because playing synchronously here would stall the frame loop for the
 * length of every miaow. */
void MMSYSTEM_SNDPLAYSOUND(CPU *cpu) {
    uint16_t flags = a16(cpu, 0);
    uint16_t off = a16(cpu, 2), seg = a16(cpu, 4);
    int ok = 0;
    if (!seg && !off) {
        PlaySoundA(NULL, NULL, 0);          /* NULL name: stop what is playing */
        ok = 1;
    } else {
        char guest[192] = "", host[256] = "";
        read_asciiz(cpu, seg, off, guest, sizeof guest);
        /* Check the file first. Without SND_NODEFAULT a name that does not
           resolve makes Windows play its own default sound and report success,
           so a broken path would come back as a system ding rather than as an
           error worth seeing. */
        FILE *probe = map_guest_path(guest, host, sizeof host)
                      ? fopen(host, "rb") : NULL;
        if (probe) {
            fclose(probe);
            { static int said; if (!said++)
                fprintf(stderr, "[sound] %s -> %s\n", guest, host); }
            DWORD f = SND_FILENAME;
            f |= (flags & 0x0001) ? SND_ASYNC : SND_SYNC;
            if (flags & 0x0002) f |= SND_NODEFAULT;
            if (flags & 0x0008) f |= SND_LOOP;
            if (flags & 0x0010) f |= SND_NOSTOP;
            ok = PlaySoundA(host, NULL, f) ? 1 : 0;
            if (!ok) {
                static char told[16][192]; static int ntold; int seen = 0;
                for (int i = 0; i < ntold; i++)
                    if (!strcmp(told[i], guest)) { seen = 1; break; }
                if (!seen) {
                    if (ntold < 16) snprintf(told[ntold++], 192, "%s", guest);
                    fprintf(stderr, "[sound] could not play %s (tried %s)\n",
                            guest, host);
                }
            }
        }
    }
    cpu->ax = (uint16_t)ok;
    ret(cpu, 6);
}

/* Kept for the trace: a failed open must report the path the guest asked
   for, which is the whole diagnostic when the engine composes one wrong. */
static char g_last_dos_path[192];

static int dos_map_path(CPU *cpu, char *host, int hostsz) {
    read_asciiz(cpu, cpu->ds, cpu->dx, g_last_dos_path, sizeof g_last_dos_path);
    return map_guest_path(g_last_dos_path, host, hostsz);
}

/* ---- FindFirst/FindNext (INT 21h 4Eh/4Fh) and the DTA they fill (1Ah/2Fh).
 * Borland's findfirst/findnext loop on CF; left to the default case, which
 * returned success, Oddballz enumerated its EGGZ directory forever. The DTA's
 * reserved first bytes carry which host search it belongs to, as real DOS kept
 * its own state there. */
static uint16_t g_dta_seg, g_dta_off = 0x80;
static HANDLE   g_find[16];

static void dta_fill(CPU *cpu, const WIN32_FIND_DATAA *fd, int slot) {
    uint16_t s = g_dta_seg, o = g_dta_off;
    mem_write8(cpu, s, o, 'R'); mem_write8(cpu, s, (uint16_t)(o + 1), (uint8_t)slot);
    uint8_t attr = (uint8_t)(fd->dwFileAttributes & 0x3F);
    FILETIME lt; WORD dd = 0, dt = 0;
    FileTimeToLocalFileTime(&fd->ftLastWriteTime, &lt);
    FileTimeToDosDateTime(&lt, &dd, &dt);
    mem_write8(cpu, s, (uint16_t)(o + 21), attr);
    mem_write16(cpu, s, (uint16_t)(o + 22), dt);
    mem_write16(cpu, s, (uint16_t)(o + 24), dd);
    mem_write16(cpu, s, (uint16_t)(o + 26), (uint16_t)fd->nFileSizeLow);
    mem_write16(cpu, s, (uint16_t)(o + 28), (uint16_t)(fd->nFileSizeLow >> 16));
    /* 8.3, upper case, the only form a DOS program expects back */
    const char *n = fd->cAlternateFileName[0] ? fd->cAlternateFileName : fd->cFileName;
    int i = 0;
    for (; n[i] && i < 12; i++) mem_write8(cpu, s, (uint16_t)(o + 30 + i), (uint8_t)toupper((unsigned char)n[i]));
    mem_write8(cpu, s, (uint16_t)(o + 30 + i), 0);
}

/* Next entry the guest's attribute mask admits: normal files always, and
 * directories/hidden/system only when asked for, as DOS did. */
static int find_step(CPU *cpu, int slot, WIN32_FIND_DATAA *fd, uint8_t want, int first) {
    for (;;) {
        if (!first && !FindNextFileA(g_find[slot], fd)) return 0;
        first = 0;
        DWORD a = fd->dwFileAttributes;
        if (!strcmp(fd->cFileName, ".") || !strcmp(fd->cFileName, "..")) continue;
        if ((a & FILE_ATTRIBUTE_DIRECTORY) && !(want & 0x10)) continue;
        if ((a & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) && !(want & 0x06)) continue;
        dta_fill(cpu, fd, slot);
        return 1;
    }
}

void dos_int21(CPU *cpu) {
    switch (cpu->ah) {
    case 0x4C:                              /* terminate process */
        printf("[INT21/4C] program exit, code=%u\n", cpu->al);
        fflush(stdout);
        exit(cpu->al);
    case 0x30:                              /* DOS version -> 5.00 */
        cpu->al = 5; cpu->ah = 0;
        cpu->flags &= ~FLAG_CF;
        break;
    case 0x2A: {                           /* get date */
        /* Unimplemented, this returned whatever was in the registers, and
           the engine writes the result to the save file as the day it last
           saw your cat -- it had been storing 'day 58 of month 0, year 0'.
           It dates the pet from this, so it has to be the real date. */
        SYSTEMTIME st; GetLocalTime(&st);
        cpu->cx = st.wYear;
        cpu->dh = (uint8_t)st.wMonth;
        cpu->dl = (uint8_t)st.wDay;
        cpu->al = (uint8_t)st.wDayOfWeek;
        cpu->flags &= ~FLAG_CF;
        break;
    }
    case 0x2C: {                           /* get time */
        SYSTEMTIME st; GetLocalTime(&st);
        cpu->ch = (uint8_t)st.wHour;
        cpu->cl = (uint8_t)st.wMinute;
        cpu->dh = (uint8_t)st.wSecond;
        cpu->dl = (uint8_t)(st.wMilliseconds / 10);
        cpu->flags &= ~FLAG_CF;
        break;
    }
    case 0x3D: {                           /* open existing file */
        char host[256];
        FILE *f = dos_map_path(cpu, host, sizeof host) ? fopen(host, "rb") : NULL;
        int slot = -1;
        if (f) for (int i = 0; i < (int)(sizeof g_dosfiles / sizeof g_dosfiles[0]); i++)
            if (!g_dosfiles[i]) { slot = i; break; }
        if (f && slot >= 0) {
            g_dosfiles[slot] = f;
            cpu->ax = (uint16_t)(slot + 5);    /* handle (0-4 reserved) */
            cpu->flags &= ~FLAG_CF;
            IMPL_LOG("[INT21] open -> handle %u (%s)\n", cpu->ax, host);
        } else {
            if (f) fclose(f);
            cpu->ax = 0x02; cpu->flags |= FLAG_CF;
            /* A data file the engine cannot open is never harmless -- it ends
               up as a null object several layers later. Say so, once each. */
            { static char told[24][192]; static int ntold; int seen = 0;
              for (int i = 0; i < ntold; i++)
                  if (!strcmp(told[i], g_last_dos_path)) { seen = 1; break; }
              if (!seen) {
                  if (ntold < 24) snprintf(told[ntold++], 192, "%s", g_last_dos_path);
                  fprintf(stderr, "[INT21] open FAILED: %s (tried %s)\n",
                          g_last_dos_path, host);
              } }
        }
        break;
    }
    case 0x3F: {                           /* read: bx=handle cx=count buf=ds:dx */
        int slot = (int)cpu->bx - 5;
        uint16_t cnt = cpu->cx, got = 0;
        if (slot >= 0 && slot < (int)(sizeof g_dosfiles/sizeof g_dosfiles[0]) && g_dosfiles[slot]) {
            for (; got < cnt; got++) {
                int c = fgetc(g_dosfiles[slot]);
                if (c < 0) break;
                mem_write8(cpu, cpu->ds, (uint16_t)(cpu->dx + got), (uint8_t)c);
            }
            cpu->ax = got; cpu->flags &= ~FLAG_CF;
        } else { cpu->ax = 0; cpu->flags |= FLAG_CF; }
        break;
    }
    case 0x42: {                           /* lseek: bx=handle al=whence cx:dx=off -> dx:ax pos */
        int slot = (int)cpu->bx - 5;
        if (slot >= 0 && slot < (int)(sizeof g_dosfiles/sizeof g_dosfiles[0]) && g_dosfiles[slot]) {
            long off = (long)(((uint32_t)cpu->cx << 16) | cpu->dx);
            int whence = (cpu->al == 1) ? SEEK_CUR : (cpu->al == 2) ? SEEK_END : SEEK_SET;
            fseek(g_dosfiles[slot], off, whence);
            long pos = ftell(g_dosfiles[slot]);
            cpu->ax = (uint16_t)pos; cpu->dx = (uint16_t)(pos >> 16);
            cpu->flags &= ~FLAG_CF;
        } else { cpu->flags |= FLAG_CF; }
        break;
    }
    case 0x3E: {                           /* close: bx=handle */
        int slot = (int)cpu->bx - 5;
        if (slot >= 0 && slot < (int)(sizeof g_dosfiles/sizeof g_dosfiles[0]) && g_dosfiles[slot]) {
            fclose(g_dosfiles[slot]); g_dosfiles[slot] = NULL;
        }
        cpu->flags &= ~FLAG_CF;
        break;
    }
    case 0x43: {                           /* get attributes = existence check */
        char host[256];
        FILE *f = dos_map_path(cpu, host, sizeof host) ? fopen(host, "rb") : NULL;
        if (f) { fclose(f); cpu->cx = 0; cpu->flags &= ~FLAG_CF; }
        else   { cpu->ax = 0x02; cpu->flags |= FLAG_CF; }
        break;
    }
    case 0x44:                             /* ioctl get-device-info -> regular disk file */
        cpu->dx = 0; cpu->ax = 0; cpu->flags &= ~FLAG_CF;
        break;
    case 0x1A:                             /* set DTA = ds:dx */
        g_dta_seg = cpu->ds; g_dta_off = cpu->dx;
        break;
    case 0x2F:                             /* get DTA -> es:bx */
        cpu->es = g_dta_seg; cpu->bx = g_dta_off;
        break;
    case 0x4E: {                           /* FindFirst: ds:dx pattern, cx attributes */
        char pat[192], dir[192], hostdir[256], host[320];
        static uint8_t want[16];
        read_asciiz(cpu, cpu->ds, cpu->dx, pat, sizeof pat);
        const char *leaf = pat;
        for (const char *q = pat; *q; q++) if (*q == '\\' || *q == '/' || *q == ':') leaf = q + 1;
        snprintf(dir, sizeof dir, "%.*s", (int)(leaf - pat), pat);
        if (dir[0] && map_guest_path(dir, hostdir, sizeof hostdir))
            snprintf(host, sizeof host, "%s/%s", hostdir, leaf);
        else
            snprintf(host, sizeof host, "%s/%s", RECOMP_DATA_DIR, leaf);
        int slot = 0;
        for (; slot < 16 && g_find[slot]; slot++) {}
        if (slot == 16) { FindClose(g_find[0]); g_find[0] = NULL; slot = 0; }  /* oldest goes */
        WIN32_FIND_DATAA fd;
        g_find[slot] = FindFirstFileA(host, &fd);
        want[slot] = cpu->cl;
        if (g_find[slot] == INVALID_HANDLE_VALUE) g_find[slot] = NULL;
        if (g_find[slot] && find_step(cpu, slot, &fd, want[slot], 1)) {
            cpu->ax = 0; cpu->flags &= ~FLAG_CF;
        } else {
            if (g_find[slot]) { FindClose(g_find[slot]); g_find[slot] = NULL; }
            cpu->ax = 0x12; cpu->flags |= FLAG_CF;     /* no more files */
        }
        IMPL_LOG("[INT21] FindFirst %s -> %s\n", host, (cpu->flags & FLAG_CF) ? "none" : "found");
        /* 4Fh needs the mask; keep it where it can find it */
        mem_write8(cpu, g_dta_seg, (uint16_t)(g_dta_off + 2), want[slot]);
        break;
    }
    case 0x4F: {                           /* FindNext: state in the current DTA */
        int slot = mem_read8(cpu, g_dta_seg, (uint16_t)(g_dta_off + 1));
        WIN32_FIND_DATAA fd;
        if (mem_read8(cpu, g_dta_seg, g_dta_off) == 'R' && slot < 16 && g_find[slot]
            && find_step(cpu, slot, &fd, mem_read8(cpu, g_dta_seg, (uint16_t)(g_dta_off + 2)), 0)) {
            cpu->ax = 0; cpu->flags &= ~FLAG_CF;
        } else {
            if (slot < 16 && g_find[slot]) { FindClose(g_find[slot]); g_find[slot] = NULL; }
            cpu->ax = 0x12; cpu->flags |= FLAG_CF;
        }
        break;
    }
    case 0x3C:                             /* create (read-only env) */
    case 0x40:                             /* write (read-only env) */
        cpu->ax = 0x05; cpu->flags |= FLAG_CF;
        break;
    default:
        IMPL_LOG("[INT21] ah=%02X (ignored)\n", cpu->ah);
        cpu->flags &= ~FLAG_CF;
        break;
    }
    /* `int` is not a far call - no stack frame to clean. */
}

/* ===== KERNEL: private profile (INI) =====
 * The engine reads its per-pet configuration out of the game's INI files; with
 * the stub returning empty it composed filenames from an empty key and threw an
 * XStruct "file not found". Serve them from the real INIs in RECOMP_DATA_DIR. */

/* Guest INI paths are absolute DOS ("C:\CATZ\KITTENZ.INI") or bare names. Only
 * the leaf matters — everything the game reads lives in the install root.
 *
 * A NULL/empty filename means WIN.INI under Win16, and the installer put the
 * game's [Catz] settings there. We have no Windows 3.1 WIN.INI, so fall back to
 * the INIs shipped in the install (LASTCAT.INI holds "This Last Cat", the pet
 * file the engine loads at startup). Anything not found there still gets the
 * caller's default, which is what the game ships with anyway. */
#ifndef RECOMP_WIN_INI
#define RECOMP_WIN_INI "win.ini"
#endif

static void ini_host_path(const char *guest, char *out, int outsz) {
    const char *leaf = guest;
    for (const char *q = guest; *q; q++) if (*q == '\\' || *q == '/') leaf = q + 1;
    snprintf(out, outsz, "%s/%s", RECOMP_DATA_DIR, leaf);
}

/* Resolve which host INI actually answers (app,key); empty guest name searches
 * the fallbacks in order. Returns 1 and fills `out` on a hit. */
static int ini_resolve(const char *guest, const char *app, const char *key,
                       char *out, int outsz) {
    /* A named INI wins if we actually have it. If we don't (the game names
     * C:\WINDOWS\catz.ini / catzdbug.ini, which only exist on a real Win3.1
     * install), fall through to the substitutes below rather than answering
     * from a file that isn't there. */
    if (guest && guest[0]) {
        ini_host_path(guest, out, outsz);
        FILE *probe = fopen(out, "rb");
        if (probe) { fclose(probe); return 1; }
    }
    for (int i = -1; i < 6; i++) {
        const char *f = i < 0 ? RECOMP_WIN_INI : recomp_game.ini_fallbacks[i];
        if (!f) break;
        if (strchr(f, '/'))  snprintf(out, outsz, "%s", f);          /* already a host path */
        else                 snprintf(out, outsz, "%s/%s", RECOMP_DATA_DIR, f);
        char probe[8];
        if (GetPrivateProfileStringA(app, key, "\1", probe, sizeof probe, out) &&
            probe[0] != '\1')
            return 1;
    }
    return 0;                       /* no hit: caller's default stands */
}

/* A profile call whose app-name or file-name arrives with a null selector is
   the guest building a far pointer from a null DS, not an intentional NULL:
   Win16 code passes 0000:0000, never 0000:<offset>. Report the caller so the
   corruption is traced to its source rather than silently answering garbage
   (lpAppName=NULL makes GetPrivateProfileString return the *section list*). */
static void ini_check_selectors(CPU *cpu, const char *who,
                                uint16_t apseg, uint16_t apoff,
                                uint16_t fnseg, uint16_t fnoff) {
    static int fired = 0;
    if ((apseg || !apoff) && (fnseg || !fnoff)) return;
    if (fired++ >= 4) return;
    fprintf(stderr, "[NULL-SEL] %s: app=%04X:%04X file=%04X:%04X\n",
            who, apseg, apoff, fnseg, fnoff);
    dump_guest_stack(cpu, 30);
    fflush(stderr);
}

/* WritePrivateProfileString was a stub returning 0, so the engine could not
 * persist anything: not its settings, and not a newly adopted cat. It writes
 * the pet out and reads it straight back, got nothing, and ended up with a null
 * object it then spun on. Same file resolution as the read side.
 *
 * Win16 args (PASCAL, last pushed at offset 0):
 *   lpFileName@0(4) lpString@4(4) lpKeyName@8(4) lpAppName@12(4) */
void KERNEL_WRITEPRIVATEPROFILESTRING(CPU *cpu) {
    uint16_t fnoff = a16(cpu, 0),  fnseg = a16(cpu, 2);
    uint16_t vloff = a16(cpu, 4),  vlseg = a16(cpu, 6);
    uint16_t kyoff = a16(cpu, 8),  kyseg = a16(cpu, 10);
    uint16_t apoff = a16(cpu, 12), apseg = a16(cpu, 14);

    char app[128] = "", key[128] = "", val[512] = "", file[192] = "";
    if (apseg) read_asciiz(cpu, apseg, apoff, app, sizeof app);
    if (kyseg) read_asciiz(cpu, kyseg, kyoff, key, sizeof key);
    if (vlseg) read_asciiz(cpu, vlseg, vloff, val, sizeof val);
    if (fnseg) read_asciiz(cpu, fnseg, fnoff, file, sizeof file);

    char host[320];
    ini_resolve(file, app, key, host, sizeof host);
    /* A NULL key erases the whole section, a NULL value erases the key --
       both are how Win16 callers clear state, so pass the nulls through. */
    BOOL ok = WritePrivateProfileStringA(apseg ? app : NULL,
                                         kyseg ? key : NULL,
                                         vlseg ? val : NULL, host);
    IMPL_LOG("[ini] WritePrivateProfileString(%s, [%s] %s = ""%s"") -> %d\n",
             host, app, key, val, (int)ok);
    cpu->ax = (uint16_t)(ok ? 1 : 0);
    ret(cpu, 16);
}

void KERNEL_GETPRIVATEPROFILESTRING(CPU *cpu) {
    /* (lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, lpFileName) */
    uint16_t fnoff = a16(cpu, 0),  fnseg = a16(cpu, 2);
    uint16_t nsize = a16(cpu, 4);
    uint16_t rsoff = a16(cpu, 6),  rsseg = a16(cpu, 8);
    uint16_t dfoff = a16(cpu, 10), dfseg = a16(cpu, 12);
    uint16_t kyoff = a16(cpu, 14), kyseg = a16(cpu, 16);
    uint16_t apoff = a16(cpu, 18), apseg = a16(cpu, 20);

    char app[128] = "", key[128] = "", def[256] = "", file[192] = "";
    if (apseg) read_asciiz(cpu, apseg, apoff, app, sizeof app);
    if (kyseg) read_asciiz(cpu, kyseg, kyoff, key, sizeof key);
    if (dfseg) read_asciiz(cpu, dfseg, dfoff, def, sizeof def);
    if (fnseg) read_asciiz(cpu, fnseg, fnoff, file, sizeof file);

    ini_check_selectors(cpu, "GetPrivateProfileString", apseg, apoff, fnseg, fnoff);
    char host[320]; ini_resolve(file, app, key, host, sizeof host);
    char val[1024];
    DWORD n = GetPrivateProfileStringA(apseg ? app : NULL, kyseg ? key : NULL,
                                       def, val, sizeof val, host);
    /* The playpen wallpaper is the one setting the engine cannot cope with
       missing: with no name it composes the path "\\playpenz\\", fails to open a
       directory, and leaves a null draw object it then spins on -- which is
       what locked the screen after adopting a cat. A save written before the
       key existed simply has not got one, so stand in the plain backdrop and
       let the engine persist the player's own choice over it. */
    for (int i = 0; !n && recomp_game.ini_defaults[i]; i += 2)
        if (!strcmp(key, recomp_game.ini_defaults[i])) {
            snprintf(val, sizeof val, "%s", recomp_game.ini_defaults[i + 1]);
            n = (DWORD)strlen(val);
        }
    if (n > (DWORD)nsize) n = nsize ? (DWORD)nsize - 1 : 0;   /* clamp to guest buffer */
    for (DWORD i = 0; i < n; i++) mem_write8(cpu, rsseg, (uint16_t)(rsoff + i), (uint8_t)val[i]);
    if (nsize) mem_write8(cpu, rsseg, (uint16_t)(rsoff + n), 0);

    /* The serial number is licence data and is NOT shipped with this project:
       it must come from the user's own copy. Say so once, plainly, instead of
       letting the engine drop into its registration wizard with no explanation. */
    if (!n && recomp_game.serial_key && !strcmp(key, recomp_game.serial_key)) {
        static int said = 0;
        if (!said++ && recomp_game.serial_help)
            fprintf(stderr, recomp_game.serial_help, RECOMP_DATA_DIR);
    }

    fprintf(stderr, "[ini] GetPrivateProfileString(%s, [%s] %s, def=\"%s\") -> \"%s\"\n",
            file, app, key, def, n ? val : "");
    cpu->ax = (uint16_t)n;
    ret(cpu, 22);
}

void KERNEL_GETPRIVATEPROFILEINT(CPU *cpu) {
    /* (lpAppName, lpKeyName, nDefault, lpFileName) */
    uint16_t fnoff = a16(cpu, 0), fnseg = a16(cpu, 2);
    uint16_t ndef  = a16(cpu, 4);
    uint16_t kyoff = a16(cpu, 6),  kyseg = a16(cpu, 8);
    uint16_t apoff = a16(cpu, 10), apseg = a16(cpu, 12);

    char app[128] = "", key[128] = "", file[192] = "";
    if (apseg) read_asciiz(cpu, apseg, apoff, app, sizeof app);
    if (kyseg) read_asciiz(cpu, kyseg, kyoff, key, sizeof key);
    if (fnseg) read_asciiz(cpu, fnseg, fnoff, file, sizeof file);

    ini_check_selectors(cpu, "GetPrivateProfileInt", apseg, apoff, fnseg, fnoff);
    char host[320]; ini_resolve(file, app, key, host, sizeof host);
    cpu->ax = (uint16_t)GetPrivateProfileIntA(app, key, ndef, host);
    fprintf(stderr, "[ini] GetPrivateProfileInt(%s, [%s]@%04X:%04X %s@%04X:%04X) -> %u\n",
            file, app, apseg, apoff, key, kyseg, kyoff, cpu->ax);
    ret(cpu, 14);
}

/* ===== USER: wsprintf =====
 * The engine formats filenames, resource keys and its whole debug log through
 * this; with the stub returning an empty buffer it composed empty paths and
 * threw "file not found". _wsprintf is the cdecl variant (caller cleans), so
 * the purge is 0 and we just walk the arg words ourselves. Supports the subset
 * Win16 wsprintf actually documents: %s (far ptr), %c, %d/%i/%u/%x/%X with an
 * optional l (DWORD) size, %%, plus '-'/'0' flags and a width. */
/* The formatter both share: the arguments are words at aseg:aoff on, on the
 * stack for wsprintf, behind a far pointer for wvsprintf. */
static uint16_t format16(CPU *cpu, uint16_t oseg, uint16_t ooff,
                         uint16_t fseg, uint16_t foff, uint16_t aseg, uint16_t aoff) {
#define a16(cpu, i) mem_read16(cpu, aseg, (uint16_t)(aoff + (i)))
#define a32(cpu, i) ((uint32_t)a16(cpu, i) | (uint32_t)a16(cpu, (i) + 2) << 16)
    int argi = 0;                          /* next argument, bytes from aoff */

    char fmt[512]; read_asciiz(cpu, fseg, foff, fmt, sizeof fmt);
    char out[1024]; int n = 0;

    for (const char *p = fmt; *p && n < (int)sizeof out - 1; p++) {
        if (*p != '%') { out[n++] = *p; continue; }
        p++;
        if (*p == '%') { out[n++] = '%'; continue; }

        int left = 0, zero = 0, width = 0, lng = 0;
        for (; *p == '-' || *p == '0'; p++) { if (*p == '-') left = 1; else zero = 1; }
        for (; *p >= '0' && *p <= '9'; p++) width = width * 10 + (*p - '0');
        if (*p == '.') { p++; while (*p >= '0' && *p <= '9') p++; }   /* precision: ignored */
        if (*p == 'l' || *p == 'L') { lng = 1; p++; }

        char item[512]; item[0] = 0;
        switch (*p) {
        case 's': {
            uint16_t soff = a16(cpu, argi), sseg = a16(cpu, argi + 2); argi += 4;
            read_asciiz(cpu, sseg, soff, item, sizeof item);
            break;
        }
        case 'c':
            item[0] = (char)a16(cpu, argi); item[1] = 0; argi += 2;
            break;
        case 'd': case 'i': {
            long v = lng ? (long)(int32_t)a32(cpu, argi) : (long)(int16_t)a16(cpu, argi);
            argi += lng ? 4 : 2;
            snprintf(item, sizeof item, "%ld", v);
            break;
        }
        case 'u': {
            unsigned long v = lng ? (unsigned long)a32(cpu, argi) : (unsigned long)a16(cpu, argi);
            argi += lng ? 4 : 2;
            snprintf(item, sizeof item, "%lu", v);
            break;
        }
        case 'x': case 'X': {
            unsigned long v = lng ? (unsigned long)a32(cpu, argi) : (unsigned long)a16(cpu, argi);
            argi += lng ? 4 : 2;
            snprintf(item, sizeof item, *p == 'x' ? "%lx" : "%lX", v);
            break;
        }
        default:                            /* unknown conversion: emit literally */
            item[0] = '%'; item[1] = *p; item[2] = 0;
            break;
        }

        int ilen = (int)strlen(item), pad = width > ilen ? width - ilen : 0;
        if (!left) for (int i = 0; i < pad && n < (int)sizeof out - 1; i++) out[n++] = zero ? '0' : ' ';
        for (int i = 0; i < ilen && n < (int)sizeof out - 1; i++) out[n++] = item[i];
        if (left)  for (int i = 0; i < pad && n < (int)sizeof out - 1; i++) out[n++] = ' ';
    }
    out[n] = 0;

    for (int i = 0; i <= n; i++) mem_write8(cpu, oseg, (uint16_t)(ooff + i), (uint8_t)out[i]);
    IMPL_LOG("[wsprintf] fmt=%s| -> %s|\n", fmt, out);
    return (uint16_t)n;
#undef a16
#undef a32
}

void USER__WSPRINTF(CPU *cpu) {            /* cdecl (lpOut, lpFmt, ...): caller cleans */
    cpu->ax = format16(cpu, a16(cpu, 2), a16(cpu, 0), a16(cpu, 6), a16(cpu, 4),
                       cpu->ss, (uint16_t)(cpu->sp + 4 + 8));
    ret(cpu, 0);
}

/* wvsprintf(lpOut@8/10, lpFmt@4/6, lpArgs@0/2): PASCAL, the arguments behind
 * a far pointer. SimAnt formats its fatal-error text through it. */
void USER_WVSPRINTF(CPU *cpu) {
    cpu->ax = format16(cpu, a16(cpu, 10), a16(cpu, 8), a16(cpu, 6), a16(cpu, 4),
                       a16(cpu, 2), a16(cpu, 0));
    ret(cpu, 12);
}

/* ===== KERNEL: Win16 file API =====
 * The engine loads its data files (pet .lnz, sound tables, sprite data) through
 * OpenFile/_lopen/_lread rather than INT 21h, and these were stubs returning 0 —
 * so every load silently produced nothing. Same host mapping as the DOS path. */
/* One handle space with INT 21h, as on the real thing: a handle from
 * AccessResource or _lopen is read with DOS read() as often as with _lread.
 * Two tables numbered from 1 and 5 handed out colliding handles. */
#define NDOSFILES ((int)(sizeof g_dosfiles / sizeof g_dosfiles[0]))

static FILE *lfile(uint16_t h) {
    return (h >= 5 && h - 5 < NDOSFILES) ? g_dosfiles[h - 5] : NULL;
}

static uint16_t lfile_add(FILE *f) {
    for (int i = 0; i < NDOSFILES; i++)
        if (!g_dosfiles[i]) { g_dosfiles[i] = f; return (uint16_t)(i + 5); }
    fclose(f);
    return 0xFFFF;
}

static uint16_t lopen_host(const char *guest, const char *mode) {
    char host[320];
    if (!map_guest_path(guest, host, sizeof host)) return 0xFFFF;   /* HFILE_ERROR */
    FILE *f = fopen(host, mode);
    if (!f) { fprintf(stderr, "[file] open FAILED %s -> %s\n", guest, host); return 0xFFFF; }
    uint16_t h = lfile_add(f);
    fprintf(stderr, "[file] open %s -> handle %d\n", guest, h);
    return h;
}

void KERNEL_OPENFILE(CPU *cpu) {
    /* OpenFile(lpFileName, lpReOpenBuff, wStyle); OF_EXIST(0x4000) only probes. */
    uint16_t style = a16(cpu, 0);
    uint16_t boff  = a16(cpu, 2), bseg = a16(cpu, 4);
    uint16_t noff  = a16(cpu, 6), nseg = a16(cpu, 8);
    char name[192]; read_asciiz(cpu, nseg, noff, name, sizeof name);

    char host[320];
    int mapped = map_guest_path(name, host, sizeof host);
    if (style & 0x4000) {                    /* OF_EXIST: report, don't keep open */
        FILE *f = mapped ? fopen(host, "rb") : NULL;
        if (f) fclose(f);
        cpu->ax = f ? 1 : 0xFFFF;
    } else {
        cpu->ax = lopen_host(name, (style & 3) ? "r+b" : "rb");
    }
    /* OFSTRUCT: cBytes, fFixedDisk, nErrCode, reserved[4], szPathName[128] */
    if (bseg) {
        mem_write8(cpu, bseg, boff, (uint8_t)sizeof(name));
        mem_write16(cpu, bseg, (uint16_t)(boff + 2), (uint16_t)(cpu->ax == 0xFFFF ? 2 : 0));
        int i = 0;
        for (; name[i] && i < 127; i++) mem_write8(cpu, bseg, (uint16_t)(boff + 8 + i), (uint8_t)name[i]);
        mem_write8(cpu, bseg, (uint16_t)(boff + 8 + i), 0);
    }
    ret(cpu, 10);
}

void KERNEL__LOPEN(CPU *cpu) {              /* _lopen(lpPathName, iReadWrite) */
    uint16_t rw   = a16(cpu, 0);
    uint16_t noff = a16(cpu, 2), nseg = a16(cpu, 4);
    char name[192]; read_asciiz(cpu, nseg, noff, name, sizeof name);
    cpu->ax = lopen_host(name, (rw & 3) ? "r+b" : "rb");
    ret(cpu, 6);
}

void KERNEL__LCREAT(CPU *cpu) {             /* _lcreat(lpPathName, iAttribute) */
    uint16_t noff = a16(cpu, 2), nseg = a16(cpu, 4);
    char name[192]; read_asciiz(cpu, nseg, noff, name, sizeof name);
    cpu->ax = lopen_host(name, "w+b");
    ret(cpu, 6);
}

void KERNEL__LREAD(CPU *cpu) {              /* _lread(hFile, lpBuffer, wBytes) */
    uint16_t n    = a16(cpu, 0);
    uint16_t boff = a16(cpu, 2), bseg = a16(cpu, 4);
    uint16_t h    = a16(cpu, 6);
    FILE *f = lfile(h);
    uint16_t got = 0;
    if (f) {
        for (; got < n; got++) {
            int c = fgetc(f);
            if (c < 0) break;
            mem_write8(cpu, bseg, (uint16_t)(boff + got), (uint8_t)c);
        }
        cpu->ax = got;
    } else {
        cpu->ax = 0xFFFF;
    }
    ret(cpu, 8);
}

/* _hread(hFile, lpBuffer, lBytes) -> LONG: _lread with a 32-bit count into a
 * huge buffer. The buffer's tiles sit over one flat range (cpu_alloc_selector),
 * so the read lands at sel_base[sel] + off contiguously. */
void KERNEL__HREAD(CPU *cpu) {
    uint32_t n    = a16(cpu, 0) | ((uint32_t)a16(cpu, 2) << 16);
    uint16_t boff = a16(cpu, 4), bseg = a16(cpu, 6);
    uint16_t h    = a16(cpu, 8);
    FILE *f = lfile(h);
    uint32_t base = cpu->sel_base[bseg] + boff, got = 0;
    if (f && base < cpu->mem_size) {
        if (n > cpu->mem_size - base) n = cpu->mem_size - base;
        got = (uint32_t)fread(cpu->mem + base, 1, n, f);
        cpu->ax = (uint16_t)got; cpu->dx = (uint16_t)(got >> 16);
    } else {
        cpu->ax = 0xFFFF; cpu->dx = 0xFFFF;  /* HFILE_ERROR as a LONG */
    }
    ret(cpu, 10);
}

void KERNEL__LWRITE(CPU *cpu) {             /* read-only bring-up: report success */
    uint16_t n = a16(cpu, 0);
    cpu->ax = n;
    ret(cpu, 8);
}

void KERNEL__LCLOSE(CPU *cpu) {             /* _lclose(hFile) */
    uint16_t h = a16(cpu, 0);
    FILE *f = lfile(h);
    if (f) { fclose(f); g_dosfiles[h - 5] = NULL; }
    cpu->ax = f ? 0 : 0xFFFF;
    ret(cpu, 2);
}

void KERNEL__LLSEEK(CPU *cpu) {             /* _llseek(hFile, lOffset, iOrigin) */
    uint16_t origin = a16(cpu, 0);
    int32_t  off    = (int32_t)a32(cpu, 2);
    uint16_t h      = a16(cpu, 6);
    FILE *f = lfile(h);
    long pos = -1;
    if (f && fseek(f, off, origin == 1 ? SEEK_CUR : origin == 2 ? SEEK_END : SEEK_SET) == 0)
        pos = ftell(f);
    cpu->ax = (uint16_t)(pos < 0 ? 0xFFFF : (uint32_t)pos);
    cpu->dx = (uint16_t)(pos < 0 ? 0xFFFF : ((uint32_t)pos >> 16));
    ret(cpu, 8);
}

/* ===== TOOLHELP: GlobalEntryHandle =====
 * The engine validates every heap block it owns by asking TOOLHELP to describe
 * the handle; the stub returned FALSE, so the engine concluded its own heap was
 * corrupt and logged "###ERROR: You've stomped on memory, dude" for essentially
 * every allocation. Describe the block for real: a handle IS a selector here, so
 * everything the caller needs is already in the allocator's tables. */
void TOOLHELP_GLOBALENTRYHANDLE(CPU *cpu) {
    /* GlobalEntryHandle(lpGlobalEntry, hItem) */
    uint16_t h    = a16(cpu, 0);
    uint16_t eoff = a16(cpu, 2), eseg = a16(cpu, 4);
    uint32_t size = h ? g_sel_size[h] : 0;

    if (!h || !size) { cpu->ax = 0; ret(cpu, 6); return; }   /* not a live block */

    /* GLOBALENTRY (36 bytes): dwSize@0, dwAddress@4, dwBlockSize@8, hBlock@12,
     * wcLock@14, wcPageLock@16, wFlags@18, wHeapPresent@20, hOwner@22,
     * wType@24, wData@26, dwNext@28, dwNextAlt@32. */
    #define GE_W(o, v) mem_write16(cpu, eseg, (uint16_t)(eoff + (o)), (uint16_t)(v))
    GE_W(0, 36);            GE_W(2, 0);
    GE_W(4, 0);             GE_W(6, h);      /* dwAddress: this selector, offset 0 */
    GE_W(8, size);          GE_W(10, size >> 16);
    GE_W(12, h);            GE_W(14, 0);
    GE_W(16, 0);            GE_W(18, 0);
    GE_W(20, 0);            GE_W(22, h);     /* hOwner == the block itself */
    GE_W(24, 0);            GE_W(26, 0);
    GE_W(28, 0);            GE_W(30, 0);
    GE_W(32, 0);            GE_W(34, 0);
    #undef GE_W

    cpu->ax = 1;                            /* TRUE */
    ret(cpu, 6);
}

/* ==== KERNEL shims first needed by Dogz and Oddballz ==== */

void KERNEL_LSTRLEN(CPU *cpu) {             /* lstrlen(lpString@0/2) */
    uint16_t o = a16(cpu, 0), s = a16(cpu, 2);
    uint16_t n = 0;
    if (s) while (n < 0xFFFF && mem_read8(cpu, s, (uint16_t)(o + n))) n++;
    cpu->ax = n;
    ret(cpu, 4);
}

/* hmemcpy(hpvDest@8/10, hpvSource@4/6, cbCopy@0/2): huge pointers, so a copy
   can cross 64 KB; the tiles of a huge block are one flat range. */
void KERNEL_HMEMCPY(CPU *cpu) {
    uint32_t n = a16(cpu, 0) | ((uint32_t)a16(cpu, 2) << 16);
    uint32_t src = cpu->sel_base[a16(cpu, 6)] + a16(cpu, 4);
    uint32_t dst = cpu->sel_base[a16(cpu, 10)] + a16(cpu, 8);
    if (src + n <= cpu->mem_size && dst + n <= cpu->mem_size)
        memmove(cpu->mem + dst, cpu->mem + src, n);
    ret(cpu, 12);
}

/* GetModuleHandle(lpModuleName@0/2): a lifted module answers with its handle
   (see recomp_hinst_alias); the system modules get stand-ins so a caller that
   only checks for non-zero -- or feeds the result to GetProcAddress, which
   then reports "not lifted" -- carries on. */
void KERNEL_GETMODULEHANDLE(CPU *cpu) {
    uint16_t o = a16(cpu, 0), s = a16(cpu, 2);
    char name[64] = "";
    if (s) read_asciiz(cpu, s, o, name, sizeof name);
    else { cpu->ax = o; ret(cpu, 4); return; }   /* already a handle: identity */
    char base[64]; int k = 0;
    for (const char *p = name; *p && *p != '.' && k < 63; p++) base[k++] = (char)toupper((unsigned char)*p);
    base[k] = 0;
    cpu->ax = 0;
    for (int i = 0; i < RECOMP_NUM_MODULES; i++) {
        const RecompModule *m = &RECOMP_MODULES[i];
        char fb[32]; int j = 0;
        for (const char *p = m->file; *p && *p != '.' && j < 31; p++) fb[j++] = (char)toupper((unsigned char)*p);
        fb[j] = 0;
        if (!strcmp(base, fb) || !_stricmp(base, m->name)) { cpu->ax = recomp_hinst_alias(m->dgroup); break; }
    }
    if (!cpu->ax && (!strcmp(base, "KERNEL") || !strcmp(base, "USER") || !strcmp(base, "GDI")))
        cpu->ax = (uint16_t)(0x00F0 + base[0]);  /* nonzero, never a lifted DGROUP */
    ret(cpu, 4);
}

void KERNEL_SETERRORMODE(CPU *cpu) { cpu->ax = 0; ret(cpu, 2); }   /* previous mode */
void KERNEL_DEBUGBREAK(CPU *cpu)   { ret(cpu, 0); }

/* GetDOSEnvironment() -> far pointer to "VAR=value\0...\0\0". An empty block:
   nothing the recomp runs reads a variable it would miss. */
void KERNEL_GETDOSENVIRONMENT(CPU *cpu) {
    static uint16_t env;
    if (!env) env = galloc(cpu, 16);        /* zeroed: an empty environment */
    cpu->dx = env; cpu->ax = 0;
    ret(cpu, 0);
}

/* GlobalDosAlloc(dwBytes@0/2) -> DWORD: real-mode paragraph (hi) and
   selector (lo). There is no real mode here; both halves name the block. */
void KERNEL_GLOBALDOSALLOC(CPU *cpu) {
    uint32_t n = a16(cpu, 0) | ((uint32_t)a16(cpu, 2) << 16);
    uint16_t s = galloc(cpu, n);
    cpu->ax = s; cpu->dx = s;
    ret(cpu, 4);
}
void KERNEL_GLOBALDOSFREE(CPU *cpu) { cpu->ax = 0; ret(cpu, 2); }

/* WinExec(lpCmdLine@2/4, nCmdShow@0): nothing else can run; 2 = file not found. */
void KERNEL_WINEXEC(CPU *cpu) { cpu->ax = 2; ret(cpu, 6); }

/* _hwrite(hFile@8, lpBuffer@4/6, lBytes@0/2): as _lwrite, a read-only bring-up
   reports the whole count written. */
void KERNEL__HWRITE(CPU *cpu) { cpu->ax = a16(cpu, 0); cpu->dx = a16(cpu, 2); ret(cpu, 10); }

/* TimerCount(lpti@0/2): TIMERINFO { DWORD dwSize, dwmsSinceStart, dwmsThisVM }. */
void TOOLHELP_TIMERCOUNT(CPU *cpu) {
    uint16_t o = a16(cpu, 0), s = a16(cpu, 2);
    DWORD t = GetTickCount();
    if (s) {
        for (int k = 4; k <= 8; k += 4) {
            mem_write16(cpu, s, (uint16_t)(o + k), (uint16_t)t);
            mem_write16(cpu, s, (uint16_t)(o + k + 2), (uint16_t)(t >> 16));
        }
    }
    cpu->ax = s ? 1 : 0;
    ret(cpu, 4);
}

/* The registry (SHELL.DLL). Oddballz registers its file types on every start;
   there is nothing to register them with, and success lets it move on. */
void SHELL_REGCREATEKEY(CPU *cpu) {         /* (hKey@8/10, lpSubKey@4/6, phkResult@0/2) */
    uint16_t o = a16(cpu, 0), s = a16(cpu, 2);
    if (s) { mem_write16(cpu, s, o, 0x0100); mem_write16(cpu, s, (uint16_t)(o + 2), 0); }
    cpu->ax = 0; cpu->dx = 0;               /* ERROR_SUCCESS */
    ret(cpu, 12);
}
void SHELL_REGSETVALUE(CPU *cpu) { cpu->ax = 0; cpu->dx = 0; ret(cpu, 20); }

/* ===== KERNEL: WIN.INI, strings, memory flags =====
 * SimAnt keeps its ribbon's user-button choices in WIN.INI [SimAnt]:
 * GetProfileInt(app, "Button%d", current) for each one. As a stub returning 0
 * every button became type 0, and the row showed one icon eight times. WIN.INI
 * is served the way a NULL lpFileName is for the private-profile calls, and
 * writes go to RECOMP_DATA_DIR, never the host's own WIN.INI. */
void KERNEL_GETPROFILEINT(CPU *cpu) {      /* (lpAppName@6/8, lpKeyName@2/4, nDefault@0) */
    char app[128] = "", key[128] = "", host[320];
    read_asciiz(cpu, a16(cpu, 8), a16(cpu, 6), app, sizeof app);
    read_asciiz(cpu, a16(cpu, 4), a16(cpu, 2), key, sizeof key);
    uint16_t def = a16(cpu, 0);
    cpu->ax = ini_resolve("", app, key, host, sizeof host)
            ? (uint16_t)GetPrivateProfileIntA(app, key, (int16_t)def, host) : def;
    ret(cpu, 10);
}

void KERNEL_WRITEPROFILESTRING(CPU *cpu) { /* (lpAppName@8/10, lpKeyName@4/6, lpString@0/2) */
    char app[128] = "", key[128] = "", val[512] = "", host[320];
    uint16_t kseg = a16(cpu, 6), vseg = a16(cpu, 2);
    read_asciiz(cpu, a16(cpu, 10), a16(cpu, 8), app, sizeof app);
    if (kseg) read_asciiz(cpu, kseg, a16(cpu, 4), key, sizeof key);
    if (vseg) read_asciiz(cpu, vseg, a16(cpu, 0), val, sizeof val);
    snprintf(host, sizeof host, "%s/%s", RECOMP_DATA_DIR, RECOMP_WIN_INI);
    cpu->ax = (uint16_t)!!WritePrivateProfileStringA(app, kseg ? key : NULL,
                                                     vseg ? val : NULL, host);
    ret(cpu, 12);
}

/* lstrcpy/lstrcat(lpDst@4/6, lpSrc@0/2) -> lpDst in DX:AX. */
static void lstr_copy(CPU *cpu, int append) {
    uint16_t doff = a16(cpu, 4), dseg = a16(cpu, 6);
    uint16_t soff = a16(cpu, 0), sseg = a16(cpu, 2);
    uint16_t d = doff;
    if (append) while (mem_read8(cpu, dseg, d)) d++;
    uint8_t c;
    do { c = mem_read8(cpu, sseg, soff++); mem_write8(cpu, dseg, d++, c); } while (c);
    cpu->ax = doff; cpu->dx = dseg;
    ret(cpu, 8);
}
void KERNEL_LSTRCPY(CPU *cpu) { lstr_copy(cpu, 0); }
void KERNEL_LSTRCAT(CPU *cpu) { lstr_copy(cpu, 1); }

void KERNEL_GETSYSTEMDIRECTORY(CPU *cpu) { /* (lpBuffer@2/4, uSize@0) -> length */
    static const char dir[] = "C:\\WINDOWS\\SYSTEM";
    uint16_t off = a16(cpu, 2), seg = a16(cpu, 4), n = a16(cpu, 0);
    if (n > sizeof dir)
        for (unsigned i = 0; i < sizeof dir; i++) mem_write8(cpu, seg, (uint16_t)(off + i), (uint8_t)dir[i]);
    cpu->ax = n > sizeof dir ? (uint16_t)(sizeof dir - 1) : (uint16_t)sizeof dir;
    ret(cpu, 6);
}

/* Nothing is ever discarded or moved here, so no handle is discardable. */
void KERNEL_GLOBALFLAGS(CPU *cpu)     { cpu->ax = 0; ret(cpu, 2); }
void KERNEL_GLOBALLRUNEWEST(CPU *cpu) { cpu->ax = a16(cpu, 0); ret(cpu, 2); }

/* AddFontResource(lpFilename@0/2): SimAnt ships its own FONTRES.FON. Added
 * privately, so the font lives only as long as the game. A null selector is a
 * module handle (a loaded font DLL), which nothing here produces. */
static void font_resource(CPU *cpu, int add) {
    char g[260], host[320];
    uint16_t seg = a16(cpu, 2);
    cpu->ax = 0;
    if (seg) {
        read_asciiz(cpu, seg, a16(cpu, 0), g, sizeof g);
        if (map_guest_path(g, host, sizeof host))
            cpu->ax = (uint16_t)(add ? AddFontResourceExA(host, FR_PRIVATE, 0)
                                     : RemoveFontResourceExA(host, FR_PRIVATE, 0));
        IMPL_LOG("[gdi] %sFontResource(%s -> %s) -> %u\n", add ? "Add" : "Remove", g, host, cpu->ax);
    }
    ret(cpu, 4);
}
void GDI_ADDFONTRESOURCE(CPU *cpu)    { font_resource(cpu, 1); }
void GDI_REMOVEFONTRESOURCE(CPU *cpu) { font_resource(cpu, 0); }
