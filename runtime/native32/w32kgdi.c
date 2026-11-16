/*
 * w32kgdi: GDI's half of win32k, for a lifted Windows 2000 gdi32 on the
 * host's GDI (syscall32.c's win32k table).
 *
 * gdi32 is a client of state win32k shares with it, read directly:
 *
 *   handle table  Peb->GdiSharedHandleTable, 0x4000 GDI_TABLE_ENTRYs of 16
 *                 bytes. gdi32 validates a handle h against entry
 *                 [h & 0xFFFF] (an index of 0x4000 or more is invalid): +0x08
 *                 the handle's high word, +0x0A its type (h >> 16 & 0x1F; 1 a
 *                 DC), +0x04 the owning process (pid, low bits clear), +0x0C
 *                 the object's user-mode attributes.
 *   DC_ATTR       a DC's attributes, which gdi32 changes in user mode and
 *                 win32k reads when it draws (Windows 2000 SP4 offsets, from
 *                 the lifted gdi32): +0x04 dirty flags, +0x08 the selected
 *                 brush, +0x0C the pen (SelectObject sets them, no system
 *                 call), +0x14 the background colour, +0x1C the text colour,
 *                 +0x38 the ROP2, +0x39 the background mode, +0x3C/+0x40 the
 *                 current position, +0x7C the text alignment, +0x90 the font,
 *                 +0x1B0/+0x1B4 the brush origin.
 *   TEB batch     some calls are queued in the TEB, not made: TEB+0x1D4 the
 *                 bytes used, +0x1D8 the DC, +0x1DC the entries
 *                 { USHORT length, USHORT command, data }, +0xF70 their count.
 *                 win32k runs them on entry to any GDI service and at
 *                 NtGdiFlushUserBatch. Commands: 0 PatBlt { x, y, cx, cy,
 *                 brush, rop, colours... } (0x34 bytes), 1 PolyPatBlt (DrawEdge),
 *                 4 SetBrushOrg { x, y }, 6 select a font, 8 DeleteObject.
 *
 * Here the table is ours, in that layout, over the host's GDI objects. The
 * guest never sees a host handle: a host's index runs to 0xFFFF, which
 * Windows 2000's gdi32 rejects. Each host object gets a guest handle, the
 * host's high word (the type codes are the same) with an index of ours below
 * 0x4000; the NtGdi* services translate both ways, and so do the hooks on
 * host user32 in its proxy image (BeginPaint, GetDC, ..., EndPaint, ReleaseDC,
 * RegisterClass, LoadBitmap, LoadImage). Before a draw the DC's attributes go
 * onto the host DC.
 *
 * The table, the translation, DC_ATTR and the batch are what a full win32k
 * (user32 lifted too) will share: native32_gdi_handle, native32_gdi_host and
 * native32_gdi_attr are its entry points; the services and hooks are this
 * host-user32 configuration's.
 *
 * ponytail: DC_ATTR fields beyond those above (mapping mode, brush origin,
 * stretch mode, ...) are not synced; batch commands other than PatBlt and
 * a font selection are logged and dropped. Add each with the program that needs it.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "native32.h"

#define GDI_ENTRIES 0x4000
#define ATTR_SIZE 0x400
#define HASH 0x8000                      /* host handle -> guest index, open addressing */

static uint8_t* g_table;                 /* the shared section: entries, then gdi32's shared data */
static uint32_t g_host[GDI_ENTRIES];     /* guest index -> host handle */
static uint32_t g_hkey[HASH];            /* host handle (0 empty, 1 deleted) */
static uint16_t g_hval[HASH];            /* its guest index */
static int g_top = 1;                    /* index 0 is never used */
static int g_free[GDI_ENTRIES], g_nfree; /* indices given back */

static uint32_t ea(int i) { return (uint32_t)(uintptr_t)(g_table + 16 * i); }
static uint32_t slot(uint32_t h) { return (h * 2654435761u) >> 17; }

static int hfind(uint32_t h) {
    for (uint32_t s = slot(h), n = 0; n < HASH; s = (s + 1) & (HASH - 1), n++) {
        if (g_hkey[s] == h) return g_hval[s];
        if (!g_hkey[s]) return 0;
    }
    return 0;
}
static void hput(uint32_t h, int i) {
    uint32_t s = slot(h);
    while (g_hkey[s] > 1) s = (s + 1) & (HASH - 1);
    g_hkey[s] = h, g_hval[s] = (uint16_t)i;
}
static void hdel(uint32_t h) {
    for (uint32_t s = slot(h), n = 0; n < HASH && g_hkey[s]; s = (s + 1) & (HASH - 1), n++)
        if (g_hkey[s] == h) { g_hkey[s] = 1; return; }
}

/* The host object behind a guest handle (0 for none or a stale handle). */
uint32_t native32_gdi_host(uint32_t g) {
    int i = (int)(g & 0xFFFF);
    if (!g || !g_table || i >= GDI_ENTRIES || !g_host[i] || MEM16(ea(i) + 8) != (g >> 16)) return 0;
    return g_host[i];
}

uint8_t* native32_gdi_attr(uint32_t g) {
    return native32_gdi_host(g) ? (uint8_t*)(uintptr_t)MEM32(ea((int)(g & 0xFFFF)) + 12) : NULL;
}

#define HOST(x) native32_gdi_host((uint32_t)(uintptr_t)(x))
#define GUEST(x) native32_gdi_handle((uint32_t)(uintptr_t)(x))
#define AT32(a, o) (*(uint32_t*)((a) + (o)))

/* The guest handle for a host GDI object, entered in the table the first
 * time it is seen. */
uint32_t native32_gdi_handle(uint32_t h) {
    if (!h || !g_table) return h;
    int i = hfind(h);
    if (i) return (h & 0xFFFF0000u) | (uint32_t)i;
    i = g_nfree ? g_free[--g_nfree] : g_top < GDI_ENTRIES ? g_top++ : 0;
    if (!i) { fprintf(stderr, "[gdi] guest handle table full\n"); return 0; }
    uint32_t type = (h >> 16) & 0x1F, e = ea(i);
    uint8_t* attr = (uint8_t*)(uintptr_t)MEM32(e + 12);
    HDC d = (HDC)(uintptr_t)h;
    if (type == 1) {
        if (!attr) attr = (uint8_t*)calloc(1, ATTR_SIZE);
        else memset(attr, 0, ATTR_SIZE);
    }
    g_host[i] = h;
    hput(h, i);
    MEM32(e) = 0x80000000u | (uint32_t)i;                              /* "kernel object": nonzero */
    MEM32(e + 4) = GetCurrentProcessId() & ~3u;
    MEM16(e + 8) = (uint16_t)(h >> 16);
    MEM8(e + 10) = (uint8_t)type;
    /* a region's RGNATTR (gdi32 keeps a rectangular region's rectangle in
     * it client-side, CreateRectRgn / SetRectRgn) */
    if (type == 4 && !attr) attr = (uint8_t*)calloc(1, ATTR_SIZE);   /* (the slot may be a DC's next: its memset is ATTR_SIZE) */
    MEM32(e + 12) = type == 1 || type == 4 ? (uint32_t)(uintptr_t)attr : 0;
    if (type == 1) {                                                   /* a DC: its attributes, as it is */
        POINT p;
        GetCurrentPositionEx(d, &p);
        AT32(attr, 0x08) = GUEST(GetCurrentObject(d, OBJ_BRUSH));
        AT32(attr, 0x0C) = GUEST(GetCurrentObject(d, OBJ_PEN));
        AT32(attr, 0x10) = AT32(attr, 0x14) = GetBkColor(d);
        AT32(attr, 0x18) = AT32(attr, 0x1C) = GetTextColor(d);
        attr[0x38] = (uint8_t)GetROP2(d);
        attr[0x39] = (uint8_t)GetBkMode(d);
        AT32(attr, 0x3C) = (uint32_t)p.x;
        AT32(attr, 0x40) = (uint32_t)p.y;
        AT32(attr, 0x78) = AT32(attr, 0x7C) = GetTextAlign(d);
        AT32(attr, 0x90) = GUEST(GetCurrentObject(d, OBJ_FONT));
        GetBrushOrgEx(d, &p);
        AT32(attr, 0x1B0) = (uint32_t)p.x;
        AT32(attr, 0x1B4) = (uint32_t)p.y;
    }
    return (h & 0xFFFF0000u) | (uint32_t)i;
}

static void forget(uint32_t g) {
    int i = (int)(g & 0xFFFF);
    if (!native32_gdi_host(g)) return;
    hdel(g_host[i]);
    g_host[i] = 0, MEM32(ea(i)) = 0, MEM16(ea(i) + 8) = 0;
    g_free[g_nfree++] = i;
}

/* A guest DC as the host's, with its user-mode attributes applied. */
static HDC dc(uint32_t g) {
    HDC h = (HDC)(uintptr_t)HOST(g);
    uint8_t* a = native32_gdi_attr(g);
    if (h && a) {
        uint32_t br = HOST(AT32(a, 0x08)), pen = HOST(AT32(a, 0x0C)), font = HOST(AT32(a, 0x90));
        if (br) SelectObject(h, (HGDIOBJ)(uintptr_t)br);
        if (pen) SelectObject(h, (HGDIOBJ)(uintptr_t)pen);
        if (font) SelectObject(h, (HGDIOBJ)(uintptr_t)font);
        SetBkColor(h, AT32(a, 0x14));
        SetTextColor(h, AT32(a, 0x1C));
        SetROP2(h, a[0x38] ? a[0x38] : R2_COPYPEN);
        SetBkMode(h, a[0x39] ? a[0x39] : OPAQUE);
        SetTextAlign(h, AT32(a, 0x7C));
        MoveToEx(h, (int)AT32(a, 0x3C), (int)AT32(a, 0x40), NULL);
        SetBrushOrgEx(h, (int)AT32(a, 0x1B0), (int)AT32(a, 0x1B4), NULL);
    }
    return h;
}

static void dc_back(uint32_t g) {          /* after a draw that moves the pen */
    uint8_t* a = native32_gdi_attr(g);
    POINT p;
    if (a && GetCurrentPositionEx((HDC)(uintptr_t)HOST(g), &p)) AT32(a, 0x3C) = (uint32_t)p.x, AT32(a, 0x40) = (uint32_t)p.y;
}

/* ---- the TEB batch -------------------------------------------------------- */
static uint32_t s_delete(uint32_t* a);
static void batch(void) {
    uint32_t teb = MEM32(g_fs_base + 0x18), used = MEM32(teb + 0x1D4), hdc = MEM32(teb + 0x1D8);
    if (!used) return;
    for (uint32_t off = 0; off + 4 <= used && off < 0x4D8; ) {
        uint32_t e = teb + 0x1DC + off, len = MEM16(e), cmd = MEM16(e + 2);
        if (cmd == 0) {                                        /* PatBlt { x, y, cx, cy, brush, rop, ... } */
            HDC h = dc(hdc);
            uint32_t br = HOST(MEM32(e + 0x14));
            HGDIOBJ old = br ? SelectObject(h, (HGDIOBJ)(uintptr_t)br) : NULL;
            PatBlt(h, (int)MEM32(e + 4), (int)MEM32(e + 8), (int)MEM32(e + 0xC), (int)MEM32(e + 0x10), MEM32(e + 0x18));
            if (old) SelectObject(h, old);
        } else if (cmd == 1) {                                 /* PolyPatBlt { rop, mode, count, ?, colour, ?, ?, */
            HDC h = dc(hdc);                                   /* then count x { x, y, cx, cy, brush } at +0x24 } */
            for (uint32_t k = 0, n = MEM32(e + 0xC); k < n && 0x24 + 0x14 * (k + 1) <= len; k++) {
                uint32_t r = e + 0x24 + 0x14 * k, br = HOST(MEM32(r + 0x10));
                HGDIOBJ old = br ? SelectObject(h, (HGDIOBJ)(uintptr_t)br) : NULL;
                PatBlt(h, (int)MEM32(r), (int)MEM32(r + 4), (int)MEM32(r + 8), (int)MEM32(r + 0xC), MEM32(e + 4));
                if (old) SelectObject(h, old);
            }
        } else if (cmd == 8) {                                 /* DeleteObject { handle } (a region) */
            s_delete((uint32_t*)(uintptr_t)(e + 4));
        } else if (cmd == 4) {                                 /* SetBrushOrg { x, y } */
            SetBrushOrgEx((HDC)(uintptr_t)HOST(hdc), (int)MEM32(e + 4), (int)MEM32(e + 8), NULL);
        } else if (cmd == 6) {                                 /* select a font: DC_ATTR's is current */
            uint8_t* a = native32_gdi_attr(hdc);
            if (a) AT32(a, 0x90) = MEM32(e + 4);
        } else
            fprintf(stderr, "[gdi] batch command %u (%u bytes) dropped\n", cmd, len);
        if (len < 4) break;
        off += (len + 3) & ~3u;
    }
    MEM32(teb + 0x1D4) = 0;
    MEM32(teb + 0x1D8) = 0;
    MEM32(teb + 0xF70) = 0;
}

/* ---- the services (Windows 2000 argument lists) -------------------------- */
static uint32_t s_init(uint32_t* a) {
    (void)a;
    if (!g_table) {
        /* the handle table and the shared data after it (gdi32 reads +0x40094) */
        g_table = (uint8_t*)VirtualAlloc(NULL, 0x80000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        MEM32(native32_guest_peb + 0x94) = (uint32_t)(uintptr_t)g_table;
    }
    return 1;
}
static uint32_t s_zero(uint32_t* a) { (void)a; return 0; }
static uint32_t s_one(uint32_t* a) { (void)a; return 1; }
static uint32_t s_stock(uint32_t* a) { return GUEST(GetStockObject((int)a[0])); }
static uint32_t s_compat_dc(uint32_t* a) { return GUEST(CreateCompatibleDC((HDC)(uintptr_t)HOST(a[0]))); }
static uint32_t s_compat_bitmap(uint32_t* a) {
    return GUEST(CreateCompatibleBitmap((HDC)(uintptr_t)HOST(a[0]), a[1], a[2]));
}
static uint32_t s_pen(uint32_t* a) { return GUEST(CreatePen((int)a[0], (int)a[1], a[2])); }
static uint32_t s_brush(uint32_t* a) { return GUEST(CreateSolidBrush(a[0])); }
/* NtGdiGetRandomRgn(hdc, hrgn, which), NtGdiIntersectClipRect(hdc, l, t, r, b),
 * NtGdiExtSelectClipRgn(hdc, hrgn, mode) */
static uint32_t s_randomrgn(uint32_t* a) { return (uint32_t)GetRandomRgn((HDC)(uintptr_t)HOST(a[0]), (HRGN)(uintptr_t)HOST(a[1]), (INT)a[2]); }
static uint32_t s_intersectclip(uint32_t* a) {
    return (uint32_t)IntersectClipRect((HDC)(uintptr_t)HOST(a[0]), (int)a[1], (int)a[2], (int)a[3], (int)a[4]);
}
static uint32_t s_selectcliprgn(uint32_t* a) {
    return (uint32_t)ExtSelectClipRgn((HDC)(uintptr_t)HOST(a[0]), (HRGN)(uintptr_t)HOST(a[1]), (int)a[2]);
}
/* NtGdiCreateRectRgn(l, t, r, b) */
static uint32_t s_rectrgn(uint32_t* a) { return GUEST(CreateRectRgn((int)a[0], (int)a[1], (int)a[2], (int)a[3])); }
static uint32_t s_select(uint32_t* a) {
    return GUEST(SelectObject((HDC)(uintptr_t)HOST(a[0]), (HGDIOBJ)(uintptr_t)HOST(a[1])));
}
static uint32_t s_delete(uint32_t* a) {
    uint32_t h = HOST(a[0]);
    BOOL r = !h ? FALSE : ((h >> 16) & 0x1F) == 1 ? DeleteDC((HDC)(uintptr_t)h) : DeleteObject((HGDIOBJ)(uintptr_t)h);
    if (r) forget(a[0]);
    return r;
}
static uint32_t s_bitblt(uint32_t* a) {
    return BitBlt(dc(a[0]), a[1], a[2], a[3], a[4], a[5] ? dc(a[5]) : NULL, a[6], a[7], a[8]);
}
static uint32_t s_lineto(uint32_t* a) {
    BOOL r = LineTo(dc(a[0]), (int)a[1], (int)a[2]);
    dc_back(a[0]);
    return r;
}
static uint32_t s_moveto(uint32_t* a) {        /* NtGdiMoveTo(hdc, x, y, POINT* old) */
    BOOL r = MoveToEx(dc(a[0]), (int)a[1], (int)a[2], (POINT*)(uintptr_t)a[3]);
    dc_back(a[0]);
    return r;
}
static uint32_t s_setpixel(uint32_t* a) { return SetPixel(dc(a[0]), a[1], a[2], a[3]); }
static uint32_t s_devcaps(uint32_t* a) { return GetDeviceCaps((HDC)(uintptr_t)HOST(a[0]), (int)a[1]); }
static uint32_t s_setlayout(uint32_t* a) { return SetLayout((HDC)(uintptr_t)HOST(a[0]), a[2]); }
/* NtGdiSetDIBitsToDeviceInternal(hdc, xDst, yDst, cx, cy, xSrc, ySrc, iStartScan,
 * cNumScan, pInitBits, pbmi, iUsage, cjMaxBits, cjMaxInfo, bTransform, hcmXform) */
static uint32_t s_setdibits(uint32_t* a) {
    return SetDIBitsToDevice(dc(a[0]), a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8],
                             (void*)(uintptr_t)a[9], (BITMAPINFO*)(uintptr_t)a[10], a[11]);
}
/* NtGdiCreateDIBitmapInternal(hdc, cx, cy, fInit, pjInit, pbmi, iUsage,
 * cjMaxInitInfo, cjMaxBits, fl, hcmXform): fInit 4 CBM_INIT (bits given),
 * 2 a DIB-format bitmap (cards.dll's, through lifted LoadBitmap); the
 * host's CreateDIBitmap of the same header. ponytail: fInit 2 becomes a
 * device-compatible bitmap, which is what the host gives LoadBitmap too */
static uint32_t s_dibitmap(uint32_t* a) {
    BITMAPINFO* bi = (BITMAPINFO*)(uintptr_t)a[5];
    HDC h = (HDC)(uintptr_t)HOST(a[0]);
    if (!bi) return GUEST(CreateCompatibleBitmap(h ? h : GetDC(NULL), (int)a[1], (int)a[2]));
    return GUEST(CreateDIBitmap(h ? h : GetDC(NULL), &bi->bmiHeader, a[3] & CBM_INIT, (void*)(uintptr_t)a[4], bi, a[6]));
}
/* NtGdiGetRegionData(hrgn, count, RGNDATA*). NtGdiGetDeviceWidth stays
 * unanswered (0): answered with HORZRES, gdisol looped in gdi32 */
static uint32_t s_rgndata(uint32_t* a) { return GetRegionData((HRGN)(uintptr_t)HOST(a[0]), a[1], (RGNDATA*)(uintptr_t)a[2]); }
/* NtGdiCreateBitmap(cx, cy, planes, bpp, bits) */
static uint32_t s_bitmap(uint32_t* a) {
    return GUEST(CreateBitmap((int)a[0], (int)a[1], a[2], a[3], (void*)(uintptr_t)a[4]));
}
/* NtGdiExtGetObjectW(h, count, buffer) */
static uint32_t s_getobject(uint32_t* a) {
    return GetObjectW((HGDIOBJ)(uintptr_t)HOST(a[0]), (int)a[1], (void*)(uintptr_t)a[2]);
}
/* NtGdiGetTextMetricsW(hdc, TMW_INTERNAL*, cj): TEXTMETRICW, then zeros */
static uint32_t s_textmetrics(uint32_t* a) {
    TEXTMETRICW tm;
    if (!GetTextMetricsW(dc(a[0]), &tm)) return 0;
    memset((void*)(uintptr_t)a[1], 0, a[2]);
    memcpy((void*)(uintptr_t)a[1], &tm, a[2] < sizeof tm ? a[2] : sizeof tm);
    return 1;
}
/* NtGdiOpenDCW(device, devmode, logaddr, iType, hspool, driverinfo, umpd):
 * a NULL device is the display; iType 2 an information context */
static uint32_t s_opendc(uint32_t* a) {
    const wchar_t* dev = a[0] ? (const wchar_t*)(uintptr_t)MEM32(a[0] + 4) : L"DISPLAY";
    HDC h = a[3] == 2 ? CreateICW(dev, NULL, NULL, (DEVMODEW*)(uintptr_t)a[1])
                      : CreateDCW(dev, NULL, NULL, (DEVMODEW*)(uintptr_t)a[1]);
    return GUEST(h);
}
/* NtGdiHfontCreate(ENUMLOGFONTEXDVW*, cj, lft, fl, pvCliData): its LOGFONTW leads */
static uint32_t s_font(uint32_t* a) { return GUEST(CreateFontIndirectW((LOGFONTW*)(uintptr_t)a[0])); }
/* NtGdiExtTextOutW(hdc, x, y, flOpts, prcl, pwsz, cwc, pdx, dwCodePage) */
static uint32_t s_textout(uint32_t* a) {
    return ExtTextOutW(dc(a[0]), (int)a[1], (int)a[2], a[3], (RECT*)(uintptr_t)a[4],
                       (const wchar_t*)(uintptr_t)a[5], a[6], (const INT*)(uintptr_t)a[7]);
}
static uint32_t s_flushbatch(uint32_t* a) { (void)a; batch(); return 0; }
/* NtGdiGetTextCharsetInfo(hdc, FONTSIGNATURE*, flags) */
static uint32_t s_charset(uint32_t* a) { return GetTextCharsetInfo(dc(a[0]), (FONTSIGNATURE*)(uintptr_t)a[1], a[2]); }
/* NtGdiGetDCPoint(hdc, iPoint, POINTL*): 6 the DC's origin (GetDCOrgEx); the
 * other points gdi32 reads from DC_ATTR itself */
static uint32_t s_dcpoint(uint32_t* a) {
    if (a[1] == 6) return GetDCOrgEx((HDC)(uintptr_t)HOST(a[0]), (POINT*)(uintptr_t)a[2]);
    fprintf(stderr, "[gdi] NtGdiGetDCPoint %u not answered\n", a[1]);
    return 0;
}
static uint32_t s_getpixel(uint32_t* a) { return GetPixel(dc(a[0]), (int)a[1], (int)a[2]); }
/* NtGdiGetTextFaceW(hdc, cChar, pszOut, bAliasName) */
static uint32_t s_textface(uint32_t* a) {
    return GetTextFaceW(dc(a[0]), (int)a[1], (wchar_t*)(uintptr_t)a[2]);
}
/* NtGdiEnumFontOpen(hdc, iType, fl, cwchMax, pwszFace, lfCharSet, *pulCount) /
 * EnumFontChunk / EnumFontClose. ponytail: an enumeration that finds no
 * fonts; ENUMFONTDATAW's Windows 2000 layout is not filled in yet. */
static uint32_t s_enumopen(uint32_t* a) { if (a[6]) MEM32(a[6]) = 0; return 1; }
static uint32_t s_enumchunk(uint32_t* a) { if (a[3]) MEM32(a[3]) = 0; return 0; }
/* NtGdiGetTextExtent(hdc, pwsz, cwc, SIZE*, flOpts) */
static uint32_t s_textextent(uint32_t* a) {
    return GetTextExtentPoint32W(dc(a[0]), (const wchar_t*)(uintptr_t)a[1], (int)a[2], (SIZE*)(uintptr_t)a[3]);
}

/* ---- host user32, translated where GDI handles cross ---------------------- */
static HDC WINAPI hk_BeginPaint(HWND w, PAINTSTRUCT* ps) {
    HDC h = BeginPaint(w, ps);
    if (ps) ps->hdc = (HDC)(uintptr_t)GUEST(ps->hdc);
    return (HDC)(uintptr_t)GUEST(h);
}
static BOOL WINAPI hk_EndPaint(HWND w, PAINTSTRUCT* ps) {
    uint32_t g = ps ? (uint32_t)(uintptr_t)ps->hdc : 0;
    if (ps) ps->hdc = (HDC)(uintptr_t)HOST(g);
    BOOL r = EndPaint(w, ps);
    if (ps) forget(g), ps->hdc = (HDC)(uintptr_t)g;
    return r;
}
static HDC WINAPI hk_GetDC(HWND w) { return (HDC)(uintptr_t)GUEST(GetDC(w)); }
static HDC WINAPI hk_GetWindowDC(HWND w) { return (HDC)(uintptr_t)GUEST(GetWindowDC(w)); }
static HDC WINAPI hk_GetDCEx(HWND w, HRGN r, DWORD f) { return (HDC)(uintptr_t)GUEST(GetDCEx(w, (HRGN)(uintptr_t)HOST(r), f)); }
static int WINAPI hk_ReleaseDC(HWND w, HDC g) {
    int r = ReleaseDC(w, (HDC)(uintptr_t)HOST(g));
    forget((uint32_t)(uintptr_t)g);
    return r;
}
/* A class's background brush (winmine's GetStockObject(LTGRAY_BRUSH)); a
 * COLOR_* + 1 value is no handle and passes. */
#define BRUSH_IN(b) ((uint32_t)(uintptr_t)(b) > 0x40 && HOST(b) ? (HBRUSH)(uintptr_t)HOST(b) : (b))
static ATOM WINAPI hk_RegisterClassW(const WNDCLASSW* c) {
    WNDCLASSW w = *c;
    w.hbrBackground = BRUSH_IN(w.hbrBackground);
    return RegisterClassW(&w);
}
static ATOM WINAPI hk_RegisterClassA(const WNDCLASSA* c) {
    WNDCLASSA w = *c;
    w.hbrBackground = BRUSH_IN(w.hbrBackground);
    return RegisterClassA(&w);
}
static ATOM WINAPI hk_RegisterClassExW(const WNDCLASSEXW* c) {
    WNDCLASSEXW w = *c;
    w.hbrBackground = BRUSH_IN(w.hbrBackground);
    return RegisterClassExW(&w);
}
static ATOM WINAPI hk_RegisterClassExA(const WNDCLASSEXA* c) {
    WNDCLASSEXA w = *c;
    w.hbrBackground = BRUSH_IN(w.hbrBackground);
    return RegisterClassExA(&w);
}
static HBITMAP WINAPI hk_LoadBitmapW(HINSTANCE i, LPCWSTR n) { return (HBITMAP)(uintptr_t)GUEST(LoadBitmapW(i, n)); }
static HBITMAP WINAPI hk_LoadBitmapA(HINSTANCE i, LPCSTR n) { return (HBITMAP)(uintptr_t)GUEST(LoadBitmapA(i, n)); }
static HANDLE WINAPI hk_LoadImageW(HINSTANCE i, LPCWSTR n, UINT t, int cx, int cy, UINT f) {
    HANDLE h = LoadImageW(i, n, t, cx, cy, f);
    return t == IMAGE_BITMAP ? (HANDLE)(uintptr_t)GUEST(h) : h;
}
static HANDLE WINAPI hk_LoadImageA(HINSTANCE i, LPCSTR n, UINT t, int cx, int cy, UINT f) {
    HANDLE h = LoadImageA(i, n, t, cx, cy, f);
    return t == IMAGE_BITMAP ? (HANDLE)(uintptr_t)GUEST(h) : h;
}

/* ---- window messages that carry GDI handles into the guest -------------
 * Host user32 hands a window procedure its own HDCs (WM_ERASEBKGND,
 * WM_CTLCOLOR*, WM_DRAWITEM: calc's owner-drawn buttons) and takes a brush
 * back from WM_CTLCOLOR*. Each such DC is entered afresh (the host reuses
 * them, with new state); the brush goes back as the host's. */
static int is_dc_msg(uint32_t m) {
    return m == WM_ERASEBKGND || m == WM_ICONERASEBKGND || m == WM_PRINT || m == WM_PRINTCLIENT ||
           m == WM_PAINT || (m >= WM_CTLCOLORMSGBOX && m <= WM_CTLCOLORSTATIC);
}
static uint32_t fresh(uint32_t h) {
    int i = hfind(h);
    if (i) forget((h & 0xFFFF0000u) | (uint32_t)i);
    return native32_gdi_handle(h);
}
static void cb_in(uint32_t* a) {
    if (!g_table || !IsWindow((HWND)(uintptr_t)a[0])) return;
    /* (a handle that is already the guest's came through a guest -> host ->
     * guest CallWindowProc and stays) */
    if (is_dc_msg(a[1]) && a[2] && ((a[2] >> 16) & 0x1F) == 1 && !HOST(a[2])) a[2] = fresh(a[2]);
    else if (a[1] == WM_DRAWITEM && a[3]) {
        DRAWITEMSTRUCT* d = (DRAWITEMSTRUCT*)(uintptr_t)a[3];
        if (!HOST(d->hDC)) d->hDC = (HDC)(uintptr_t)fresh((uint32_t)(uintptr_t)d->hDC);
    }
}
static void cb_out(uint32_t* a, uint32_t* eax) {
    if (!g_table || !IsWindow((HWND)(uintptr_t)a[0])) return;
    if (a[1] >= WM_CTLCOLORMSGBOX && a[1] <= WM_CTLCOLORSTATIC && HOST(*eax)) *eax = HOST(*eax);
    else if (a[1] == WM_DRAWITEM && a[3]) {
        DRAWITEMSTRUCT* d = (DRAWITEMSTRUCT*)(uintptr_t)a[3];
        if (HOST(d->hDC)) d->hDC = (HDC)(uintptr_t)HOST(d->hDC);
    }
}

/* ... and back: a guest procedure passes the message on to host user32's
 * default processing with the guest's handle. */
static WPARAM wp_out(UINT m, WPARAM w) {
    return is_dc_msg(m) && HOST(w) ? (WPARAM)HOST(w) : w;
}
static LPARAM lp_out(UINT m, LPARAM l, HDC* saved) {
    if (m == WM_DRAWITEM && l && HOST(((DRAWITEMSTRUCT*)l)->hDC)) {
        *saved = ((DRAWITEMSTRUCT*)l)->hDC;
        ((DRAWITEMSTRUCT*)l)->hDC = (HDC)(uintptr_t)HOST(*saved);
    }
    return l;
}
static void lp_back(UINT m, LPARAM l, HDC saved) { if (m == WM_DRAWITEM && l && saved) ((DRAWITEMSTRUCT*)l)->hDC = saved; }
#define PASS_ON(call) do { HDC sv = NULL; LRESULT r; l = lp_out(m, l, &sv); r = call; lp_back(m, l, sv); return r; } while (0)
static LRESULT WINAPI hk_DefWindowProcW(HWND h, UINT m, WPARAM w, LPARAM l) { PASS_ON(DefWindowProcW(h, m, wp_out(m, w), l)); }
static LRESULT WINAPI hk_DefWindowProcA(HWND h, UINT m, WPARAM w, LPARAM l) { PASS_ON(DefWindowProcA(h, m, wp_out(m, w), l)); }
static LRESULT WINAPI hk_DefDlgProcW(HWND h, UINT m, WPARAM w, LPARAM l) { PASS_ON(DefDlgProcW(h, m, wp_out(m, w), l)); }
static LRESULT WINAPI hk_DefDlgProcA(HWND h, UINT m, WPARAM w, LPARAM l) { PASS_ON(DefDlgProcA(h, m, wp_out(m, w), l)); }
static LRESULT WINAPI hk_CallWindowProcW(WNDPROC p, HWND h, UINT m, WPARAM w, LPARAM l) {
    PASS_ON(CallWindowProcW(p, h, m, wp_out(m, w), l));
}
static LRESULT WINAPI hk_CallWindowProcA(WNDPROC p, HWND h, UINT m, WPARAM w, LPARAM l) {
    PASS_ON(CallWindowProcA(p, h, m, wp_out(m, w), l));
}

/* ---- host user32's own drawing, on a guest DC -------------------------------
 * calc draws its owner-drawn buttons with DrawText and DrawEdge on the DC it
 * was given: the guest's handle, with the colours and font the guest's gdi32
 * left in DC_ATTR. Each of these takes the host DC with those applied. */
static HDC dc_out(HDC g) { return HOST(g) ? dc((uint32_t)(uintptr_t)g) : g; }
static HGDIOBJ obj_out(HGDIOBJ g) { return HOST(g) ? (HGDIOBJ)(uintptr_t)HOST(g) : g; }
static int WINAPI hk_DrawTextW(HDC d, LPCWSTR t, int n, LPRECT r, UINT f) { return DrawTextW(dc_out(d), t, n, r, f); }
static int WINAPI hk_DrawTextA(HDC d, LPCSTR t, int n, LPRECT r, UINT f) { return DrawTextA(dc_out(d), t, n, r, f); }
static int WINAPI hk_DrawTextExW(HDC d, LPWSTR t, int n, LPRECT r, UINT f, LPDRAWTEXTPARAMS p) {
    return DrawTextExW(dc_out(d), t, n, r, f, p);
}
static BOOL WINAPI hk_DrawEdge(HDC d, LPRECT r, UINT e, UINT f) { return DrawEdge(dc_out(d), r, e, f); }
static int WINAPI hk_FillRect(HDC d, const RECT* r, HBRUSH b) { return FillRect(dc_out(d), r, (HBRUSH)obj_out(b)); }
static int WINAPI hk_FrameRect(HDC d, const RECT* r, HBRUSH b) { return FrameRect(dc_out(d), r, (HBRUSH)obj_out(b)); }
static BOOL WINAPI hk_InvertRect(HDC d, const RECT* r) { return InvertRect(dc_out(d), r); }
static BOOL WINAPI hk_DrawFocusRect(HDC d, const RECT* r) { return DrawFocusRect(dc_out(d), r); }
static BOOL WINAPI hk_DrawFrameControl(HDC d, LPRECT r, UINT t, UINT s) { return DrawFrameControl(dc_out(d), r, t, s); }
static BOOL WINAPI hk_DrawIconEx(HDC d, int x, int y, HICON i, int cx, int cy, UINT st, HBRUSH b, UINT f) {
    return DrawIconEx(dc_out(d), x, y, i, cx, cy, st, (HBRUSH)obj_out(b), f);
}
static HBRUSH WINAPI hk_GetSysColorBrush(int i) { return (HBRUSH)(uintptr_t)GUEST(GetSysColorBrush(i)); }
/* An edit control's buffer by handle (EM_SETHANDLE, Windows 2000 notepad's
 * file text): an HLOCAL of the lifted kernel32's heap, which the host's edit
 * control cannot use. Its text goes over instead. ponytail: EM_GETHANDLE
 * still answers the host's handle (notepad's save path reads through it). */
static uint32_t guest_call(const char* fn, int n, uint32_t* a) {
    uint32_t va = native32_export(native32_module("kernel32.dll"), fn);
    if (!va) return 0;
    mach_enter();
    uint32_t sp = g_esp;
    native32_call_guest(va, n, a);
    uint32_t r = g_eax;
    g_esp = sp;
    mach_leave();
    return r;
}

/* A font handed to a control, or asked of one; an edit buffer by handle */
static LRESULT font_msg(LRESULT (WINAPI* send)(HWND, UINT, WPARAM, LPARAM), HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == EM_SETHANDLE && w) {
        uint32_t a[1] = { (uint32_t)w };
        const wchar_t* t = (const wchar_t*)(uintptr_t)guest_call("LocalLock", 1, a);
        LRESULT r = t ? SendMessageW(h, WM_SETTEXT, 0, (LPARAM)t) : 0;
        if (t) guest_call("LocalUnlock", 1, a);
        return r;
    }
    if (m == WM_SETFONT) w = (WPARAM)obj_out((HGDIOBJ)w);
    LRESULT r = send(h, m, w, l);
    return m == WM_GETFONT && r ? (LRESULT)GUEST(r) : r;
}
static LRESULT WINAPI hk_SendMessageW(HWND h, UINT m, WPARAM w, LPARAM l) { return font_msg(SendMessageW, h, m, w, l); }
static LRESULT WINAPI hk_SendMessageA(HWND h, UINT m, WPARAM w, LPARAM l) { return font_msg(SendMessageA, h, m, w, l); }
static LRESULT WINAPI hk_SendDlgItemMessageW(HWND h, int id, UINT m, WPARAM w, LPARAM l) {
    return font_msg(SendMessageW, GetDlgItem(h, id), m, w, l);
}

void native32_gdi_install(void) {
    static const struct { const char* name; void* fn; } draw[] = {
        { "DrawTextW", hk_DrawTextW }, { "DrawTextA", hk_DrawTextA }, { "DrawTextExW", hk_DrawTextExW },
        { "DrawEdge", hk_DrawEdge }, { "FillRect", hk_FillRect }, { "FrameRect", hk_FrameRect },
        { "InvertRect", hk_InvertRect }, { "DrawFocusRect", hk_DrawFocusRect },
        { "DrawFrameControl", hk_DrawFrameControl }, { "DrawIconEx", hk_DrawIconEx },
        { "GetSysColorBrush", hk_GetSysColorBrush }, { "SendMessageW", hk_SendMessageW },
        { "SendMessageA", hk_SendMessageA }, { "SendDlgItemMessageW", hk_SendDlgItemMessageW },
    };
    for (int i = 0; i < (int)(sizeof draw / sizeof draw[0]); i++) native32_nt_proxy_hook(draw[i].name, draw[i].fn);
    native32_nt_proxy_hook("DefWindowProcW", (void*)hk_DefWindowProcW);
    native32_nt_proxy_hook("DefWindowProcA", (void*)hk_DefWindowProcA);
    native32_nt_proxy_hook("DefDlgProcW", (void*)hk_DefDlgProcW);
    native32_nt_proxy_hook("DefDlgProcA", (void*)hk_DefDlgProcA);
    native32_nt_proxy_hook("CallWindowProcW", (void*)hk_CallWindowProcW);
    native32_nt_proxy_hook("CallWindowProcA", (void*)hk_CallWindowProcA);
    native32_cb_in = cb_in;
    native32_cb_out = cb_out;
    static const struct { const char* name; native32_syscall_fn fn; } svc[] = {
        { "NtGdiInit", s_init }, { "NtGdiQueryFontAssocInfo", s_zero }, { "NtGdiGetStockObject", s_stock },
        { "NtGdiCreateCompatibleDC", s_compat_dc }, { "NtGdiCreateCompatibleBitmap", s_compat_bitmap },
        { "NtGdiCreatePen", s_pen }, { "NtGdiCreateRectRgn", s_rectrgn }, { "NtGdiCreateDIBitmapInternal", s_dibitmap }, { "NtGdiCreateBitmap", s_bitmap },
        { "NtGdiGetRegionData", s_rgndata }, { "NtGdiGetDCforBitmap", s_zero },   /* (the DC a bitmap is selected into: none we know of) */
        { "NtGdiGetRandomRgn", s_randomrgn }, { "NtGdiIntersectClipRect", s_intersectclip }, { "NtGdiExtSelectClipRgn", s_selectcliprgn }, { "NtGdiCreateSolidBrush", s_brush },
        { "NtGdiSelectBitmap", s_select }, { "NtGdiSelectBrush", s_select }, { "NtGdiSelectPen", s_select },
        { "NtGdiSelectFont", s_select }, { "NtGdiDeleteObjectApp", s_delete }, { "NtGdiBitBlt", s_bitblt },
        { "NtGdiLineTo", s_lineto }, { "NtGdiMoveTo", s_moveto }, { "NtGdiSetPixel", s_setpixel },
        { "NtGdiGetDeviceCaps", s_devcaps }, { "NtGdiSetLayout", s_setlayout },
        { "NtGdiSetDIBitsToDeviceInternal", s_setdibits }, { "NtGdiFlush", s_one },
        { "NtGdiExtGetObjectW", s_getobject }, { "NtGdiComputeXformCoefficients", s_one },
        { "NtGdiGetTextMetricsW", s_textmetrics }, { "NtGdiOpenDCW", s_opendc },
        { "NtGdiHfontCreate", s_font }, { "NtGdiExtTextOutW", s_textout },
        { "NtGdiFlushUserBatch", s_flushbatch }, { "NtGdiGetTextExtent", s_textextent }, { "NtGdiGetTextCharsetInfo", s_charset },
        { "NtGdiGetDCPoint", s_dcpoint }, { "NtGdiGetTextFaceW", s_textface },
        { "NtGdiEnumFontOpen", s_enumopen }, { "NtGdiEnumFontChunk", s_enumchunk }, { "NtGdiEnumFontClose", s_one }, { "NtGdiGetPixel", s_getpixel },
    };
    static const struct { const char* name; void* fn; } hooks[] = {
        { "BeginPaint", hk_BeginPaint }, { "EndPaint", hk_EndPaint }, { "GetDC", hk_GetDC },
        { "GetWindowDC", hk_GetWindowDC }, { "GetDCEx", hk_GetDCEx }, { "ReleaseDC", hk_ReleaseDC },
        { "RegisterClassW", hk_RegisterClassW }, { "RegisterClassA", hk_RegisterClassA },
        { "RegisterClassExW", hk_RegisterClassExW }, { "RegisterClassExA", hk_RegisterClassExA },
        { "LoadBitmapW", hk_LoadBitmapW }, { "LoadBitmapA", hk_LoadBitmapA },
        { "LoadImageW", hk_LoadImageW }, { "LoadImageA", hk_LoadImageA },
    };
    for (int i = 0; i < (int)(sizeof svc / sizeof svc[0]); i++) native32_nt_win32k_override(svc[i].name, svc[i].fn);
    for (int i = 0; i < (int)(sizeof hooks / sizeof hooks[0]); i++) native32_nt_proxy_hook(hooks[i].name, hooks[i].fn);
    native32_win32k_pre = batch;
}

/* Windows 2000's gdi32 has no entry point: user32's DllMain calls its
 * GdiDllInitialize. With the host's user32 nobody would; call after the
 * guest's loader is done (native32_nt_boot). 0 if gdi32 has no such export. */
int native32_gdi_start(uint32_t gdi32) {
    uint32_t init = native32_export(gdi32, "GdiDllInitialize");
    if (!init) return 0;
    uint32_t a[3] = { gdi32, DLL_PROCESS_ATTACH, 0 };
    mach_enter();
    uint32_t sp = g_esp;
    native32_call_guest(init, 3, a);
    g_esp = sp;
    mach_leave();
    return 1;
}
