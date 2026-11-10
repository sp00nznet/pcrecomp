/*
 * codepage: a guest's ANSI code page, whatever the system's is.
 *
 * A Win9x program written for one locale (a Japanese game: Shift-JIS, code
 * page 932) passes its text to the A functions and to MultiByteToWideChar
 * with CP_ACP. On a machine whose system locale is another one (1252), every
 * byte of that text is read in the wrong code page: file names, the script
 * converted to UTF-16, the font's face name, every string drawn. The guest's
 * strings are not wrong; Windows' idea of the ANSI code page is.
 *
 * native32_set_codepage(932) before native32_bind changes it for the guest
 * alone: the imports below bind to the replacements here instead of the real
 * functions. Each one is an ordinary WINAPI function with the real one's
 * signature (the bridge calls it like any other native function), which reads
 * the guest's strings in that code page, calls the W function, and converts
 * what comes back. GetProcAddress for one of these names returns the
 * replacement too. The host process keeps the system's code page.
 *
 * ponytail: the functions a Japanese visual novel's engine (VCL and a script
 * interpreter) and the Win9x titles around it reached; a guest calling another
 * A function with non-ASCII text still gets the system's code page. Add each
 * as a title needs it. Window messages (WM_CHAR, WM_SETTEXT to an A window)
 * are not converted.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

static UINT g_cp;   /* 0: off (the system's code page) */

void native32_set_codepage(unsigned cp) { g_cp = cp; }

static UINT cp_of(UINT cp) {
    return cp == CP_ACP || cp == CP_OEMCP || cp == CP_THREAD_ACP || cp == CP_MACCP ? g_cp : cp;
}

/* A guest string as UTF-16 in buf (n wide chars), or NULL for NULL / an atom. */
static WCHAR* wide(const char* s, WCHAR* buf, int n) {
    if (!s || (uintptr_t)s < 0x10000) return (WCHAR*)s;
    if (!MultiByteToWideChar(g_cp, 0, s, -1, buf, n)) buf[n - 1] = 0;
    return buf;
}

/* ---- kernel32 ---- */
static UINT WINAPI cp_GetACP(void) { return g_cp; }
static UINT WINAPI cp_GetOEMCP(void) { return g_cp; }
static BOOL WINAPI cp_GetCPInfo(UINT cp, LPCPINFO info) { return GetCPInfo(cp_of(cp), info); }
static BOOL WINAPI cp_IsDBCSLeadByte(BYTE c) { return IsDBCSLeadByteEx(g_cp, c); }

static int WINAPI cp_MultiByteToWideChar(UINT cp, DWORD fl, LPCSTR s, int n, LPWSTR w, int nw) {
    return MultiByteToWideChar(cp_of(cp), fl, s, n, w, nw);
}

static int WINAPI cp_WideCharToMultiByte(UINT cp, DWORD fl, LPCWSTR w, int nw, LPSTR s, int n,
                                         LPCSTR def, LPBOOL used) {
    cp = cp_of(cp);
    /* UTF-7/8 take no default char; the guest asked for the ANSI page, which does. */
    return WideCharToMultiByte(cp, fl, w, nw, s, n, def, used);
}

static int WINAPI cp_CompareStringA(LCID lc, DWORD fl, LPCSTR a, int na, LPCSTR b, int nb) {
    WCHAR wa[1024], wb[1024];
    int la = MultiByteToWideChar(g_cp, 0, a, na, wa, 1024);
    int lb = MultiByteToWideChar(g_cp, 0, b, nb, wb, 1024);
    if ((na && !la) || (nb && !lb)) return CompareStringA(lc, fl, a, na, b, nb);   /* too long */
    if (na == -1) la--;
    if (nb == -1) lb--;
    return CompareStringW(lc, fl, wa, la, wb, lb);
}

static HANDLE WINAPI cp_CreateFileA(LPCSTR p, DWORD acc, DWORD sh, LPSECURITY_ATTRIBUTES sa,
                                    DWORD disp, DWORD fl, HANDLE tmpl) {
    WCHAR w[MAX_PATH * 2];
    return CreateFileW(wide(p, w, MAX_PATH * 2), acc, sh, sa, disp, fl, tmpl);
}

static DWORD WINAPI cp_GetFileAttributesA(LPCSTR p) {
    WCHAR w[MAX_PATH * 2];
    return GetFileAttributesW(wide(p, w, MAX_PATH * 2));
}

static BOOL WINAPI cp_DeleteFileA(LPCSTR p) {
    WCHAR w[MAX_PATH * 2];
    return DeleteFileW(wide(p, w, MAX_PATH * 2));
}

static BOOL WINAPI cp_CreateDirectoryA(LPCSTR p, LPSECURITY_ATTRIBUTES sa) {
    WCHAR w[MAX_PATH * 2];
    return CreateDirectoryW(wide(p, w, MAX_PATH * 2), sa);
}

static void find_a(const WIN32_FIND_DATAW* w, WIN32_FIND_DATAA* a) {
    memcpy(a, w, offsetof(WIN32_FIND_DATAA, cFileName));
    WideCharToMultiByte(g_cp, 0, w->cFileName, -1, a->cFileName, MAX_PATH, NULL, NULL);
    WideCharToMultiByte(g_cp, 0, w->cAlternateFileName, -1, a->cAlternateFileName, 14, NULL, NULL);
}

static HANDLE WINAPI cp_FindFirstFileA(LPCSTR p, LPWIN32_FIND_DATAA a) {
    WCHAR w[MAX_PATH * 2];
    WIN32_FIND_DATAW fw;
    HANDLE h = FindFirstFileW(wide(p, w, MAX_PATH * 2), &fw);
    if (h != INVALID_HANDLE_VALUE) find_a(&fw, a);
    return h;
}

static BOOL WINAPI cp_FindNextFileA(HANDLE h, LPWIN32_FIND_DATAA a) {
    WIN32_FIND_DATAW fw;
    BOOL ok = FindNextFileW(h, &fw);
    if (ok) find_a(&fw, a);
    return ok;
}

/* ---- user32 ---- */
static LPSTR WINAPI cp_CharNextA(LPCSTR s) { return CharNextExA((WORD)g_cp, s, 0); }
static LPSTR WINAPI cp_CharPrevA(LPCSTR start, LPCSTR s) { return CharPrevExA((WORD)g_cp, start, s, 0); }

static BOOL WINAPI cp_SetWindowTextA(HWND h, LPCSTR s) {
    WCHAR w[1024];
    return SetWindowTextW(h, wide(s, w, 1024));
}

static int WINAPI cp_MessageBoxA(HWND h, LPCSTR text, LPCSTR cap, UINT type) {
    WCHAR wt[4096], wc[512];
    return MessageBoxW(h, wide(text, wt, 4096), wide(cap, wc, 512), type);
}

static int WINAPI cp_DrawTextA(HDC dc, LPCSTR s, int n, LPRECT r, UINT fmt) {
    WCHAR w[4096];
    int len = MultiByteToWideChar(g_cp, 0, s, n, w, 4096);
    if (n && !len) return DrawTextA(dc, s, n, r, fmt);
    return DrawTextW(dc, w, n == -1 ? -1 : len, r, fmt & ~DT_MODIFYSTRING);
}

/* ---- gdi32 ---- */
static void logfont_w(const LOGFONTA* a, LOGFONTW* w) {
    memcpy(w, a, offsetof(LOGFONTA, lfFaceName));
    if (!MultiByteToWideChar(g_cp, 0, a->lfFaceName, -1, w->lfFaceName, LF_FACESIZE))
        w->lfFaceName[LF_FACESIZE - 1] = 0;
}

static void logfont_a(const LOGFONTW* w, LOGFONTA* a) {
    memcpy(a, w, offsetof(LOGFONTA, lfFaceName));
    WideCharToMultiByte(g_cp, 0, w->lfFaceName, -1, a->lfFaceName, LF_FACESIZE, NULL, NULL);
}

static HFONT WINAPI cp_CreateFontIndirectA(const LOGFONTA* a) {
    LOGFONTW w;
    if (!a) return NULL;
    logfont_w(a, &w);
    return CreateFontIndirectW(&w);
}

static HFONT WINAPI cp_CreateFontA(int h, int wd, int esc, int ori, int wt, DWORD it, DWORD ul,
                                   DWORD so, DWORD cs, DWORD op, DWORD cp, DWORD q, DWORD pf,
                                   LPCSTR face) {
    WCHAR w[LF_FACESIZE];
    return CreateFontW(h, wd, esc, ori, wt, it, ul, so, cs, op, cp, q, pf, wide(face, w, LF_FACESIZE));
}

static int WINAPI cp_GetObjectA(HANDLE h, int n, LPVOID out) {
    if (out && n >= (int)sizeof(LOGFONTA) && GetObjectType(h) == OBJ_FONT) {
        LOGFONTW w;
        if (!GetObjectW(h, sizeof w, &w)) return 0;
        logfont_a(&w, (LOGFONTA*)out);
        return sizeof(LOGFONTA);
    }
    return GetObjectA(h, n, out);
}

static BOOL WINAPI cp_TextOutA(HDC dc, int x, int y, LPCSTR s, int n) {
    WCHAR w[4096];
    int len = MultiByteToWideChar(g_cp, 0, s, n, w, 4096);
    return n && !len ? TextOutA(dc, x, y, s, n) : TextOutW(dc, x, y, w, len);
}

/* lpDx has one width per byte; a DBCS pair's two entries become one. */
static BOOL WINAPI cp_ExtTextOutA(HDC dc, int x, int y, UINT opt, const RECT* r, LPCSTR s, UINT n,
                                  const INT* dx) {
    WCHAR w[4096];
    INT wdx[4096];
    int len = s && n ? MultiByteToWideChar(g_cp, 0, s, (int)n, w, 4096) : 0;
    if (n && !len) return ExtTextOutA(dc, x, y, opt, r, s, n, dx);
    if (dx) {
        for (UINT i = 0, k = 0; i < n && k < (UINT)len; k++) {
            int lead = IsDBCSLeadByteEx(g_cp, (BYTE)s[i]) && i + 1 < n;
            wdx[k] = dx[i] + (lead ? dx[i + 1] : 0);
            i += 1 + lead;
        }
    }
    return ExtTextOutW(dc, x, y, opt & ~ETO_GLYPH_INDEX, r, w, len, dx ? wdx : NULL);
}

static BOOL WINAPI cp_GetTextExtentPoint32A(HDC dc, LPCSTR s, int n, LPSIZE sz) {
    WCHAR w[4096];
    int len = MultiByteToWideChar(g_cp, 0, s, n, w, 4096);
    return n && !len ? GetTextExtentPoint32A(dc, s, n, sz) : GetTextExtentPoint32W(dc, w, len, sz);
}

static BOOL WINAPI cp_GetTextExtentPointA(HDC dc, LPCSTR s, int n, LPSIZE sz) {
    return cp_GetTextExtentPoint32A(dc, s, n, sz);
}

/* uChar of the A function is a DBCS code (lead byte high) or a single byte. */
static DWORD WINAPI cp_GetGlyphOutlineA(HDC dc, UINT ch, UINT fmt, LPGLYPHMETRICS gm, DWORD n,
                                        LPVOID buf, const MAT2* m) {
    if (!(fmt & GGO_GLYPH_INDEX)) {
        char mb[2];
        int k = 0;
        WCHAR w = 0;
        if (ch > 0xFF) mb[k++] = (char)(ch >> 8);
        mb[k++] = (char)ch;
        if (MultiByteToWideChar(g_cp, 0, mb, k, &w, 1) == 1) ch = w;
        return GetGlyphOutlineW(dc, ch, fmt, gm, n, buf, m);
    }
    return GetGlyphOutlineA(dc, ch, fmt, gm, n, buf, m);
}

/* The guest's EnumFonts*A callback sees face names in its code page. */
typedef struct { FONTENUMPROCA fn; LPARAM lp; } enum_ctx;

static int CALLBACK enum_w(const LOGFONTW* lf, const TEXTMETRICW* tm, DWORD type, LPARAM lp) {
    enum_ctx* c = (enum_ctx*)lp;
    ENUMLOGFONTEXA a;     /* the W call gives ENUMLOGFONTEXW behind the LOGFONTW */
    TEXTMETRICA tma;
    const ENUMLOGFONTEXW* ew = (const ENUMLOGFONTEXW*)lf;
    memset(&a, 0, sizeof a);
    logfont_a(lf, &a.elfLogFont);
    WideCharToMultiByte(g_cp, 0, ew->elfFullName, -1, (char*)a.elfFullName, LF_FULLFACESIZE, NULL, NULL);
    WideCharToMultiByte(g_cp, 0, ew->elfStyle, -1, (char*)a.elfStyle, LF_FACESIZE, NULL, NULL);
    WideCharToMultiByte(g_cp, 0, ew->elfScript, -1, (char*)a.elfScript, LF_FACESIZE, NULL, NULL);
    /* TEXTMETRICA is TEXTMETRICW with its four WCHAR fields as BYTEs. */
    memcpy(&tma, tm, offsetof(TEXTMETRICA, tmFirstChar));
    tma.tmFirstChar = (BYTE)min(tm->tmFirstChar, 0xFF);
    tma.tmLastChar = (BYTE)min(tm->tmLastChar, 0xFF);
    tma.tmDefaultChar = (BYTE)min(tm->tmDefaultChar, 0xFF);
    tma.tmBreakChar = (BYTE)min(tm->tmBreakChar, 0xFF);
    memcpy(&tma.tmItalic, &tm->tmItalic, sizeof tma - offsetof(TEXTMETRICA, tmItalic));
    return c->fn((const LOGFONTA*)&a, &tma, type, c->lp);
}

static int WINAPI cp_EnumFontsA(HDC dc, LPCSTR face, FONTENUMPROCA fn, LPARAM lp) {
    WCHAR w[LF_FACESIZE];
    enum_ctx c = { fn, lp };
    return EnumFontsW(dc, wide(face, w, LF_FACESIZE), enum_w, (LPARAM)&c);
}

static int WINAPI cp_EnumFontFamiliesA(HDC dc, LPCSTR face, FONTENUMPROCA fn, LPARAM lp) {
    WCHAR w[LF_FACESIZE];
    enum_ctx c = { fn, lp };
    return EnumFontFamiliesW(dc, wide(face, w, LF_FACESIZE), enum_w, (LPARAM)&c);
}

static int WINAPI cp_EnumFontFamiliesExA(HDC dc, LPLOGFONTA lf, FONTENUMPROCA fn, LPARAM lp, DWORD fl) {
    LOGFONTW w;
    enum_ctx c = { fn, lp };
    logfont_w(lf, &w);
    return EnumFontFamiliesExW(dc, &w, enum_w, (LPARAM)&c, fl);
}

static const struct { const char* name; void* fn; } g_cp_funcs[] = {
    { "GetACP", cp_GetACP }, { "GetOEMCP", cp_GetOEMCP }, { "GetCPInfo", cp_GetCPInfo },
    { "IsDBCSLeadByte", cp_IsDBCSLeadByte },
    { "MultiByteToWideChar", cp_MultiByteToWideChar }, { "WideCharToMultiByte", cp_WideCharToMultiByte },
    { "CompareStringA", cp_CompareStringA },
    { "CreateFileA", cp_CreateFileA }, { "GetFileAttributesA", cp_GetFileAttributesA },
    { "DeleteFileA", cp_DeleteFileA }, { "CreateDirectoryA", cp_CreateDirectoryA },
    { "FindFirstFileA", cp_FindFirstFileA }, { "FindNextFileA", cp_FindNextFileA },
    { "CharNextA", cp_CharNextA }, { "CharPrevA", cp_CharPrevA },
    { "SetWindowTextA", cp_SetWindowTextA }, { "MessageBoxA", cp_MessageBoxA },
    { "DrawTextA", cp_DrawTextA },
    { "CreateFontIndirectA", cp_CreateFontIndirectA }, { "CreateFontA", cp_CreateFontA },
    { "GetObjectA", cp_GetObjectA },
    { "TextOutA", cp_TextOutA }, { "ExtTextOutA", cp_ExtTextOutA },
    { "GetTextExtentPoint32A", cp_GetTextExtentPoint32A }, { "GetTextExtentPointA", cp_GetTextExtentPointA },
    { "GetGlyphOutlineA", cp_GetGlyphOutlineA },
    { "EnumFontsA", cp_EnumFontsA }, { "EnumFontFamiliesA", cp_EnumFontFamiliesA },
    { "EnumFontFamiliesExA", cp_EnumFontFamiliesExA },
};

static FARPROC WINAPI cp_GetProcAddress(HMODULE h, LPCSTR name);

/* The replacement for an import by this name, or 0 (also 0 while off). */
uint32_t codepage_func(const char* name) {   /* extern for the selftest */
    if (!g_cp || (uintptr_t)name < 0x10000) return 0;
    if (!strcmp(name, "GetProcAddress")) return (uint32_t)(uintptr_t)cp_GetProcAddress;
    for (int i = 0; i < (int)(sizeof g_cp_funcs / sizeof g_cp_funcs[0]); i++)
        if (!strcmp(g_cp_funcs[i].name, name)) return (uint32_t)(uintptr_t)g_cp_funcs[i].fn;
    return 0;
}

/* GetProcAddress, for a guest that finds these at run time. */
static FARPROC WINAPI cp_GetProcAddress(HMODULE h, LPCSTR name) {
    uint32_t va = codepage_func(name);
    return va ? (FARPROC)(uintptr_t)va : GetProcAddress(h, name);
}
