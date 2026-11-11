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
 * interpreter; an MSVC 5 C engine with a static CRT) and the Win9x titles
 * around them reached; a guest calling another
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

/* Paths Windows hands back. CreateFileA and the rest read the guest's paths
 * in g_cp, so the paths it is given have to be in g_cp too: the system's ANSI
 * code page would hand a 932 guest a user folder spelled with an e acute as
 * 0xE9, which 932 reads as a lead byte. A path that g_cp cannot spell comes
 * back as its 8.3 short name,
 * which is ASCII, and the guest can still open what is inside. A-function
 * results: the length without the NUL, or the size needed with it when n is
 * too small. */
static DWORD path_a(const WCHAR* w, DWORD wn, char* out, DWORD n) {
    WCHAR sh[MAX_PATH * 2];
    BOOL lossy = FALSE;
    if (!wn) return 0;
    int need = WideCharToMultiByte(g_cp, 0, w, -1, NULL, 0, NULL, &lossy);
    if (lossy) {
        DWORD k = GetShortPathNameW(w, sh, MAX_PATH * 2);
        if (k && k < MAX_PATH * 2) w = sh, need = WideCharToMultiByte(g_cp, 0, w, -1, NULL, 0, NULL, NULL);
    }
    if (!out || (DWORD)need > n) return (DWORD)need;
    WideCharToMultiByte(g_cp, 0, w, -1, out, (int)n, NULL, NULL);
    return (DWORD)need - 1;
}

static DWORD WINAPI cp_GetModuleFileNameA(HMODULE h, LPSTR buf, DWORD n) {
    WCHAR w[MAX_PATH * 2];
    DWORD r = path_a(w, GetModuleFileNameW(h, w, MAX_PATH * 2), buf, n);
    if (r >= n && n) {   /* this one truncates instead */
        char full[MAX_PATH * 4];
        path_a(w, 1, full, sizeof full);
        lstrcpynA(buf, full, (int)n);
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return n;
    }
    return r;
}

static DWORD WINAPI cp_GetCurrentDirectoryA(DWORD n, LPSTR buf) {
    WCHAR w[MAX_PATH * 2];
    return path_a(w, GetCurrentDirectoryW(MAX_PATH * 2, w), buf, n);
}

static BOOL WINAPI cp_SetCurrentDirectoryA(LPCSTR p) {
    WCHAR w[MAX_PATH * 2];
    return SetCurrentDirectoryW(wide(p, w, MAX_PATH * 2));
}

static UINT WINAPI cp_GetWindowsDirectoryA(LPSTR buf, UINT n) {
    WCHAR w[MAX_PATH * 2];
    return path_a(w, GetWindowsDirectoryW(w, MAX_PATH * 2), buf, n);
}

static UINT WINAPI cp_GetSystemDirectoryA(LPSTR buf, UINT n) {
    WCHAR w[MAX_PATH * 2];
    return path_a(w, GetSystemDirectoryW(w, MAX_PATH * 2), buf, n);
}

static DWORD WINAPI cp_GetTempPathA(DWORD n, LPSTR buf) {
    WCHAR w[MAX_PATH * 2];
    return path_a(w, GetTempPathW(MAX_PATH * 2, w), buf, n);
}

static DWORD WINAPI cp_GetFullPathNameA(LPCSTR p, DWORD n, LPSTR buf, LPSTR* part) {
    WCHAR in[MAX_PATH * 2], w[MAX_PATH * 2];
    DWORD r = path_a(w, GetFullPathNameW(wide(p, in, MAX_PATH * 2), MAX_PATH * 2, w, NULL), buf, n);
    if (part && r && r < n) {
        char* s = NULL;   /* the last separator, not a 0x5C trail byte */
        for (char* c = buf; *c; c++)
            if (IsDBCSLeadByteEx(g_cp, (BYTE)*c) && c[1]) c++;
            else if (*c == 0x5C) s = c;
        *part = s && s[1] ? s + 1 : NULL;
    }
    return r;
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

/* An A window gets the A message, so its own procedure (and DefWindowProcA,
 * below) sees the guest's bytes; a Unicode one the converted text. */
static BOOL WINAPI cp_SetWindowTextA(HWND h, LPCSTR s) {
    WCHAR w[1024];
    return IsWindowUnicode(h) ? SetWindowTextW(h, wide(s, w, 1024)) : SetWindowTextA(h, s);
}

static int WINAPI cp_MessageBoxA(HWND h, LPCSTR text, LPCSTR cap, UINT type) {
    WCHAR wt[4096], wc[512];
    return MessageBoxW(h, wide(text, wt, 4096), wide(cap, wc, 512), type);
}

/* A window's text, which Windows keeps as UTF-16: an A window converts it in
 * and out of the system's code page in DefWindowProcA (WM_NCCREATE's
 * lpszName, WM_SETTEXT, WM_GETTEXT). Done here in the guest's instead. A
 * guest that hands the message to the real DefWindowProcA another way (a
 * pointer it got before binding) still gets the system's. */
static LRESULT WINAPI cp_DefWindowProcA(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    WCHAR w[1024];
    switch (msg) {
    case WM_NCCREATE: {
        LRESULT r = DefWindowProcA(h, msg, wp, lp);
        const CREATESTRUCTA* cs = (const CREATESTRUCTA*)lp;
        if (r && cs && cs->lpszName && (uintptr_t)cs->lpszName >= 0x10000)
            DefWindowProcW(h, WM_SETTEXT, 0, (LPARAM)wide(cs->lpszName, w, 1024));
        return r;
    }
    case WM_SETTEXT:
        return DefWindowProcW(h, msg, wp, (LPARAM)wide((const char*)lp, w, 1024));
    case WM_GETTEXT: {
        int n = (int)DefWindowProcW(h, WM_GETTEXT, 1024, (LPARAM)w);
        if (!wp || !lp) return 0;
        int k = WideCharToMultiByte(g_cp, 0, w, n, (char*)lp, (int)wp - 1, NULL, NULL);
        ((char*)lp)[k] = 0;
        return k;
    }
    case WM_GETTEXTLENGTH: {
        int n = (int)DefWindowProcW(h, WM_GETTEXT, 1024, (LPARAM)w);
        return WideCharToMultiByte(g_cp, 0, w, n, NULL, 0, NULL, NULL);
    }
    }
    return DefWindowProcA(h, msg, wp, lp);
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
    { "GetModuleFileNameA", cp_GetModuleFileNameA }, { "GetCurrentDirectoryA", cp_GetCurrentDirectoryA },
    { "SetCurrentDirectoryA", cp_SetCurrentDirectoryA }, { "GetWindowsDirectoryA", cp_GetWindowsDirectoryA },
    { "GetSystemDirectoryA", cp_GetSystemDirectoryA }, { "GetTempPathA", cp_GetTempPathA },
    { "GetFullPathNameA", cp_GetFullPathNameA },
    { "CharNextA", cp_CharNextA }, { "CharPrevA", cp_CharPrevA },
    { "SetWindowTextA", cp_SetWindowTextA }, { "DefWindowProcA", cp_DefWindowProcA }, { "MessageBoxA", cp_MessageBoxA },
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

/* native32_redirect: a host's own native replacements, by name, for imports
 * and for GetProcAddress (a DLL the guest loads itself: a host that wants to
 * see what reaches DrawDibDraw). */
#define MAX_REDIRECTS 32
static struct { const char* name; void* fn; } g_redir[MAX_REDIRECTS];
static int g_nredir;

void native32_redirect(const char* name, void* fn) {
    if (g_nredir < MAX_REDIRECTS) g_redir[g_nredir].name = name, g_redir[g_nredir++].fn = fn;
}

/* The replacement for an import by this name, or 0: a host redirect, then
 * (while a code page is set) the code page's. */
uint32_t codepage_func(const char* name) {   /* extern for the selftest */
    if ((uintptr_t)name < 0x10000) return 0;
    for (int i = 0; i < g_nredir; i++)
        if (!strcmp(g_redir[i].name, name)) return (uint32_t)(uintptr_t)g_redir[i].fn;
    if (!g_cp && !g_nredir) return 0;
    if (!strcmp(name, "GetProcAddress")) return (uint32_t)(uintptr_t)cp_GetProcAddress;
    if (!g_cp) return 0;
    for (int i = 0; i < (int)(sizeof g_cp_funcs / sizeof g_cp_funcs[0]); i++)
        if (!strcmp(g_cp_funcs[i].name, name)) return (uint32_t)(uintptr_t)g_cp_funcs[i].fn;
    return 0;
}

/* GetProcAddress, for a guest that finds these at run time. */
static FARPROC WINAPI cp_GetProcAddress(HMODULE h, LPCSTR name) {
    uint32_t va = codepage_func(name);
    return va ? (FARPROC)(uintptr_t)va : GetProcAddress(h, name);
}
