/*
 * host_selftest.c - a full boot, headless, with no game binary. A synthetic
 * "lifted app" plays the part the generated C would: an entry point that reads
 * its IAT, registers a window class, creates a window, and runs a real
 * GetMessage/TranslateMessage/DispatchMessage loop; and a WndProc that paints
 * on WM_PAINT by blitting a DIB through gdi32. The host maps the image, binds
 * its one import, and calls the entry — the same path a real title takes.
 *
 * Build -m32 -no-pie (the image maps at ImageBase 0x00400000).
 */
#define RECOMP_GENERATED_CODE
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "pe_format.h"
#include "pe_loader.h"
#include "win32hle.h"
#include "host.h"

void hle_gdi_set_target(uint32_t *pixels, int w, int h);

#define IMAGE_BASE 0x00400000u
#define ENTRY_VA   0x00401000u
#define WNDPROC_VA 0x00401100u
#define WM_PAINT   0x000Fu
#define FB_W 8
#define FB_H 8

/* --- synthetic image VAs (data the "app" reads) --- */
#define SEC_RVA    0x1000u
#define SEC_FOFF   0x200u
#define FILE_SZ    0x400u
#define RVA_IMPDESC 0x1010u
#define RVA_ILT     0x1040u
#define RVA_IAT     0x1050u     /* IAT[0] = GetModuleHandleA after bind */
#define RVA_NAME0   0x1060u
#define RVA_DLLNAME 0x10A0u

static int fails;
static void ok(const char *w, int c) { if (!c) { printf("FAIL %s\n", w); fails++; } }

#define GUEST_PROLOGUE(va) \
    uint32_t _cf = 0; uint32_t _flag_k = FK_NONE; uint32_t _flag_a = 0, _flag_b = 0; RECOMP_ENTER(va)

/* host-side resources the app draws with / into */
static uint32_t fb[FB_W * FB_H];
static uint8_t  g_bmi[40];
static uint32_t g_dib[16];
static uint8_t  g_wc[40];
static uint8_t  g_msg[28];
static char     g_clsname[] = "appwnd";
static char     g_title[]   = "t";
static int      g_paint_count;
static uint32_t src_pixel(int x, int y) { return 0xFF000000u | (uint32_t)((x << 4) | y); }

/* resolved shim VAs */
static uint32_t VA_RegisterClassA, VA_CreateWindowExA, VA_ShowWindow, VA_PostMessageA,
                VA_PostQuitMessage, VA_GetMessageA, VA_TranslateMessage, VA_DispatchMessageA,
                VA_StretchDIBits;

/* The lifted CRT entry -> WinMain -> message loop. */
static void app_entry(void) {
    GUEST_PROLOGUE(ENTRY_VA);
    /* GetModuleHandleA(NULL) through the bound IAT (proves map+bind+use). */
    PUSH32(esp, 0);
    RECOMP_ICALL(MEM32(IMAGE_BASE + RVA_IAT));
    uint32_t hinst = eax;

    PUSH32(esp, (uint32_t)(uintptr_t)g_wc);
    RECOMP_ICALL(VA_RegisterClassA);

    /* CreateWindowExA(exStyle,class,title,style,x,y,w,h,parent,menu,hinst,param) */
    PUSH32(esp, 0);                                   /* lParam    */
    PUSH32(esp, hinst);                               /* hInstance */
    PUSH32(esp, 0);                                   /* hMenu     */
    PUSH32(esp, 0);                                   /* parent    */
    PUSH32(esp, FB_H);                                /* height    */
    PUSH32(esp, FB_W);                                /* width     */
    PUSH32(esp, 0);                                   /* y         */
    PUSH32(esp, 0);                                   /* x         */
    PUSH32(esp, 0);                                   /* style     */
    PUSH32(esp, (uint32_t)(uintptr_t)g_title);        /* winName   */
    PUSH32(esp, (uint32_t)(uintptr_t)g_clsname);      /* className */
    PUSH32(esp, 0);                                   /* exStyle   */
    RECOMP_ICALL(VA_CreateWindowExA);
    uint32_t hwnd = eax;

    PUSH32(esp, 1); PUSH32(esp, hwnd); RECOMP_ICALL(VA_ShowWindow);

    /* queue one paint, then a quit so the loop terminates */
    PUSH32(esp, 0); PUSH32(esp, 0); PUSH32(esp, WM_PAINT); PUSH32(esp, hwnd);
    RECOMP_ICALL(VA_PostMessageA);
    PUSH32(esp, 0); RECOMP_ICALL(VA_PostQuitMessage);

    for (;;) {
        PUSH32(esp, 0); PUSH32(esp, 0); PUSH32(esp, 0); PUSH32(esp, (uint32_t)(uintptr_t)g_msg);
        RECOMP_ICALL(VA_GetMessageA);
        if (eax == 0) break;
        PUSH32(esp, (uint32_t)(uintptr_t)g_msg); RECOMP_ICALL(VA_TranslateMessage);
        PUSH32(esp, (uint32_t)(uintptr_t)g_msg); RECOMP_ICALL(VA_DispatchMessageA);
    }
    eax = 0x1234;   /* exit code */
}

/* WndProc(hwnd,msg,wParam,lParam): paint on WM_PAINT, else return 0. */
static void app_wndproc(void) {
    GUEST_PROLOGUE(WNDPROC_VA);
    uint32_t message = MEM32(esp + 8);
    if (message == WM_PAINT) {
        g_paint_count++;
        /* StretchDIBits(hdc,0,0,FB_W,FB_H, 0,0,4,4, g_dib, g_bmi, 0, SRCCOPY) */
        PUSH32(esp, 0x00CC0020u); PUSH32(esp, 0);
        PUSH32(esp, (uint32_t)(uintptr_t)g_bmi); PUSH32(esp, (uint32_t)(uintptr_t)g_dib);
        PUSH32(esp, 4); PUSH32(esp, 4); PUSH32(esp, 0); PUSH32(esp, 0);
        PUSH32(esp, FB_H); PUSH32(esp, FB_W); PUSH32(esp, 0); PUSH32(esp, 0);
        PUSH32(esp, 0);
        RECOMP_ICALL(VA_StretchDIBits);
    }
    eax = 0;
    esp += 4 + 16;   /* stdcall WndProc: pop ret + 4 args */
}

const recomp_dispatch_entry_t recomp_dispatch_table[] = {
    { ENTRY_VA,   app_entry },
    { WNDPROC_VA, app_wndproc },
};
const uint32_t recomp_dispatch_count = 2;

static void put32(uint8_t *s, uint32_t rva, uint32_t v) { memcpy(s + (rva - SEC_RVA), &v, 4); }
static void build_pe(const char *path) {
    uint8_t *img = (uint8_t *)calloc(1, FILE_SZ);
    pe_dos_header *dos = (pe_dos_header *)img; dos->e_magic = 0x5A4D; dos->e_lfanew = 0x40;
    pe_nt_headers32 *nt = (pe_nt_headers32 *)(img + 0x40);
    nt->Signature = 0x00004550;
    nt->FileHeader.Machine = 0x14C;
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(pe_opt_header32);
    pe_opt_header32 *opt = &nt->OptionalHeader;
    opt->Magic = 0x10B;
    opt->AddressOfEntryPoint = ENTRY_VA - IMAGE_BASE;   /* -> img.entry == ENTRY_VA */
    opt->ImageBase = IMAGE_BASE;
    opt->SectionAlignment = 0x1000; opt->FileAlignment = 0x200;
    opt->SizeOfImage = 0x2000; opt->SizeOfHeaders = SEC_FOFF; opt->NumberOfRvaAndSizes = 16;
    opt->DataDirectory[PE_DIR_IMPORT].VirtualAddress = RVA_IMPDESC;
    opt->DataDirectory[PE_DIR_IMPORT].Size = 2 * sizeof(pe_import_descriptor);
    pe_section_header *sh = (pe_section_header *)(img + 0x40 + sizeof(pe_nt_headers32));
    memcpy(sh->Name, ".data", 5);
    sh->VirtualSize = 0x200; sh->VirtualAddress = SEC_RVA;
    sh->SizeOfRawData = 0x200; sh->PointerToRawData = SEC_FOFF;
    sh->Characteristics = 0xC0000040u;
    uint8_t *sec = img + SEC_FOFF;
    pe_import_descriptor *d = (pe_import_descriptor *)(sec + (RVA_IMPDESC - SEC_RVA));
    d[0].OriginalFirstThunk = RVA_ILT; d[0].Name = RVA_DLLNAME; d[0].FirstThunk = RVA_IAT;
    put32(sec, RVA_ILT, RVA_NAME0); put32(sec, RVA_ILT + 4, 0);
    put32(sec, RVA_IAT, RVA_NAME0); put32(sec, RVA_IAT + 4, 0);
    sec[RVA_NAME0 - SEC_RVA] = 0; sec[RVA_NAME0 - SEC_RVA + 1] = 0;
    strcpy((char *)sec + (RVA_NAME0 - SEC_RVA) + 2, "GetModuleHandleA");
    strcpy((char *)sec + (RVA_DLLNAME - SEC_RVA), "KERNEL32.dll");
    FILE *f = fopen(path, "wb"); fwrite(img, 1, FILE_SZ, f); fclose(f); free(img);
}

int main(void) {
    recomp_host_init();

    /* the "image data" the app draws with: a window class, a 4x4 DIB, a header */
    *(uint32_t *)(g_wc + 4)  = WNDPROC_VA;                        /* lpfnWndProc  */
    *(uint32_t *)(g_wc + 36) = (uint32_t)(uintptr_t)g_clsname;    /* lpszClassName */
    g_bmi[0] = 40; g_bmi[4] = 4; { int32_t h = -4; memcpy(g_bmi + 8, &h, 4); }
    g_bmi[12] = 1; g_bmi[14] = 32;
    for (int y = 0; y < 4; y++) for (int x = 0; x < 4; x++) g_dib[y * 4 + x] = src_pixel(x, y);
    hle_gdi_set_target(fb, FB_W, FB_H);

    VA_RegisterClassA   = hle_resolve("RegisterClassA");
    VA_CreateWindowExA  = hle_resolve("CreateWindowExA");
    VA_ShowWindow       = hle_resolve("ShowWindow");
    VA_PostMessageA     = hle_resolve("PostMessageA");
    VA_PostQuitMessage  = hle_resolve("PostQuitMessage");
    VA_GetMessageA      = hle_resolve("GetMessageA");
    VA_TranslateMessage = hle_resolve("TranslateMessage");
    VA_DispatchMessageA = hle_resolve("DispatchMessageA");
    VA_StretchDIBits    = hle_resolve("StretchDIBits");
    ok("user32/gdi32 shims resolve", VA_CreateWindowExA && VA_GetMessageA && VA_DispatchMessageA && VA_StretchDIBits);

    const char *path = "/tmp/win32hle_host_pe.bin";
    build_pe(path);
    ok("host boot (map + bind) ok", recomp_host_boot(path) == 0);
    ok("entry VA is the image's",   recomp_host_entry() == ENTRY_VA);

    uint32_t code = recomp_host_run();
    ok("entry ran to completion (exit code)", code == 0x1234);
    ok("WndProc was called once via the message loop", g_paint_count == 1);

    int painted = 1;
    for (int y = 0; y < FB_H; y++) for (int x = 0; x < FB_W; x++)
        if (fb[y * FB_W + x] != src_pixel(x / 2, y / 2)) painted = 0;
    ok("WM_PAINT blitted the DIB into the framebuffer", painted);

    if (fails == 0) printf("host_selftest: all checks passed\n");
    return fails != 0;
}
