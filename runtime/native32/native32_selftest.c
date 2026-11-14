/*
 * native32 selftest: the bridge's purge measurement and st(0) transfer,
 * without a game. Build from an x86 prompt (vcvarsall x86):
 *
 *   cl /nologo /I. /I..\recomp32 native32_selftest.c native32.c ..\recomp32\image_loader.c ..\recomp32\recomp_trace.c
 *   native32_selftest.exe
 */
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "native32.h"

/* Two "lifted" guest SEH handlers at made-up addresses (seh32.c's check). */
static uint32_t seh_seen, seh_unwinds;
static void seh_skip(void) {           /* ExceptionContinueSearch; counts unwinds */
    uint32_t er = MEM32(g_esp + 4);
    if (MEM32(er + 4) & 2) seh_unwinds++;
    g_eax = 1; g_esp += 4;
}
static void seh_take(void) {           /* ExceptionContinueExecution */
    seh_seen = MEM32(MEM32(g_esp + 4));
    g_eax = 0; g_esp += 4;
}
const recomp_dispatch_entry_t recomp_dispatch_table[2] = {
    { 0x7FFE0000u, seh_skip }, { 0x7FFE0010u, seh_take } };
const uint32_t recomp_dispatch_count = 2;
recomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; return NULL; }

static int __stdcall add3(int a, int b, int c) { return a + b * 10 + c * 100; }
static int __cdecl sub2(int a, int b) { return a - b; }
static int __fastcall this_plus(int self, int unused, int x) { (void)unused; return self + x; }
static double __cdecl half(int a) { return a / 2.0; }

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } } while (0)

/* What a lifted `push args...; call [slot]` does: args, dummy ret, ICALL. */
static uint32_t call(void* fn, int n, const uint32_t* args, uint32_t* esp_after) {
    for (int i = n - 1; i >= 0; i--) PUSH32(g_esp, args[i]);
    recomp_func_t f = recomp_lookup_import((uint32_t)(uintptr_t)fn);   /* RECOMP_ICALL, by hand */
    CHECK(f != NULL);
    PUSH32(g_esp, RECOMP_RETADDR);
    f();
    *esp_after = g_esp;
    return g_eax;
}

int main(void) {
    native32_init();
    mach_enter();                       /* a guest stack and TIB for this thread */
    uint32_t esp0 = g_esp, after, eax = 0;

    uint32_t a3[] = {1, 2, 3};
    eax = call(add3, 3, a3, &after);
    CHECK(eax == 321);
    CHECK(after == esp0);               /* stdcall: callee popped 12 */

    g_esp = esp0;
    uint32_t a2[] = {9, 4};
    eax = call(sub2, 2, a2, &after);
    CHECK(eax == 5);
    CHECK(after == esp0 - 8);           /* cdecl: the lifted caller pops its args */

    g_esp = esp0;
    g_ecx = 40; g_edx = 0;              /* fastcall stands in for thiscall's ecx */
    uint32_t a1[] = {2};
    eax = call(this_plus, 1, a1, &after);
    CHECK(eax == 42);
    CHECK(after == esp0);

    g_esp = esp0;
    int top = g_fp_top;
    uint32_t h[] = {7};
    call(half, 1, h, &after);
    CHECK(g_fp_top == top + 1);          /* one value pushed on the lifted x87 */
    CHECK(g_st[0] == 3.5);

    mach_leave();

    /* Guest modules by name, and their exports by name and ordinal. Any DLL
     * with exports will do; version.dll is small and on every Windows. */
    char sys[MAX_PATH];
    GetSystemDirectoryA(sys, MAX_PATH);
    strcat(sys, "\\version.dll");
    uint32_t base = 0x20000000u, gva;
    if (!native32_map(sys, base)) {     /* everything below reads the mapping */
        printf("FAIL: cannot map %s at 0x%08X\n", sys, base);
        return 1;
    }
    CHECK(native32_module("VERSION.DLL") == base);
    CHECK(native32_module("c:\\anywhere\\version.dll") == base);
    CHECK(native32_module("kernel32.dll") == 0);
    gva = native32_export(base, "GetFileVersionInfoSizeA");
    CHECK(gva > base && native32_in_guest(gva));
    {
        IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(uintptr_t)(base + ((IMAGE_DOS_HEADER*)(uintptr_t)base)->e_lfanew);
        IMAGE_EXPORT_DIRECTORY* e = (IMAGE_EXPORT_DIRECTORY*)(uintptr_t)(base +
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        uint16_t ord = ((uint16_t*)(uintptr_t)(base + e->AddressOfNameOrdinals))[0];
        const char* first = (const char*)(uintptr_t)(base + ((uint32_t*)(uintptr_t)(base + e->AddressOfNames))[0]);
        CHECK(native32_export(base, (const char*)(uintptr_t)(e->Base + ord)) == native32_export(base, first));
    }
    CHECK(native32_export(base, "NoSuchExport") == 0);

    /* Two modules bound with one shim array: a shim only the first imports
     * still resolves after the second bind (each bind rebuilds the table). */
    {
        IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(uintptr_t)(base + ((IMAGE_DOS_HEADER*)(uintptr_t)base)->e_lfanew);
        IMAGE_IMPORT_DESCRIPTOR* d = (IMAGE_IMPORT_DESCRIPTOR*)(uintptr_t)(base +
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        uint32_t* ilt = (uint32_t*)(uintptr_t)(base + (d->OriginalFirstThunk ? d->OriginalFirstThunk : d->FirstThunk));
        uint32_t* slot = (uint32_t*)(uintptr_t)(base + d->FirstThunk);
        static native32_shim_t shims[1];
        char sys2[MAX_PATH];
        shims[0].name = (const char*)(uintptr_t)(base + *ilt + 2);   /* version.dll's first import */
        shims[0].fn = (recomp_func_t)add3;
        native32_bind(base, shims, 1);
        uint32_t va1 = *slot;
        GetSystemDirectoryA(sys2, MAX_PATH);
        strcat(sys2, "\\msimg32.dll");             /* small, and imports none of version.dll's */
        CHECK(native32_map(sys2, 0x21000000u) != 0);
        native32_bind(0x21000000u, shims, 1);
        CHECK(recomp_lookup_import(va1) == (recomp_func_t)add3);
    }

    /* A DLL every one of whose imports the host shims is never loaded:
     * version.dll's first import descriptor renamed to a DLL this process
     * has not loaded, and all its imports shimmed. */
    {
        IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(uintptr_t)(base + ((IMAGE_DOS_HEADER*)(uintptr_t)base)->e_lfanew);
        IMAGE_IMPORT_DESCRIPTOR* d = (IMAGE_IMPORT_DESCRIPTOR*)(uintptr_t)(base +
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        uint32_t* ilt = (uint32_t*)(uintptr_t)(base + (d->OriginalFirstThunk ? d->OriginalFirstThunk : d->FirstThunk));
        char* name = (char*)(uintptr_t)(base + d->Name);
        static native32_shim_t shims[256];
        int n = 0;
        for (; *ilt && n < 256; ilt++)
            if (!(*ilt & 0x80000000u)) {
                shims[n].name = (const char*)(uintptr_t)(base + *ilt + 2);
                shims[n++].fn = (recomp_func_t)add3;
            }
        CHECK(GetModuleHandleA("icm32.dll") == NULL && strlen(name) >= strlen("icm32.dll"));
        strcpy(name, "icm32.dll");
        native32_bind(base, shims, n);
        CHECK(GetModuleHandleA("icm32.dll") == NULL);
    }

    /* RaiseException is a built-in shim: the SetThreadName code returns, as the
     * guest's empty __except would; any other code is raised for real. This
     * exe (its static CRT) imports RaiseException, so bind a copy of it. */
    {
        char self[MAX_PATH];
        GetModuleFileNameA(NULL, self, MAX_PATH);
        uint32_t sb = 0x23000000u;
        CHECK(native32_map(self, sb) != 0);
        native32_bind(sb, NULL, 0);
        uint32_t slot = 0;
        IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(uintptr_t)(sb + ((IMAGE_DOS_HEADER*)(uintptr_t)sb)->e_lfanew);
        IMAGE_IMPORT_DESCRIPTOR* d = (IMAGE_IMPORT_DESCRIPTOR*)(uintptr_t)(sb +
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        for (; d->Name && !slot; d++) {
            uint32_t* ilt = (uint32_t*)(uintptr_t)(sb + (d->OriginalFirstThunk ? d->OriginalFirstThunk : d->FirstThunk));
            for (int k = 0; ilt[k] && !slot; k++)
                if (!(ilt[k] & 0x80000000u) && !strcmp((const char*)(uintptr_t)(sb + ilt[k] + 2), "RaiseException"))
                    slot = MEM32(sb + d->FirstThunk + 4 * k);
        }
        CHECK(slot != 0);
        if (slot) {
            mach_enter();
            uint32_t esp0 = g_esp, name[4] = { 0x1000, 0, 0xFFFFFFFFu, 0 };
            uint32_t args[4] = { 0x406D1388u, 0, 4, (uint32_t)(uintptr_t)name };
            uint32_t after;
            call((void*)(uintptr_t)slot, 4, args, &after);     /* returns: the name is swallowed */
            CHECK(after == esp0);
            int raised = 0;
            args[0] = 0xE0001234u;
            __try { call((void*)(uintptr_t)slot, 4, args, &after); }
            __except (GetExceptionCode() == 0xE0001234u) { raised = 1; }
            CHECK(raised);
            g_esp = esp0;                /* the real raise left the shim's pop undone */
            /* With native32_guest_seh the guest's own chain is asked: the
             * first frame passes, the second continues execution. */
            native32_guest_seh = 1;
            uint32_t regs[4] = { 0, 0x7FFE0000u, 0xFFFFFFFFu, 0x7FFE0010u };
            regs[0] = (uint32_t)(uintptr_t)&regs[2];
            uint32_t head = MEM32(g_fs_base);
            MEM32(g_fs_base) = (uint32_t)(uintptr_t)regs;
            args[0] = 0x0EEDFADEu;
            call((void*)(uintptr_t)slot, 4, args, &after);
            CHECK(seh_seen == 0x0EEDFADEu && after == esp0);
            MEM32(g_fs_base) = head;
            native32_guest_seh = 0;
            g_esp = esp0;
            mach_leave();
        }
    }

    /* An import by ordinal binds to a "<dll>#<ordinal>" shim, the DLL name in
     * any case. A copy of this exe with its first import descriptor turned
     * into one ordinal import from a DLL that does not exist: without the
     * shim it is unresolved, with it the slot is the shim. */
    {
        char self[MAX_PATH];
        GetModuleFileNameA(NULL, self, MAX_PATH);
        uint32_t ob = 0x27000000u;
        CHECK(native32_map(self, ob) != 0);
        IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(uintptr_t)(ob + ((IMAGE_DOS_HEADER*)(uintptr_t)ob)->e_lfanew);
        IMAGE_IMPORT_DESCRIPTOR* d = (IMAGE_IMPORT_DESCRIPTOR*)(uintptr_t)(ob +
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        uint32_t* ilt = (uint32_t*)(uintptr_t)(ob + (d->OriginalFirstThunk ? d->OriginalFirstThunk : d->FirstThunk));
        uint32_t* slot = (uint32_t*)(uintptr_t)(ob + d->FirstThunk);
        char* name = (char*)(uintptr_t)(ob + d->Name);
        CHECK(strlen(name) >= strlen("nodll.dll"));
        strcpy(name, "nodll.dll");
        ilt[0] = 0x80000000u | 7;
        ilt[1] = 0;
        d[1].Name = 0;                          /* only this descriptor */
        CHECK(native32_bind(ob, NULL, 0) == 1); /* no shim: unresolved */
        static native32_shim_t shims[1] = { { "NODLL.DLL#7", (recomp_func_t)add3 } };
        CHECK(native32_bind(ob, shims, 1) == 0);
        CHECK(recomp_lookup_import(*slot) == (recomp_func_t)add3);
    }

    /* A guest longjmp: the frame that owns a saved esp is the newest one
     * entered above it, and resuming it lands in its setjmp with its function
     * current again. */
    {
        static recomp_ehframe_t outer, inner;
        outer.entry_esp = 0x1000, outer.func = 0x00401000u;
        inner.entry_esp = 0x0F00, inner.func = 0x00402000u;
        recomp_eh_push(&outer);
        recomp_eh_push(&inner);
        CHECK(recomp_eh_owner(0x0F80) == &outer);
        CHECK(recomp_eh_owner(0x0E00) == &inner);
        CHECK(recomp_eh_owner(0x2000) == NULL);
        if (!setjmp(outer.jb)) {
            recomp_eh_resume(&outer, 0x00401234u);
            CHECK(!"recomp_eh_resume returned");
        } else {
            CHECK(outer.resume == 0x00401234u && g_cur_func == 0x00401000u);
            CHECK(recomp_eh_owner(0x0E00) == &outer);     /* the inner frame is gone */
        }
        recomp_eh_pop(&outer);
    }

    /* An MSVC exception frame's landing pad (RECOMP_EH_FRAME): a guest
     * handler's call or jump into the body -- an __except block entered by
     * _except_handler3, here in a frame-pointer-omitted function, whose
     * handlers' ebp is its entry esp -- comes back to it. An address the
     * frame does not list, or another ebp, is not taken. */
    {
        static const uint32_t at[] = { 0x00403010u, 0 };
        static recomp_ehframe_t f;
        memset(&f, 0, sizeof f);
        f.entry_esp = 0x2000, f.func = 0x00403000u, f.off = 0, f.resume_at = at;
        recomp_eh_push(&f);
        CHECK(recomp_eh_jump_hook != NULL);
        g_ebp = 0x2000;
        CHECK(recomp_eh_jump_hook(0x00403020u) == 0);
        g_ebp = 0x2004;
        CHECK(recomp_eh_jump_hook(0x00403010u) == 0);
        g_ebp = 0x2000;
        if (!setjmp(f.jb)) {
            recomp_eh_jump_hook(0x00403010u);
            CHECK(!"recomp_eh_jump returned");
        } else {
            CHECK(f.resume == 0x00403010u && g_cur_func == 0x00403000u);
        }
        recomp_eh_pop(&f);
    }

    /* Code the guest generates: entered with its registers, not the C ABI.
     * Inputs in esi, edi, a stack argument and mm1; outputs in eax, ebx and
     * mm1; `ret 4` pops its argument. ebp is changed and must come back to
     * the guest, not the host. */
    {
        static const uint8_t gen[] = {
            0x89, 0xF0,                     /* mov eax, esi          */
            0x01, 0xF8,                     /* add eax, edi          */
            0x03, 0x44, 0x24, 0x04,         /* add eax, [esp+4]      */
            0x0F, 0x7E, 0xC9,               /* movd ecx, mm1         */
            0x01, 0xC8,                     /* add eax, ecx          */
            0xBB, 0x34, 0x12, 0x00, 0x00,   /* mov ebx, 0x1234       */
            0xBD, 0x78, 0x56, 0x00, 0x00,   /* mov ebp, 0x5678       */
            0x0F, 0xFE, 0xC9,               /* paddd mm1, mm1        */
            0xC2, 0x04, 0x00,               /* ret 4                 */
        };
        uint8_t* code = (uint8_t*)VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        memcpy(code, gen, sizeof gen);
        uint32_t va = (uint32_t)(uintptr_t)code, after, arg = 1000;
        CHECK(!native32_is_generated(va));
        CHECK(recomp_lookup_import(va) != NULL);         /* before: an ordinary native call */
        native32_add_generated(va, 4096);
        CHECK(native32_is_generated(va + 100) && !native32_is_generated(va + 4096));
        uint32_t ebp0 = g_ebp, esp0 = g_esp;
        g_esi = 1; g_edi = 20; g_mm[1] = 300; g_ebx = 0;
        uint32_t eax = call(code, 1, &arg, &after);
        CHECK(eax == 1321);
        CHECK(g_ebx == 0x1234 && g_ebp == 0x5678 && g_mm[1] == 600);
        CHECK(after == esp0);                            /* ret 4: the callee popped its argument */
        g_ebp = ebp0;
        VirtualFree(code, 0, MEM_RELEASE);
    }

    /* Code page 932 for the guest: "\x93\xfa\x96\x7b" is Shift-JIS for U+65E5 U+672C,
     * whatever the system's ANSI code page is. */
    {
        uint32_t codepage_func(const char* name);
        CHECK(codepage_func("MultiByteToWideChar") == 0);          /* off by default */
        native32_set_codepage(932);
        uint32_t mb = codepage_func("MultiByteToWideChar"), acp = codepage_func("GetACP");
        uint32_t ext = codepage_func("GetTextExtentPoint32A");
        CHECK(mb && acp && ext && codepage_func("lstrlenA") == 0);
        WCHAR w[8] = { 0 };
        uint32_t a[6] = { CP_ACP, 0, (uint32_t)(uintptr_t)"\x93\xfa\x96\x7b", 4,
                          (uint32_t)(uintptr_t)w, 8 }, after;
        CHECK(call((void*)(uintptr_t)mb, 6, a, &after) == 2 && w[0] == 0x65E5 && w[1] == 0x672C);
        CHECK(call((void*)(uintptr_t)acp, 0, a, &after) == 932);
        /* Two DBCS characters measure as two glyphs of the same width, not four bytes. */
        HDC dc = CreateCompatibleDC(NULL);
        HFONT f = CreateFontA(16, 0, 0, 0, 0, 0, 0, 0, SHIFTJIS_CHARSET, 0, 0, 0, FIXED_PITCH, NULL);
        SelectObject(dc, f);
        SIZE one, two;
        uint32_t b[4] = { (uint32_t)(uintptr_t)dc, (uint32_t)(uintptr_t)"\x93\xfa", 2, (uint32_t)(uintptr_t)&one };
        call((void*)(uintptr_t)ext, 4, b, &after);
        b[1] = (uint32_t)(uintptr_t)"\x93\xfa\x96\x7b"; b[2] = 4; b[3] = (uint32_t)(uintptr_t)&two;
        call((void*)(uintptr_t)ext, 4, b, &after);
        CHECK(one.cx > 0 && two.cx == 2 * one.cx);
        DeleteDC(dc);
        DeleteObject(f);
        /* A folder named U+65E5 U+672C: the paths Windows hands back are in 932 too. */
        {
            WCHAR tmp[MAX_PATH], dir[MAX_PATH], old[MAX_PATH];
            char got[MAX_PATH * 2], full[MAX_PATH * 2], *part = NULL;
            GetTempPathW(MAX_PATH, tmp);
            _snwprintf(dir, MAX_PATH, L"%s\x65E5\x672C%lu", tmp, GetCurrentProcessId());
            GetCurrentDirectoryW(MAX_PATH, old);
            CHECK(CreateDirectoryW(dir, NULL) && SetCurrentDirectoryW(dir));
            uint32_t gcd = codepage_func("GetCurrentDirectoryA"), gfp = codepage_func("GetFullPathNameA");
            uint32_t c[2] = { sizeof got, (uint32_t)(uintptr_t)got };
            uint32_t n = call((void*)(uintptr_t)gcd, 2, c, &after);
            CHECK(n == strlen(got) && strstr(got, "\x93\xfa\x96\x7b") != NULL);
            uint32_t d[4] = { (uint32_t)(uintptr_t)"a.txt", sizeof full, (uint32_t)(uintptr_t)full,
                              (uint32_t)(uintptr_t)&part };
            n = call((void*)(uintptr_t)gfp, 4, d, &after);
            CHECK(n == strlen(full) && part && !strcmp(part, "a.txt") && !strncmp(full, got, strlen(got)));
            c[0] = 4;   /* too small: the size needed, NUL included */
            CHECK(call((void*)(uintptr_t)gcd, 2, c, &after) == strlen(got) + 1);
            SetCurrentDirectoryW(old);
            RemoveDirectoryW(dir);
        }
        native32_set_codepage(0);
    }

    printf("native32 selftest: %s\n", fails ? "FAILED" : "ok");
    return fails != 0;
}
