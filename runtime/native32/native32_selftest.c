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

const recomp_dispatch_entry_t recomp_dispatch_table[1];
const uint32_t recomp_dispatch_count = 0;
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

    printf("native32 selftest: %s\n", fails ? "FAILED" : "ok");
    return fails != 0;
}
