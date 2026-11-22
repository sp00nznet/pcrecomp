/*
 * native64.c: modules, dispatch, the syscall boundary and process start for
 * a lifted 64-bit NT userland (native64.h).
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include "native64.h"

__declspec(thread) uint64_t g_guest_gs;   /* cpu64.h RECOMP_GUEST_GS: this thread's guest TEB */
static __declspec(thread) CPU* t_cpu;     /* this thread's guest registers */
static __declspec(thread) jmp_buf* t_top; /* NtContinue lands here */
int64_t g_image_delta;                    /* every module sits at its own base */
uint64_t native64_peb;
int native64_trace;

#define ST_SUCCESS 0
#define ST_NOT_IMPLEMENTED 0xC0000002u
#define ST_ACCESS_DENIED 0xC0000022u
#define ST_NAME_NOT_FOUND 0xC0000034u
#define ST_INVALID_SERVICE 0xC000001Cu

/* ---- modules -------------------------------------------------------------- */
#define MAXMODS 64
static struct { char file[64]; uint64_t base, size; } g_mod[MAXMODS];
static int g_nmod;

uint64_t native64_module(const char* file) {
    for (int i = 0; i < g_nmod; i++) if (!_stricmp(g_mod[i].file, file)) return g_mod[i].base;
    return 0;
}

static int map_image(const wchar_t* path, uint64_t base, uint64_t* size) {
    FILE* f = _wfopen(path, L"rb");
    if (!f) { fprintf(stderr, "[native64] %ls: missing\n", path); return 0; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    uint8_t* d = (uint8_t*)malloc(n);
    fseek(f, 0, SEEK_SET);
    fread(d, 1, n, f);
    fclose(f);
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(d + *(uint32_t*)(d + 0x3C));
    if (nt->OptionalHeader.Magic != 0x20B || nt->OptionalHeader.ImageBase != base) {
        fprintf(stderr, "[native64] %ls: not a PE32+ at %llX\n", path, (unsigned long long)base);
        return 0;
    }
    uint8_t* m = (uint8_t*)VirtualAlloc((void*)(uintptr_t)base, nt->OptionalHeader.SizeOfImage,
                                        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if ((uint64_t)(uintptr_t)m != base) {
        fprintf(stderr, "[native64] %ls: %llX is taken in this process\n", path, (unsigned long long)base);
        return 0;
    }
    memcpy(m, d, nt->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
        if (s[i].SizeOfRawData)
            memcpy(m + s[i].VirtualAddress, d + s[i].PointerToRawData,
                   min(s[i].SizeOfRawData, max(s[i].Misc.VirtualSize, s[i].SizeOfRawData)));
    *size = nt->OptionalHeader.SizeOfImage;
    free(d);
    return 1;
}

uint64_t native64_export(uint64_t base, const char* name) {
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(uintptr_t)(base + *(uint32_t*)(uintptr_t)(base + 0x3C));
    IMAGE_DATA_DIRECTORY dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dd.VirtualAddress) return 0;
    IMAGE_EXPORT_DIRECTORY* e = (IMAGE_EXPORT_DIRECTORY*)(uintptr_t)(base + dd.VirtualAddress);
    uint32_t* names = (uint32_t*)(uintptr_t)(base + e->AddressOfNames);
    uint16_t* ords = (uint16_t*)(uintptr_t)(base + e->AddressOfNameOrdinals);
    uint32_t* fns = (uint32_t*)(uintptr_t)(base + e->AddressOfFunctions);
    for (uint32_t i = 0; i < e->NumberOfNames; i++)
        if (!strcmp((const char*)(uintptr_t)(base + names[i]), name)) return base + fns[ords[i]];
    return 0;
}

/* ---- dispatch ------------------------------------------------------------- */
static void (*find(uint64_t va))(CPU*) {
    unsigned lo = 0, hi = native64_table_count;
    while (lo < hi) {
        unsigned mid = lo + (hi - lo) / 2;
        if (native64_table[mid].va == va) return native64_table[mid].fn;
        if (native64_table[mid].va < va) lo = mid + 1; else hi = mid;
    }
    return NULL;
}

static const char* mod_of(uint64_t va, uint64_t* off) {
    for (int i = 0; i < g_nmod; i++)
        if (va >= g_mod[i].base && va < g_mod[i].base + g_mod[i].size) { *off = va - g_mod[i].base; return g_mod[i].file; }
    *off = va;
    return "?";
}

static void guest_stack_dump(CPU* c) {
    fprintf(stderr, "  rax=%llX rcx=%llX rdx=%llX rbx=%llX rsp=%llX rbp=%llX rsi=%llX rdi=%llX\n"
                    "  r8=%llX r9=%llX r10=%llX r11=%llX r12=%llX r13=%llX r14=%llX r15=%llX\n  callers:",
            c->rax, c->rcx, c->rdx, c->rbx, c->rsp, c->rbp, c->rsi, c->rdi,
            c->r8, c->r9, c->r10, c->r11, c->r12, c->r13, c->r14, c->r15);
    for (int i = 0, k = 0; i < 4096 && k < 24; i++) {
        uint64_t p = c->rsp + 8 * i, v, off;
        if (IsBadReadPtr((void*)(uintptr_t)p, 8)) break;
        v = *(uint64_t*)(uintptr_t)p;
        const char* m = mod_of(v, &off);
        if (*m != '?') fprintf(stderr, " %s+%llX", m, off), k++;
    }
    fprintf(stderr, "\n");
}

/* The last guest entries this thread took (NATIVE64_RING_AT=<service>
 * prints them when the guest calls it, and every fault does). */
#define RING 256
static __declspec(thread) uint64_t t_ring[RING];
static __declspec(thread) unsigned t_ringn;
static const char* g_ring_at;
static void ring_dump(const char* why) {
    uint64_t off;
    fprintf(stderr, "[ring] %s, newest last:", why);
    for (unsigned i = t_ringn > RING ? t_ringn - RING : 0; i < t_ringn; i++)
        fprintf(stderr, " %s+%llX", mod_of(t_ring[i % RING], &off), off);
    fprintf(stderr, "\n");
}

void dispatch(CPU* c, uint64_t va) {
    void (*fn)(CPU*) = find(va);
    t_ring[t_ringn++ % RING] = va;
    if (fn) { fn(c); return; }
    uint64_t off;
    const char* m = mod_of(va, &off);
    fprintf(stderr, "\n[native64] no lifted function at %llX (%s+%llX), from rip %llX\n",
            (unsigned long long)va, m, (unsigned long long)off, (unsigned long long)c->rip);
    guest_stack_dump(c);
    {   /* NATIVE64_SEEDS=file: "<module> <va>" appended, for the next catalog */
        const char* sf = getenv("NATIVE64_SEEDS");
        FILE* f = sf ? fopen(sf, "a") : NULL;
        if (f) fprintf(f, "%s %llX\n", m, (unsigned long long)va), fclose(f);
    }
    fflush(stderr);
    TerminateProcess(GetCurrentProcess(), 2);
}
void dispatch_jmp(CPU* c, uint64_t va) { dispatch(c, va); }

uint64_t native64_call(uint64_t va, int n, const uint64_t* a) {
    CPU* c = t_cpu;
    uint64_t sp = c->rsp;
    c->rsp = (c->rsp - 0x100) & ~(uint64_t)15;   /* below whatever the caller had */
    c->rsp -= 0x20;                               /* home space */
    if (n > 0) c->rcx = a[0];
    if (n > 1) c->rdx = a[1];
    if (n > 2) c->r8 = a[2];
    if (n > 3) c->r9 = a[3];
    push64(c, 0);                                 /* the return: popped by the callee's ret */
    dispatch(c, va);
    c->rsp = sp;
    return c->rax;
}

/* ---- the system call boundary -------------------------------------------- */
#define NSVC 0x400
static struct { const char* name; void* host; native64_syscall_fn ovr; int seen; } g_svc[NSVC];

static void* host_nt(const char* name) {
    static HMODULE nt;
    if (!nt) nt = GetModuleHandleA("ntdll.dll");
    return (void*)GetProcAddress(nt, name);
}

void native64_override(const char* name, native64_syscall_fn fn) {
    for (int i = 0; i < NSVC; i++) if (g_svc[i].name && !strcmp(g_svc[i].name, name)) g_svc[i].ovr = fn;
}

typedef uint64_t (NTAPI *svc16_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                   uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
static uint64_t call16(void* f, const uint64_t* a) {
    return ((svc16_t)f)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);
}

uint64_t native64_forward(const char* name, uint64_t* a) {
    void* f = host_nt(name);
    if (!f) { fprintf(stderr, "[native64] host has no %s\n", name); return ST_NOT_IMPLEMENTED; }
    return call16(f, a);
}

/* The service table: every Nt export of the guest's ntdll that is a stub. */
static int read_services(uint64_t ntdll) {
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(uintptr_t)(ntdll + *(uint32_t*)(uintptr_t)(ntdll + 0x3C));
    IMAGE_EXPORT_DIRECTORY* e = (IMAGE_EXPORT_DIRECTORY*)(uintptr_t)(ntdll +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    uint32_t* names = (uint32_t*)(uintptr_t)(ntdll + e->AddressOfNames);
    uint16_t* ords = (uint16_t*)(uintptr_t)(ntdll + e->AddressOfNameOrdinals);
    uint32_t* fns = (uint32_t*)(uintptr_t)(ntdll + e->AddressOfFunctions);
    int n = 0;
    for (uint32_t i = 0; i < e->NumberOfNames; i++) {
        const char* nm = (const char*)(uintptr_t)(ntdll + names[i]);
        const uint8_t* b = (const uint8_t*)(uintptr_t)(ntdll + fns[ords[i]]);
        if (nm[0] != 'N' || nm[1] != 't') continue;
        if (b[0] != 0x4C || b[1] != 0x8B || b[2] != 0xD1 || b[3] != 0xB8 || b[8] != 0x0F || b[9] != 0x05) continue;
        uint32_t k = *(uint32_t*)(b + 4);
        if (k >= NSVC) continue;
        g_svc[k].name = nm;
        g_svc[k].host = host_nt(nm);
        n++;
    }
    return n;
}

static uint64_t win32k_call(CPU* c, uint32_t svc, uint64_t* a);
static uint64_t (*g_w32k)(uint32_t svc, uint64_t* a);   /* stage 3 */

void recomp_syscall64(CPU* c) {
    uint32_t n = (uint32_t)c->rax;
    uint64_t a[16];
    a[0] = c->r10, a[1] = c->rdx, a[2] = c->r8, a[3] = c->r9;
    for (int i = 4; i < 16; i++) a[i] = *(uint64_t*)(uintptr_t)(c->rsp + 8 + 8 * i);   /* [rsp+0x28] is the 5th */
    if (n >= 0x1000) { c->rax = win32k_call(c, n, a); return; }
    if (n >= NSVC || !g_svc[n].name) {
        fprintf(stderr, "[native64] service %X unknown (rip %llX)\n", n, c->rip);
        c->rax = ST_INVALID_SERVICE;
        return;
    }
    uint64_t r;
    if (g_ring_at && !strcmp(g_ring_at, g_svc[n].name)) ring_dump(g_ring_at);
    if (g_svc[n].ovr) r = g_svc[n].ovr(a);
    else if (g_svc[n].host) r = call16(g_svc[n].host, a);
    else r = ST_NOT_IMPLEMENTED;
    if (native64_trace || (!g_svc[n].ovr && !g_svc[n].host && !g_svc[n].seen))
        fprintf(stderr, "[nt] %-32s(%llX %llX %llX %llX %llX %llX %llX %llX %llX) -> %08llX%s\n", g_svc[n].name,
                a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], r, g_svc[n].ovr ? " *" : g_svc[n].host ? "" : " MISSING");
    g_svc[n].seen = 1;
    c->rax = (uint32_t)r;
}

static uint64_t win32k_call(CPU* c, uint32_t svc, uint64_t* a) {
    if (g_w32k) return g_w32k(svc, a);
    fprintf(stderr, "[win32k] service %X (rip %llX): no win32k layer\n", svc, c->rip);
    return ST_INVALID_SERVICE;
}

void recomp_int64(CPU* c, int v) {
    if (v == 0x2D) {          /* debug service: eax 1 = DbgPrint(ANSI_STRING*: rcx) */
        /* DebugPrint: rcx the text, dx its length */
        if ((uint32_t)c->rax == 1 && c->rcx && native64_trace)
            fprintf(stderr, "[dbg] %.*s", (int)(uint16_t)c->rdx, (const char*)(uintptr_t)c->rcx);
        c->rax = 0;
        return;
    }
    fprintf(stderr, "\n[native64] int %Xh at %llX (rcx %llX)\n", v, c->rip, c->rcx);
    guest_stack_dump(c);
    fflush(stderr);
    if (v == 0x29) TerminateProcess(GetCurrentProcess(), (UINT)c->rcx);
}

/* ---- faults --------------------------------------------------------------- */
static LONG CALLBACK fault(EXCEPTION_POINTERS* ep) {
    EXCEPTION_RECORD* r = ep->ExceptionRecord;
    if ((r->ExceptionCode & 0xF0000000u) != 0xC0000000u || !t_cpu) return EXCEPTION_CONTINUE_SEARCH;
    if (r->ExceptionCode == 0xC0000028u || r->ExceptionCode == 0xC0000029u) return EXCEPTION_CONTINUE_SEARCH;  /* unwinds */
    uint64_t off;
    const char* m = mod_of(t_cpu->rip, &off);
    fprintf(stderr, "\n=== host exception %08lX at %p (address %llX) in lifted %s+%llX (%llX) ===\n",
            r->ExceptionCode, r->ExceptionAddress, (unsigned long long)(r->NumberParameters > 1 ? r->ExceptionInformation[1] : 0),
            m, off, t_cpu->rip);
    guest_stack_dump(t_cpu);
    fflush(stderr);
    TerminateProcess(GetCurrentProcess(), 3);
    return EXCEPTION_CONTINUE_SEARCH;
}

/* ---- the files box -------------------------------------------------------- */
static wchar_t g_box[MAX_PATH], g_sys[MAX_PATH];

/* The NT path an OBJECT_ATTRIBUTES names, as a DOS path when it is one. */
static int oa_path(uint64_t oa, wchar_t* out, int max) {
    UNICODE_STRING* s = *(UNICODE_STRING**)(uintptr_t)(oa + 0x10);
    HANDLE root = *(HANDLE*)(uintptr_t)(oa + 8);
    int k = 0;
    out[0] = 0;
    if (root) {
        k = (int)GetFinalPathNameByHandleW(root, out, max - 2, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (k <= 0 || k >= max - 2) return 0;
        if (!wcsncmp(out, L"\\\\?\\", 4)) memmove(out, out + 4, (k - 3) * 2), k -= 4;
        if (k && out[k - 1] != L'\\') out[k++] = L'\\', out[k] = 0;
    }
    if (!s || !s->Buffer) return 1;
    int n = s->Length / 2;
    const wchar_t* p = s->Buffer;
    if (!root && n >= 4 && !wcsncmp(p, L"\\??\\", 4)) p += 4, n -= 4;
    if (k + n >= max) return 0;
    memcpy(out + k, p, n * 2);
    out[k + n] = 0;
    return 1;
}

static int under(const wchar_t* path, const wchar_t* dir) {
    size_t n = wcslen(dir);
    return !_wcsnicmp(path, dir, n) && (path[n] == 0 || path[n] == L'\\');
}

#define WRITE_ACCESS (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED)
/* Writing (or creating) is allowed only in the box; the console and the
 * null device are open to all. */
static int fb_denied(uint64_t oa, uint32_t access, uint32_t disposition) {
    wchar_t p[1024];
    int writes = (access & WRITE_ACCESS) || (disposition != 1 /* FILE_OPEN */);
    if (!writes) return 0;
    if (!oa_path(oa, p, 1024)) return 1;
    if (!_wcsicmp(p, L"CONOUT$") || !_wcsicmp(p, L"CONIN$") || !_wcsicmp(p, L"NUL") ||
        !_wcsnicmp(p, L"\\Device\\ConDrv", 14) || !_wcsicmp(p, L"\\Device\\Null")) return 0;
    if (under(p, g_box)) return 0;
    if (native64_trace) fprintf(stderr, "[box] write refused: %ls\n", p);
    return 1;
}
/* NtCreateFile(h, access, oa, iosb, size, attr, share, disposition, options, ea, ealen) */
static uint64_t ovr_create_file(uint64_t* a) {
    if (fb_denied(a[2], (uint32_t)a[1], (uint32_t)a[7])) return ST_ACCESS_DENIED;
    return native64_forward("NtCreateFile", a);
}
/* NtOpenFile(h, access, oa, iosb, share, options) */
static uint64_t ovr_open_file(uint64_t* a) {
    if (fb_denied(a[2], (uint32_t)a[1], 1)) return ST_ACCESS_DENIED;
    return native64_forward("NtOpenFile", a);
}
static uint64_t ovr_delete_file(uint64_t* a) {
    return fb_denied(a[0], DELETE, 1) ? ST_ACCESS_DENIED : native64_forward("NtDeleteFile", a);
}
/* NtSetInformationFile on a handle the box gave: renames/deletes out of the
 * box need a write-opened handle, which only the box hands out. */

/* ---- the registry box ----------------------------------------------------
 * ponytail: the guest reads the host's registry and never writes it: opens
 * are read-only, creates open, writes succeed and are dropped. A per-guest
 * hive (regbox32.c's model) when a program needs to read back what it wrote. */
#define KEY_WRITES (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL)
static uint64_t ovr_open_key(uint64_t* a) {
    uint64_t b[16];
    memcpy(b, a, sizeof b);
    if (b[1] & (MAXIMUM_ALLOWED | KEY_WRITES)) b[1] = (b[1] & ~(uint64_t)(MAXIMUM_ALLOWED | KEY_WRITES)) | KEY_READ;
    return native64_forward("NtOpenKey", b);
}
/* NtCreateKey(h, access, oa, index, class, options, disposition*) */
static uint64_t ovr_create_key(uint64_t* a) {
    uint64_t b[16] = { a[0], a[1], a[2] };
    uint64_t r = ovr_open_key(b);
    if (!r && a[6]) *(uint32_t*)(uintptr_t)a[6] = 2;   /* REG_OPENED_EXISTING_KEY */
    return r;
}
static uint64_t ovr_reg_dropped(uint64_t* a) { (void)a; return ST_SUCCESS; }
static uint64_t ovr_reg_denied(uint64_t* a) { (void)a; return ST_ACCESS_DENIED; }

/* ---- images: the lifted modules are the kernel's image sections ---------- */
#define SEC_TAG 0x4E363400u   /* fake section handles: SEC_TAG | module index << 2 */
static int sec_mod(uint64_t h) { return ((uint32_t)h & 0xFFFFFF00u) == SEC_TAG ? (int)(((uint32_t)h & 0xFF) >> 2) : -1; }

/* NtCreateSection(h, access, oa, size, protect, attributes, file) */
static uint64_t ovr_create_section(uint64_t* a) {
    if ((a[5] & SEC_IMAGE) && a[6]) {
        wchar_t p[1024];
        DWORD k = GetFinalPathNameByHandleW((HANDLE)(uintptr_t)a[6], p, 1024, FILE_NAME_NORMALIZED);
        const wchar_t* base = k ? wcsrchr(p, L'\\') : NULL;
        char nm[64];
        if (base) {
            WideCharToMultiByte(CP_ACP, 0, base + 1, -1, nm, sizeof nm, NULL, NULL);
            for (int i = 0; i < g_nmod; i++)
                if (!_stricmp(nm, g_mod[i].file)) {
                    *(HANDLE*)(uintptr_t)a[0] = (HANDLE)(uintptr_t)(SEC_TAG | i << 2);
                    return ST_SUCCESS;
                }
        }
        fprintf(stderr, "[native64] image %ls is not lifted into this host\n", k ? p : L"?");
        return 0xC0000135u;   /* STATUS_DLL_NOT_FOUND */
    }
    return native64_forward("NtCreateSection", a);
}
/* NtMapViewOfSection(section, process, base*, zerobits, commit, offset*, size*, inherit, type, protect) */
static uint64_t ovr_map_view(uint64_t* a) {
    int i = sec_mod(a[0]);
    if (i < 0) return native64_forward("NtMapViewOfSection", a);
    *(uint64_t*)(uintptr_t)a[2] = g_mod[i].base;
    if (a[6]) *(uint64_t*)(uintptr_t)a[6] = g_mod[i].size;
    return ST_SUCCESS;
}
static uint64_t ovr_unmap_view(uint64_t* a) {
    for (int i = 0; i < g_nmod; i++) if (a[1] == g_mod[i].base) return ST_SUCCESS;
    return native64_forward("NtUnmapViewOfSection", a);
}
static uint64_t ovr_close(uint64_t* a) {
    if (sec_mod(a[0]) >= 0) return ST_SUCCESS;
    return native64_forward("NtClose", a);
}
/* NtQuerySection(h, class, info, len, retlen): SectionImageInformation (1) */
static uint64_t ovr_query_section(uint64_t* a) {
    int i = sec_mod(a[0]);
    if (i < 0) return native64_forward("NtQuerySection", a);
    if (a[1] != 1) return 0xC0000003u;   /* STATUS_INVALID_INFO_CLASS */
    uint64_t b = g_mod[i].base;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(uintptr_t)(b + *(uint32_t*)(uintptr_t)(b + 0x3C));
    uint8_t* o = (uint8_t*)(uintptr_t)a[2];
    memset(o, 0, (size_t)min(a[3], 0x40));
    /* SECTION_IMAGE_INFORMATION (x64): TransferAddress, ZeroBits, MaximumStackSize,
     * CommittedStackSize, SubSystemType, SubSystemVersion, GpValue, ImageCharacteristics,
     * DllCharacteristics, Machine, ImageContainsCode, ..., LoaderFlags, ImageFileSize, CheckSum */
    *(uint64_t*)(o + 0x00) = b + nt->OptionalHeader.AddressOfEntryPoint;
    *(uint64_t*)(o + 0x10) = nt->OptionalHeader.SizeOfStackReserve;
    *(uint64_t*)(o + 0x18) = nt->OptionalHeader.SizeOfStackCommit;
    *(uint32_t*)(o + 0x20) = nt->OptionalHeader.Subsystem;
    *(uint16_t*)(o + 0x24) = nt->OptionalHeader.MinorSubsystemVersion;
    *(uint16_t*)(o + 0x26) = nt->OptionalHeader.MajorSubsystemVersion;
    *(uint16_t*)(o + 0x2C) = nt->FileHeader.Characteristics;
    *(uint16_t*)(o + 0x2E) = nt->OptionalHeader.DllCharacteristics;
    *(uint16_t*)(o + 0x30) = nt->FileHeader.Machine;
    *(uint8_t*)(o + 0x32) = 1;
    *(uint32_t*)(o + 0x3C) = nt->OptionalHeader.CheckSum;
    if (a[4]) *(uint32_t*)(uintptr_t)a[4] = 0x40;
    return ST_SUCCESS;
}
/* The host's \KnownDlls are the host's DLLs: the guest searches its path. */
static uint64_t ovr_open_directory(uint64_t* a) {
    wchar_t p[256];
    if (oa_path(a[2], p, 256) && !_wcsnicmp(p, L"\\KnownDlls", 10)) return ST_NAME_NOT_FOUND;
    return native64_forward("NtOpenDirectoryObject", a);
}
static uint64_t ovr_open_section(uint64_t* a) {
    wchar_t p[256];
    int named = oa_path(a[2], p, 256);
    if (named && !_wcsnicmp(p, L"\\KnownDlls", 10)) return ST_NAME_NOT_FOUND;
    if (named && !_wcsnicmp(p, L"\\NLS\\NlsSection", 15)) {
        /* basesrv's NLS sections: the guest's own .nls files, read-only */
        static const wchar_t* map[][2] = { { L"Unicode", L"unicode.nls" }, { L"Locale", L"locale.nls" },
            { L"CType", L"ctype.nls" }, { L"Sortkey", L"sortkey.nls" }, { L"SortTbls", L"sorttbls.nls" },
            { L"LANG_INTL", L"l_intl.nls" } };
        const wchar_t* k = p + 15, *file = NULL;
        wchar_t cp[32], path[MAX_PATH];
        for (int i = 0; i < 6; i++) if (!_wcsicmp(k, map[i][0])) file = map[i][1];
        if (!file && !_wcsnicmp(k, L"CP", 2)) _snwprintf(cp, 31, L"c_%ls.nls", k + 2), file = cp;
        if (!file) return ST_NAME_NOT_FOUND;
        _snwprintf(path, MAX_PATH - 1, L"%ls\\%ls", g_sys, file);
        HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (f == INVALID_HANDLE_VALUE) { if (native64_trace) fprintf(stderr, "[nls] %ls: missing\n", path); return ST_NAME_NOT_FOUND; }
        HANDLE s = CreateFileMappingW(f, NULL, PAGE_READONLY, 0, 0, NULL);
        CloseHandle(f);
        if (!s) return ST_NAME_NOT_FOUND;
        *(HANDLE*)(uintptr_t)a[0] = s;
        return ST_SUCCESS;
    }
    uint64_t r = native64_forward("NtOpenSection", a);
    if (native64_trace) fprintf(stderr, "[nt] NtOpenSection %ls -> %08llX\n", named ? p : L"?", r);
    return r;
}

/* The guest's thread-termination port is our csrss: nothing to register */
static uint64_t ovr_terminate_port(uint64_t* a) { (void)a; return ST_SUCCESS; }

/* ---- the process and its threads ----------------------------------------- */
static uint64_t g_teb0;
static int is_self(uint64_t h) { return h == (uint64_t)-1 || (h && GetProcessId((HANDLE)(uintptr_t)h) == GetCurrentProcessId()); }
static int is_self_thread(uint64_t h) { return h == (uint64_t)-2 || (h && GetThreadId((HANDLE)(uintptr_t)h) == GetCurrentThreadId()); }

/* NtQueryInformationProcess(h, class, info, len, retlen): the guest's PEB */
static uint64_t ovr_query_process(uint64_t* a) {
    uint64_t r = native64_forward("NtQueryInformationProcess", a);
    if (!r && a[1] == 0 && is_self(a[0]) && a[3] >= 0x30) *(uint64_t*)(uintptr_t)(a[2] + 8) = native64_peb;
    return r;
}
/* NtQueryInformationThread: ThreadBasicInformation's TebBaseAddress */
static uint64_t ovr_query_thread(uint64_t* a) {
    uint64_t r = native64_forward("NtQueryInformationThread", a);
    if (!r && a[1] == 0 && is_self_thread(a[0]) && a[3] >= 0x30) *(uint64_t*)(uintptr_t)(a[2] + 8) = g_guest_gs;
    return r;
}

/* NtContinue(CONTEXT*, alert): the thread resumes at the context, from the top */
static __declspec(thread) uint8_t t_ctx[0x4D0];
static uint64_t ovr_continue(uint64_t* a) {
    memcpy(t_ctx, (void*)(uintptr_t)a[0], sizeof t_ctx);
    longjmp(*t_top, 1);
}
static void load_context(CPU* c, const uint8_t* x) {
    const uint64_t* g = (const uint64_t*)(x + 0x78);   /* Rax..R15 */
    c->rax = g[0], c->rcx = g[1], c->rdx = g[2], c->rbx = g[3], c->rsp = g[4], c->rbp = g[5], c->rsi = g[6], c->rdi = g[7];
    c->r8 = g[8], c->r9 = g[9], c->r10 = g[10], c->r11 = g[11], c->r12 = g[12], c->r13 = g[13], c->r14 = g[14], c->r15 = g[15];
    c->rip = *(const uint64_t*)(x + 0xF8);
    eflags_unpack(c, *(const uint32_t*)(x + 0x44));
}

static uint64_t ovr_terminate_process(uint64_t* a) {
    if (is_self(a[0]) || !a[0]) {
        fflush(NULL);
        if (a[1] >= 0xC0000000u) fprintf(stderr, "\n[native64] the guest ends itself with %08llX\n", a[1]);
        if (a[0]) { fflush(stderr); ExitProcess((UINT)a[1]); }
        return ST_SUCCESS;   /* NtTerminateProcess(0): every other thread; this one goes on */
    }
    return native64_forward("NtTerminateProcess", a);
}
static uint64_t ovr_raise_exception(uint64_t* a) {
    EXCEPTION_RECORD* r = (EXCEPTION_RECORD*)(uintptr_t)a[0];
    uint64_t off;
    const char* m = mod_of((uint64_t)(uintptr_t)r->ExceptionAddress, &off);
    fprintf(stderr, "\n[native64] guest raises %08lX at %s+%llX (no guest exception dispatch yet)\n", r->ExceptionCode, m, off);
    guest_stack_dump(t_cpu);
    fflush(stderr);
    TerminateProcess(GetCurrentProcess(), 5);
    return 0;
}
static uint64_t ovr_create_thread(uint64_t* a) {
    (void)a;
    fprintf(stderr, "[native64] NtCreateThread: guest threads are not done yet\n");
    return ST_NOT_IMPLEMENTED;
}
/* The guest's DbgPrint reaches us (int 2Dh) when tracing */
static uint64_t ovr_debug_filter(uint64_t* a) { (void)a; return native64_trace ? 1 : 0; }
static uint64_t ovr_no_process(uint64_t* a) { (void)a; return ST_ACCESS_DENIED; }
static uint64_t ovr_denied(uint64_t* a) { (void)a; return 0xC0000061u; }   /* STATUS_PRIVILEGE_NOT_HELD */

/* ---- process start -------------------------------------------------------- */
static void* load_file(const wchar_t* dir, const wchar_t* name) {
    wchar_t p[MAX_PATH];
    _snwprintf(p, MAX_PATH - 1, L"%ls\\%ls", dir, name);
    p[MAX_PATH - 1] = 0;
    FILE* f = _wfopen(p, L"rb");
    if (!f) { fprintf(stderr, "[native64] %ls: missing\n", p); return NULL; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    void* d = VirtualAlloc(NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    fread(d, 1, n, f);
    fclose(f);
    return d;
}

static void ustr(uint8_t* at, const wchar_t* s, uint8_t** pool, size_t room) {
    size_t n = wcslen(s) * 2;
    if (room < n + 2) room = n + 2;
    memcpy(*pool, s, n + 2);
    *(uint16_t*)at = (uint16_t)n;
    *(uint16_t*)(at + 2) = (uint16_t)room;
    *(uint64_t*)(at + 8) = (uint64_t)(uintptr_t)*pool;
    *pool += (room + 7) & ~(size_t)7;
}

/* A TEB for this thread (x64 NT 5.2 layout) on a guest stack of its own. */
static uint64_t new_teb(uint64_t* stack_top) {
    const size_t SZ = 1 << 20;
    uint8_t* stk = (uint8_t*)VirtualAlloc(NULL, SZ, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    uint8_t* teb = (uint8_t*)VirtualAlloc(NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    *(uint64_t*)(teb + 0x08) = (uint64_t)(uintptr_t)(stk + SZ);     /* StackBase */
    *(uint64_t*)(teb + 0x10) = (uint64_t)(uintptr_t)stk;            /* StackLimit */
    *(uint64_t*)(teb + 0x30) = (uint64_t)(uintptr_t)teb;            /* Self */
    *(uint64_t*)(teb + 0x40) = GetCurrentProcessId();
    *(uint64_t*)(teb + 0x48) = GetCurrentThreadId();
    *(uint64_t*)(teb + 0x60) = native64_peb;
    *(uint32_t*)(teb + 0x108) = GetThreadLocale();                  /* CurrentLocale */
    *(uint16_t*)(teb + 0x125A) = 261 * 2;                           /* StaticUnicodeString: the import names' */
    *(uint64_t*)(teb + 0x1260) = (uint64_t)(uintptr_t)(teb + 0x1268);   /* ...StaticUnicodeBuffer */
    *(uint64_t*)(teb + 0x1478) = (uint64_t)(uintptr_t)stk;          /* DeallocationStack */
    *stack_top = (uint64_t)(uintptr_t)(stk + SZ);
    return (uint64_t)(uintptr_t)teb;
}

static const wchar_t* g_envv[] = {
    L"ALLUSERSPROFILE=%B\\All Users", L"APPDATA=%B\\User\\Application Data", L"COMPUTERNAME=PCRECOMP",
    L"ComSpec=%S\\cmd.exe", L"HOMEDRIVE=%D", L"HOMEPATH=%P\\User", L"LOGONSERVER=\\\\PCRECOMP",
    L"NUMBER_OF_PROCESSORS=1", L"OS=Windows_NT", L"Path=%S", L"PATHEXT=.COM;.EXE;.BAT;.CMD",
    L"PROCESSOR_ARCHITECTURE=AMD64", L"PROMPT=$P$G", L"SystemDrive=%D", L"SystemRoot=%R",
    L"TEMP=%B\\Temp", L"TMP=%B\\Temp", L"USERDOMAIN=PCRECOMP", L"USERNAME=User",
    L"USERPROFILE=%B\\User", L"windir=%R", NULL };

/* The guest's environment: fixed, never the host's (no host user or machine
 * names, no host paths). %S sysdir, %R its parent, %B the box, %D/%P the box's drive/path. */
static wchar_t* make_env(void) {
    wchar_t* e = (wchar_t*)VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE), *o = e;
    wchar_t root[MAX_PATH];
    wcscpy(root, g_sys);
    if (wcsrchr(root, L'\\')) *wcsrchr(root, L'\\') = 0;
    for (int i = 0; g_envv[i]; i++) {
        for (const wchar_t* s = g_envv[i]; *s; s++) {
            if (*s != L'%') { *o++ = *s; continue; }
            const wchar_t* v = NULL;
            wchar_t d[3] = { g_box[0], L':', 0 };
            switch (*++s) {
            case L'S': v = g_sys; break;
            case L'R': v = root; break;
            case L'B': v = g_box; break;
            case L'D': v = d; break;
            case L'P': v = g_box + 2; break;
            }
            wcscpy(o, v), o += wcslen(v);
        }
        *o++ = 0;
    }
    *o = 0;
    return e;
}

/* Run the thread from entry; when LdrInitializeThunk returns (its caller,
 * KiUserApcDispatcher, would NtContinue), resume at the initial context. */
static void run_thread_top(CPU* c, uint64_t entry, const uint8_t* ctx) {
    jmp_buf top;
    t_top = &top;
    if (setjmp(top)) { load_context(c, t_ctx); entry = c->rip; ctx = NULL; }
    dispatch(c, entry);
    if (ctx) { memcpy(t_ctx, ctx, sizeof t_ctx); longjmp(top, 1); }
    fprintf(stderr, "[native64] the guest thread returned to the host (rip %llX)\n", c->rip);
}

static struct { const native64_boot_t* b; uint64_t exe, ntdll; int status; } g_boot;

static DWORD WINAPI boot_thread(LPVOID unused) {
    (void)unused;
    static CPU cpu;
    CPU* c = &cpu;
    uint64_t top;
    t_cpu = c;
    g_guest_gs = g_teb0 = new_teb(&top);
    /* LdrInitializeThunk(Context: rsp+8, SystemArgument1 = ntdll's base): the
     * thread's initial CONTEXT, as the kernel queues it; it ends in
     * NtContinue(Context) to kernel32's BaseProcessStart(entry). */
    uint64_t k32 = native64_module("kernel32.dll");
    uint64_t start = k32 ? native64_export(k32, "BaseProcessStart") : 0;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(uintptr_t)(g_boot.exe + *(uint32_t*)(uintptr_t)(g_boot.exe + 0x3C));
    uint64_t entry = g_boot.exe + nt->OptionalHeader.AddressOfEntryPoint;
    uint64_t sp = (top - 0x100) & ~(uint64_t)15;
    sp -= 0x4D0;                          /* CONTEXT, 16-aligned */
    uint8_t* ctx = (uint8_t*)(uintptr_t)sp;
    memset(ctx, 0, 0x4D0);
    *(uint32_t*)(ctx + 0x30) = 0x10000B;  /* CONTEXT_FULL (AMD64) */
    *(uint32_t*)(ctx + 0x34) = 0x1F80;    /* MxCsr */
    *(uint32_t*)(ctx + 0x44) = 0x200;     /* EFlags: IF */
    *(uint64_t*)(ctx + 0x80) = entry;     /* Rcx: BaseProcessStart's argument */
    *(uint64_t*)(ctx + 0x98) = (top - 0x28) & ~(uint64_t)15 | 8;   /* Rsp, as after a call */
    *(uint64_t*)(ctx + 0xF8) = start;     /* Rip */
    c->rsp = sp - 8;
    c->rcx = sp, c->rdx = g_boot.ntdll, c->r8 = 0;
    *(uint64_t*)(uintptr_t)c->rsp = 0;
    run_thread_top(c, native64_export(g_boot.ntdll, "LdrInitializeThunk"), ctx);
    return 0;
}

int native64_boot(const native64_module_t* mods, int n, const native64_boot_t* b) {
    wchar_t p[MAX_PATH];
    native64_trace = getenv("NATIVE64_SYSCALLS") != NULL;
    g_ring_at = getenv("NATIVE64_RING_AT");
    wcsncpy(g_sys, b->sysdir, MAX_PATH - 1);
    wcsncpy(g_box, b->box, MAX_PATH - 1);
    for (int i = 0; i < n && g_nmod < MAXMODS; i++) {
        _snwprintf(p, MAX_PATH - 1, L"%ls\\%hs", b->sysdir, mods[i].file);
        if (!map_image(p, mods[i].base, &g_mod[g_nmod].size)) return 0;
        strncpy(g_mod[g_nmod].file, mods[i].file, 63);
        g_mod[g_nmod++].base = mods[i].base;
    }
    g_boot.b = b;
    g_boot.exe = mods[0].base;
    g_boot.ntdll = native64_module("ntdll.dll");
    if (!g_boot.ntdll) { fprintf(stderr, "[native64] no ntdll.dll in the module list\n"); return 0; }
    int nsvc = read_services(g_boot.ntdll);
    if (native64_trace) fprintf(stderr, "[native64] %d modules, %d services, %u lifted functions\n", g_nmod, nsvc, native64_table_count);
    AddVectoredExceptionHandler(1, fault);

    native64_override("NtCreateFile", ovr_create_file);
    native64_override("NtOpenFile", ovr_open_file);
    native64_override("NtDeleteFile", ovr_delete_file);
    native64_override("NtOpenKey", ovr_open_key);
    native64_override("NtCreateKey", ovr_create_key);
    native64_override("NtSetValueKey", ovr_reg_dropped);
    native64_override("NtDeleteValueKey", ovr_reg_dropped);
    native64_override("NtDeleteKey", ovr_reg_denied);
    native64_override("NtFlushKey", ovr_reg_dropped);
    native64_override("NtSaveKey", ovr_reg_denied);
    native64_override("NtRestoreKey", ovr_reg_denied);
    native64_override("NtLoadKey", ovr_reg_denied);
    native64_override("NtCreateSection", ovr_create_section);
    native64_override("NtMapViewOfSection", ovr_map_view);
    native64_override("NtUnmapViewOfSection", ovr_unmap_view);
    native64_override("NtClose", ovr_close);
    native64_override("NtQuerySection", ovr_query_section);
    native64_override("NtOpenDirectoryObject", ovr_open_directory);
    native64_override("NtOpenSection", ovr_open_section);
    native64_override("NtQueryInformationProcess", ovr_query_process);
    native64_override("NtQueryInformationThread", ovr_query_thread);
    native64_override("NtContinue", ovr_continue);
    native64_override("NtTerminateProcess", ovr_terminate_process);
    native64_override("NtRaiseException", ovr_raise_exception);
    native64_override("NtCreateThread", ovr_create_thread);
    native64_override("NtCreateProcess", ovr_no_process);
    native64_override("NtCreateProcessEx", ovr_no_process);
    native64_override("NtSetSystemTime", ovr_denied);
    native64_override("NtShutdownSystem", ovr_denied);
    native64_override("NtSetSystemPowerState", ovr_denied);
    native64_override("NtInitiatePowerAction", ovr_denied);
    native64_override("NtLoadDriver", ovr_denied);
    native64_override("NtUnloadDriver", ovr_denied);
    native64_override("NtSetSystemInformation", ovr_denied);
    native64_override("NtSetSystemEnvironmentValue", ovr_denied);
    native64_override("NtSetDefaultLocale", ovr_denied);
    native64_override("NtSetDefaultUILanguage", ovr_denied);
    native64_override("NtRaiseHardError", ovr_denied);
    native64_override("NtQueryDebugFilterState", ovr_debug_filter);
    native64_override("NtRegisterThreadTerminatePort", ovr_terminate_port);
    csr64_install();

    /* PEB (x64 NT 5.2): the fields the kernel fills. */
    uint8_t* peb = (uint8_t*)VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    uint8_t* pp = peb + 0x1000, *pool = peb + 0x2000;
    native64_peb = (uint64_t)(uintptr_t)peb;
    IMAGE_NT_HEADERS64* ent = (IMAGE_NT_HEADERS64*)(uintptr_t)(g_boot.exe + *(uint32_t*)(uintptr_t)(g_boot.exe + 0x3C));
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    *(uint64_t*)(peb + 0x10) = g_boot.exe;                         /* ImageBaseAddress */
    *(uint64_t*)(peb + 0x20) = (uint64_t)(uintptr_t)pp;            /* ProcessParameters */
    *(uint32_t*)(peb + 0xB8) = si.dwNumberOfProcessors;
    *(int64_t*)(peb + 0xC0) = -(int64_t)2592000 * 10000000;       /* CriticalSectionTimeout: 30 days */
    *(uint64_t*)(peb + 0xC8) = 0x100000;                           /* HeapSegmentReserve */
    *(uint64_t*)(peb + 0xD0) = 0x2000;                             /* HeapSegmentCommit */
    *(uint64_t*)(peb + 0xD8) = 0x10000;                            /* HeapDeCommitTotalFreeThreshold */
    *(uint64_t*)(peb + 0xE0) = 0x1000;                             /* HeapDeCommitFreeBlockThreshold */
    *(uint32_t*)(peb + 0xEC) = 16;                                 /* MaximumNumberOfHeaps */
    *(uint64_t*)(peb + 0xF0) = (uint64_t)(uintptr_t)(peb + 0x800); /* ProcessHeaps */
    *(uint32_t*)(peb + 0x118) = 5;                                 /* 5.2.3790: XP x64 is NT 5.2 */
    *(uint32_t*)(peb + 0x11C) = 2;
    *(uint16_t*)(peb + 0x120) = 3790;
    *(uint16_t*)(peb + 0x122) = b->csd;
    *(uint32_t*)(peb + 0x124) = 2;                                 /* VER_PLATFORM_WIN32_NT */
    *(uint32_t*)(peb + 0x128) = ent->OptionalHeader.Subsystem;
    *(uint32_t*)(peb + 0x12C) = ent->OptionalHeader.MajorSubsystemVersion;
    *(uint32_t*)(peb + 0x130) = ent->OptionalHeader.MinorSubsystemVersion;
    *(uint64_t*)(peb + 0x138) = 1;                                 /* ImageProcessAffinityMask */
    *(uint32_t*)(peb + 0x2C0) = *(volatile uint32_t*)(uintptr_t)0x7FFE02D8;   /* SessionId: the console's */

    /* The NLS tables the kernel maps into every process: the guest's own. */
    void* ansi = load_file(b->sysdir, L"c_1252.nls"), *oem = load_file(b->sysdir, L"c_437.nls"),
        *casetab = load_file(b->sysdir, L"l_intl.nls");
    if (!ansi || !oem || !casetab) return 0;
    *(uint64_t*)(peb + 0xA0) = (uint64_t)(uintptr_t)ansi;
    *(uint64_t*)(peb + 0xA8) = (uint64_t)(uintptr_t)oem;
    *(uint64_t*)(peb + 0xB0) = (uint64_t)(uintptr_t)casetab;

    /* RTL_USER_PROCESS_PARAMETERS (x64), normalized. No console of the
     * guest's own: ConsoleHandle is CONSOLE_DETACHED_PROCESS (-1) and the
     * standard handles are the host's, which the host kernel writes. */
    wchar_t cur[MAX_PATH], img[MAX_PATH];
    _snwprintf(cur, MAX_PATH - 1, L"%ls\\", b->box);
    _snwprintf(img, MAX_PATH - 1, L"%ls\\%ls", b->sysdir, b->image);
    *(uint32_t*)(pp + 0x00) = 0x1000;
    *(uint32_t*)(pp + 0x04) = 0x3F0;
    *(uint32_t*)(pp + 0x08) = 1;                                   /* RTL_USER_PROC_PARAMS_NORMALIZED */
    *(uint64_t*)(pp + 0x10) = (uint64_t)-1;                        /* ConsoleHandle */
    *(uint64_t*)(pp + 0x20) = (uint64_t)(uintptr_t)GetStdHandle(STD_INPUT_HANDLE);
    *(uint64_t*)(pp + 0x28) = (uint64_t)(uintptr_t)GetStdHandle(STD_OUTPUT_HANDLE);
    *(uint64_t*)(pp + 0x30) = (uint64_t)(uintptr_t)GetStdHandle(STD_ERROR_HANDLE);
    ustr(pp + 0x38, cur, &pool, MAX_PATH * 2);                     /* CurrentDirectory.DosPath */
    *(uint64_t*)(pp + 0x48) = (uint64_t)(uintptr_t)CreateFileW(cur, FILE_TRAVERSE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    ustr(pp + 0x50, b->sysdir, &pool, 0);                          /* DllPath */
    ustr(pp + 0x60, img, &pool, 0);                                /* ImagePathName */
    ustr(pp + 0x70, b->cmdline, &pool, 0);                         /* CommandLine */
    *(uint64_t*)(pp + 0x80) = (uint64_t)(uintptr_t)make_env();     /* Environment */
    ustr(pp + 0xB0, img, &pool, 0);                                /* WindowTitle */
    ustr(pp + 0xC0, L"WinSta0\\Default", &pool, 0);                /* DesktopInfo */
    ustr(pp + 0xD0, L"", &pool, 0);
    ustr(pp + 0xE0, L"", &pool, 0);

    /* The guest runs on a host thread with room for a deep lifted call chain. */
    HANDLE t = CreateThread(NULL, 256u << 20, boot_thread, NULL, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    WaitForSingleObject(t, INFINITE);
    DWORD code = 0;
    GetExitCodeThread(t, &code);
    return 1;
}
