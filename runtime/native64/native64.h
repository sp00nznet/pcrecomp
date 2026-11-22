/*
 * native64: a 64-bit host for a lifted 64-bit NT userland (lift64_cpu codegen).
 *
 * The 64-bit counterpart of native32's NT path (syscall32.c): the guest's
 * own ntdll, kernel32 and the rest are lifted with lift64_cpu, mapped 1:1 at
 * their own bases in a 64-bit host process, and run on the host's kernel. A
 * pointer the guest holds is a pointer the host can pass on, and an x64
 * guest structure is the host's structure, so the boundary is the one the
 * hardware has: the `syscall` instruction in ntdll's (and user32/gdi32's)
 * stubs. Each service is answered by name: the number is read from the
 * guest's own ntdll at start and matched to the host ntdll's export of that
 * name, with overrides where the host's answer would leak the host (its PEB,
 * its KnownDlls, its registry and files) or where the kernel's job is the
 * host's (image sections of lifted modules, the thread's NtContinue).
 *
 * The guest has its own PEB and a TEB per thread (cpu64.h RECOMP_GUEST_GS):
 * gs: in lifted code is the guest TEB, never the host's.
 *
 * A host provides main() and the generated table (native64_table); it calls
 * native64_boot() with the module list.
 */
#ifndef NATIVE64_H
#define NATIVE64_H
#include <stdint.h>
#include "cpu64.h"

typedef struct { uint64_t va; void (*fn)(CPU*); } native64_entry_t;
extern const native64_entry_t native64_table[];   /* sorted by va (tools: lift64.py) */
extern const unsigned native64_table_count;

typedef struct { const char* file; uint64_t base; } native64_module_t;

/* A service handler: a[0..15] are the arguments (r10, rdx, r8, r9, then the
 * stack's), the result is the NTSTATUS. */
typedef uint64_t (*native64_syscall_fn)(uint64_t* a);
void native64_override(const char* name, native64_syscall_fn fn);
uint64_t native64_forward(const char* name, uint64_t* a);   /* the host's service */

typedef struct {
    const wchar_t* sysdir;     /* the guest's modules and NLS files (absolute) */
    const wchar_t* box;        /* the only folder the guest may write (absolute) */
    const wchar_t* image;      /* the program, under sysdir */
    const wchar_t* cmdline;
    uint16_t csd;              /* service pack << 8 */
} native64_boot_t;

/* Map the modules at their bases, build the PEB, the process parameters and
 * the first thread, and run the guest's LdrInitializeThunk; returns the exit
 * status (the guest's NtTerminateProcess ends the host first, normally). */
int native64_boot(const native64_module_t* mods, int n, const native64_boot_t* b);

uint64_t native64_export(uint64_t base, const char* name);
uint64_t native64_module(const char* file);  /* a lifted module's base, or 0 */
const wchar_t* native64_sysdir(void);        /* the guest's system folder */
extern uint64_t native64_peb;
extern int native64_trace;                        /* NATIVE64_SYSCALLS=1 */

/* Run guest code at va on this thread's CPU with up to 4 arguments. */
uint64_t native64_call(uint64_t va, int n, const uint64_t* args);

/* Answer a guest function (its entry va) with a host one, in the lifted model. */
void native64_replace(uint64_t va, void (*fn)(CPU*));

/* win32k: names for the guest's service numbers ("0xNNNN Name" lines; 0 if
 * the file is missing), and a handler by name. */
int native64_win32k_names(const char* file);
void native64_w32k(const char* name, native64_syscall_fn fn);

/* csr64.c: \Windows\ApiPort answered here */
void csr64_install(void);
void w32k64_install(void);   /* w32k64.c: the first win32k services */
#endif
