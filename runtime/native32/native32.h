/*
 * native32: a 32-bit host for lifted 32-bit Windows code (recomp32 codegen).
 *
 * The host process is 32-bit and maps the guest image 1:1 at its own base, so
 * a Win32 struct the guest builds is already the struct Windows expects, and
 * a pointer the guest holds is a pointer the host can pass on. That removes
 * the import-shim layer a 64-bit host needs:
 *
 *   guest -> Windows  native_bridge(): copy the guest's argument slots to the
 *                     host stack, call the real function, and measure how far
 *                     the callee moved esp. That distance is the purge, so no
 *                     argc table is needed: stdcall, cdecl, thiscall and COM
 *                     methods all come out right. An x87 result in st(0) is
 *                     moved onto the lifted FPU stack.
 *   Windows -> guest  The guest's code sections are mapped non-executable.
 *                     When Windows calls a guest WndProc, thread start or
 *                     hook, the fetch faults, native32_veh() moves eip to a
 *                     trampoline, and the lifted body runs on the guest stack.
 *   threads           One machine lock: a thread owns the register globals
 *                     while it runs lifted code and hands them back around
 *                     every native call. Each guest thread gets its own guest
 *                     stack and TIB on first entry.
 *
 * Extracted from gunman (Gunman Chronicles), where it runs the whole game;
 * The Movies is the second user. MSVC x86 only: the bridge is inline asm.
 *
 * A host provides: main(), recomp_lookup_manual(), and the generated dispatch
 * table. It calls native32_init(), native32_map() per module, native32_bind()
 * per module, then native32_call_guest(entry).
 */
#ifndef NATIVE32_H
#define NATIVE32_H
#include <stdint.h>
#include "recomp_types.h"

/* Optional hand-written import bodies, matched by name at bind time. A shim
 * runs inside the lifted model (reads args from g_esp, pops them itself). */
typedef struct { const char* name; recomp_func_t fn; uint32_t va; } native32_shim_t;

/* Call once, before anything else. */
void native32_init(void);

/* Map a PE at its preferred base (image_loader.c) and make its executable
 * sections non-executable, so every entry comes through the dispatch table or
 * the callback trampoline. Returns the mapped span, 0 on failure. */
uint32_t native32_map(const char* path, uint32_t base);

/* Fill a mapped module's IAT the way the Windows loader would: shims first
 * (by name), then LoadLibrary + GetProcAddress. Returns unresolved count. */
int native32_bind(uint32_t base, native32_shim_t* shims, int nshims);

/* A mapped guest module by file name ("Golf.exe", or a path ending in one;
 * case-insensitive), and one of its exports by name or ordinal; 0 if none.
 * native32_bind uses both, so a guest DLL's imports from a guest EXE land on
 * lifted code. A host uses them to shim LoadLibraryA / GetProcAddress for its
 * guest DLLs. Map every guest module before binding one that imports from it,
 * and pass every native32_bind call the same shim array. */
uint32_t native32_module(const char* name);
uint32_t native32_export(uint32_t base, const char* name);

/* Run lifted code at va to completion on this thread's guest stack. */
void native32_call_guest(uint32_t va, int nargs, const uint32_t* args);

/* The machine lock. native32_call_guest takes it; a host that touches the
 * register globals from its own threads must too. Nests. */
void mach_enter(void);
void mach_leave(void);

/* Name for a native address ("kernel32.dll!CreateFileA"), or NULL. */
const char* native32_name(uint32_t va);

/* Diagnostics: set before running. */
extern int native32_trace_native;     /* one line per native call */
extern int native32_trace_callbacks;  /* one line per Windows -> guest call */

/* Guest address ranges known to the runtime (for fault reports). */
int native32_in_guest(uint32_t va);

/* Print the last indirect calls, newest first. */
void native32_dump_icalls(int n);

#endif
