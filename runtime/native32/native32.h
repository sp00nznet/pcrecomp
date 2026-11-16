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
 * runs inside the lifted model (reads args from g_esp, pops them itself).
 * An import by ordinal is matched by "<dll>#<ordinal>" ("DPLAY.dll#2"), the
 * DLL compared without regard to case. */
typedef struct { const char* name; recomp_func_t fn; uint32_t va; } native32_shim_t;

/* Run the guest in another ANSI code page than the system's (932 for a
 * Japanese title on a Western Windows): CP_ACP in MultiByteToWideChar and the
 * A functions that take text read the guest's strings in it (codepage.c).
 * Call before native32_bind. 0 (the default) leaves the system's. */
void native32_set_codepage(unsigned cp);

/* Bind every import of this name, and every GetProcAddress for it, to a
 * native function of the host's (same signature, called by the bridge like
 * the real one). For DLLs the guest loads itself, which a shim by import
 * name never sees. Call before native32_bind; up to 32. */
void native32_redirect(const char* name, void* fn);

/* The guest's command line ("winmine.exe -x"), not the host's flags:
 * GetCommandLineA/W and the host msvcrt's __getmainargs/__wgetmainargs
 * answer it (cmdline32.c). Call before native32_bind; uses 4 redirects. */
void native32_set_command_line(const char* line);

/* Serve the registry subtrees a .reg file names (regedit 4: [HKEY_...\path]
 * sections, "name"="text", dword:, hex:) from that file instead of the real
 * registry: the guest's RegOpenKey/RegCreateKey/RegQueryValueEx/RegSetValueEx
 * (A, Ex) on keys inside them read and write a copy, saved back to the file
 * on every change. A Win9x game finds what its installer wrote there, and
 * nothing needs administrator rights. Call before native32_bind (it uses
 * native32_redirect). Returns the number of subtrees, 0 if the file is
 * missing or names none (reg32.c). */
int native32_registry(const char* file);

/* Keep the guest's network on this machine (net32.c): connect and sendto
 * only to 127/8, bind INADDR_ANY as 127.0.0.1, gethostbyname answers only
 * localhost names. For old network programs run only against a local
 * server. Call before native32_bind. */
void native32_net_loopback_only(void);

/* Give the guest its own registry (regbox32.c), under
 * HKCU\Software\pcrecomp\sandbox\<name> (or \pcrecomp\<name> when name has a
 * backslash): its Reg* imports (A and W) and profile calls write there and
 * read there first, then the real registry read-only; it can never write the
 * real one. Two instances with two names keep apart. Call before
 * native32_bind; 0 if the key can't be made. */
int native32_registry_sandbox(const char* name);
/* The same for a lifted ntdll's NtXxxKey services and a proxied host
 * advapi32: pass native32_nt_override, native32_nt_forward and
 * native32_nt_proxy_hook (before native32_nt_boot). */
void native32_registry_sandbox_nt(void (*ovr)(const char*, uint32_t (*)(uint32_t*)),
                                  uint32_t (*fwd)(const char*, uint32_t*), void (*hook)(const char*, void*));
/* A REG_SZ the guest's own box holds under HKCU\sub (never the real
 * registry's): 1 and the text in out, 0 if there is no box or no value. */
int native32_registry_box_sz(const wchar_t* sub, const wchar_t* value, wchar_t* out, unsigned long cch);
/* A sandbox replacement by its export name (WriteProfileStringW...), or NULL. */
void* native32_registry_sandbox_fn(const char* name);

/* Call once, before anything else. */
void native32_init(void);

/* Keep a guest image's range free from process start. The process's first
 * thread stack (its /STACK reserve), heaps and the locale files are placed
 * bottom-up before main() runs; with a 16 MB /STACK the stack alone is at
 * 0x00400000-0x01400000, so an image based there either fails to map or is
 * committed into the stack's own reservation. In the launching process this
 * starts the host again suspended, reserves [base, base + the image's
 * SizeOfImage) in it before its loader runs, resumes it and exits with its
 * exit code; the child (in a kill-on-close job, so it dies with the launcher)
 * gets 1 back and maps the image into the reservation. Returns 0 if the
 * range could not be held; the caller then maps as before.
 * The host's /STACK must be small (256 KB) so the child's first stack fits
 * below base: run the lifted code on a thread with a large stack. */
int native32_hold_image(const char* path, uint32_t base);

/* Give this process a 16-bit (or 8-bit) DirectDraw. On a 32-bit desktop
 * DirectDraw enumerates and sets only 32-bit modes, so a game that wants
 * 640x480x16 fails at startup. Windows' "reduced color mode" compatibility
 * layer (__COMPAT_LAYER=16BITCOLOR / 256COLOR) emulates them, but it is read
 * at process start: so this runs the host again with it set, waits, and
 * returns the child's exit code for main() to return. Returns -1 when no
 * relaunch happened (already the child, bpp not 8/16, or CreateProcess
 * failed): carry on. The child is marked by PCRECOMP_COLOR_CHILD, since
 * Windows strips __COMPAT_LAYER from the environment the child sees; without
 * that marker the child would relaunch itself forever. Call it before
 * native32_init(), and only on the path that runs the game. */
int native32_require_color_depth(int bpp);

/* Map a PE at its preferred base (image_loader.c) and make its executable
 * sections non-executable, so every entry comes through the dispatch table or
 * the callback trampoline. Returns the mapped span, 0 on failure. */
uint32_t native32_map(const char* path, uint32_t base);

/* Fill a mapped module's IAT the way the Windows loader would: shims first
 * (by name, or "<dll>#<ordinal>"), then LoadLibrary + GetProcAddress. A shim named
 * "<dll>!<name>" ("NTDLL.DLL!CsrClientCallServer", DLL any case) also replaces
 * that export of a GUEST module; a plain name never does. Returns unresolved count. */
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
/* Give up every level of the machine around a host call that may wait on
 * another guest thread; put the same count back after. */
int mach_release(void);
void mach_reacquire(int n);

/* A lifted function answered by the host instead, wherever its address is
 * resolved (indirect calls, snapped imports); and a built-in shim by name.
 * A lifted ntdll's RtlUnwind ends in NtContinue, a resume the lift cannot
 * make; native32_nt_boot puts the seh32 one in its place. */
void native32_replace(uint32_t va, recomp_func_t fn);
recomp_func_t native32_shim(const char* name);

/* Name for a native address ("kernel32.dll!CreateFileA"), or NULL. */
const char* native32_name(uint32_t va);

/* Run a mapped module's ORIGINAL machine code instead of its lift: its code
 * is made executable again and every call into it from lifted code goes
 * through the native bridge, while its own calls out (imports, vtables) still
 * reach the lifted modules through the callback trampoline. For bisecting a
 * lift bug to one module: if the output is right with module X native, the
 * bug is in X's lift. Call after native32_map, before running. 0 if base is
 * not a mapped module. */
int native32_set_native(uint32_t base);

/* The finer step of the same bisection: these functions of a native module
 * run lifted after all. Each entry is patched with ud2, and the trap goes
 * through the callback trampoline to the lifted body. Returns how many were
 * lifted entries (the rest are skipped). */
int native32_lift_in_native(const uint32_t* vas, int n);

/* Code the guest writes at run time (a software renderer compiling its span
 * loops) cannot be lifted, so it runs natively, and it is entered with the
 * guest's whole register file, not the C ABI: eax..edi, ebp and the MMX
 * registers are loaded before the call and read back after, on the guest's
 * own stack. Memory the guest makes executable outside its modules
 * (VirtualAlloc or VirtualProtect with an execute protection) is registered
 * by the built-in shims; a host can add a range itself. */
void native32_add_generated(uint32_t lo, uint32_t size);
/* The same entry (the guest's stack and whole integer register file) for
 * compiled code that is not the C ABI but uses the x87 like C does: a
 * language runtime whose helpers read the caller's frame through ebp and move
 * esp (CA-Visual Objects' CAVORT20: _NCARG, __chkstk). The MMX registers are
 * not carried, and a float returned in st(0) goes onto the lifted FPU stack. */
void native32_add_guest_abi(uint32_t lo, uint32_t size);
int native32_is_generated(uint32_t va);

/* Code a Windows DLL builds in heap memory and jumps to: Direct3D's RGB
 * software rasteriser (d3dim/d3dim700) compiles its span loops into
 * HeapAlloc'd memory. A 1998 process could run that; this host is /NXCOMPAT
 * (the callback trampoline needs DEP), so the fetch faults. After this call,
 * an execute fault in committed private read-write memory outside the guest
 * makes that region executable and retries. Off by default: a wild jump into
 * the heap then still faults where it happened. Shogo, Unreal Tournament
 * (Galaxy's mixers) and KISS Psycho Circus need it. */
void native32_allow_heap_code(void);

/* Run this process again on a desktop of its own that is never shown, and
 * wait for it: windows, DirectDraw and Direct3D work there (software
 * rendering), but nothing reaches the user's screens, over RDP or not. Call
 * first thing in main(); it returns the child's exit code, or -1 in the child
 * (and on failure), which then carries on. SendInput and the foreground
 * window still belong to the user's desktop: a harness that drives the game
 * must post messages to its window instead, or it types into the user's
 * session. The child finds NATIVE32_HEADLESS set in its environment. */
int native32_headless(void);
/* Guest SEH (seh32.c): a guest exception is dispatched over the guest's own
 * fs:[0] chain, and RtlUnwind unwinds it. A handler that takes an exception
 * continues in its frame's function by a jump the lift cannot follow into a
 * body further up the host stack; the host patches that jump (Delphi's
 * _HandleAnyException `jmp ebx`) into this, which resumes at va inside the
 * function that registered the frame RtlUnwind last stopped at. That function
 * needs a landing pad (generate.py eh_resume). */
void native32_seh_continue(uint32_t va);
extern int native32_guest_seh;   /* 1: RaiseException goes to the guest chain */
/* A Visual Basic 5/6 guest on the real MSVBVM60/50 (vb6rt.c): the runtime is
 * entered with the guest's registers and stack, and its runtime errors go to
 * the guest's On Error handling. Call after native32_bind. 1 if set up. */
int native32_vb6_runtime(void);
extern uint32_t native32_fs_mirror_lo, native32_fs_mirror_hi;   /* vb6rt.c sets them */

/* The guest's frames as it presents them: cb gets the surface blitted to the
 * primary (a windowed game) or the primary after a Flip, and its interface
 * version (1, 4 or 7: the DDSURFACEDESC Lock wants). For screenshots and
 * recordings under native32_headless, where a GDI copy of the window is
 * black. Runs on the guest's thread, inside its present. */
void native32_on_present(void (*cb)(void* surface, int version));

/* Synthetic DirectInput (dinput32.c): every system mouse and keyboard the
 * guest creates reads its state from these calls instead of the hardware, so
 * a harness can drive a game that polls DirectInput. On by default under
 * native32_headless, where real devices cannot be acquired; dx/dy/dz add up
 * until the next GetDeviceState; b is the button (0 left), dik a DIK_ code. */
void native32_input_synthetic(int on);
void native32_input_mouse(int dx, int dy, int dz);
void native32_input_button(int b, int down);
void native32_input_key(int dik, int down);

/* A look at every Windows -> guest call (a window procedure, a hook, ...):
 * in, at the guest stack's copy of its arguments before it runs; out, at
 * them and its result after. A filter may change both. */
extern void (*native32_cb_in)(uint32_t* args);
extern void (*native32_cb_out)(uint32_t* args, uint32_t* eax);

/* Diagnostics: set before running. */
extern int native32_trace_native;     /* one line per native call */
extern int native32_trace_callbacks;  /* one line per Windows -> guest call */

/* Guest address ranges known to the runtime (for fault reports). */
int native32_in_guest(uint32_t va);

/* Print the last indirect calls, newest first. */
void native32_dump_icalls(int n);

/* ---- modules32.c: the loader's part for several lifted modules ----------
 * Map each (rebased, tools/pe/rebase.py) module from map_dir at its base;
 * GetModuleFileName reports report_dir\<name>. Bind all of them with the
 * host's shims plus LoadLibrary{A,W,ExA}, FreeLibrary, GetProcAddress,
 * GetModuleHandle{A,W} and GetModuleFileName{A,W} over the table (a host
 * shim of the same name wins). A guest DLL is attached (DllMain, after the
 * guest modules it imports) when something loads it; attach_imports does
 * that for everything a module imports, before entering it. */
typedef struct { const char* name; uint32_t base; int attached; } native32_module_t;
int native32_modules_map(const char* map_dir, const char* report_dir, native32_module_t* m, int n);
int native32_modules_bind(const native32_shim_t* host, int nhost);   /* unresolved count */
int native32_attach(uint32_t base);
int native32_attach_imports(uint32_t base);
native32_module_t* native32_module_by_name(const char* path);
native32_module_t* native32_module_by_base(uint32_t base);

/* ---- syscall32.c: a lifted Windows NT userland on the host's kernel ------
 * The guest's own ntdll (and kernel32 ... on it) is lifted like any module;
 * its system call gate (int 2Eh, lifted to recomp_syscall) is the only
 * boundary. The service numbers are the guest ntdll's own, read from its
 * NtXxx export stubs (mov eax, N; ...; int 2Eh; ret 4*argc), so the table
 * needs no symbols; a backend maps each service by NAME to the host (on
 * Windows: the host ntdll's export of that name, with per-service fixups).
 *
 *   native32_modules_map(...)        every guest module, NOT bound: the
 *                                    guest's own loader snaps the imports
 *   native32_nt_syscalls(ntdll)
 *   native32_nt_boot(...)            the kernel's part of process creation,
 *                                    then the guest ntdll's LdrInitializeThunk
 *                                    (heap, NLS, loader lists, imports, DllMains)
 *   native32_call_guest(entry)
 *
 * The kernel's part: a PEB and process parameters, the NLS tables, image
 * sections (a lifted module's view is its mapping; a host DLL is a proxy
 * image of its exports; anything else is refused, and so is process
 * creation: no original binary runs natively), \KnownDlls hidden, and csrss
 * over its LPC port (csr32.c). NATIVE32_SYSCALLS=1 traces every call. */
extern uint32_t native32_guest_peb;
extern int native32_guest_loaded;
int native32_nt_syscalls(uint32_t ntdll_base);
typedef uint32_t (*native32_syscall_fn)(uint32_t* args);
void native32_nt_override(const char* name, native32_syscall_fn fn);
uint32_t native32_nt_forward(const char* name, uint32_t* args);
/* dll_path: the loader's search path (the guest modules' directory first,
 * then the host's system directory for proxies). csd: the service pack, as
 * PEB's OSCSDVersion (0x0400 for SP4). Returns 0 on failure. */
int native32_nt_boot(uint32_t ntdll, uint32_t exe, const wchar_t* image_path, const wchar_t* cmdline,
                     const wchar_t* dll_path, const char* nls_dir, uint16_t csd);
/* win32k (services 0x1000..): numbers and argument counts from the guest's
 * own user32/gdi32 stubs, names from a "0xNNNN Name" file. Unanswered
 * services are logged and return 0; a host answers by name. */
int native32_nt_win32k(const uint32_t* bases, int nbases, const char* names_file);
void native32_nt_win32k_override(const char* name, native32_syscall_fn fn);
/* Called before every win32k service, as win32k flushes GDI's TEB batch on entry. */
extern void (*native32_win32k_pre)(void);
/* A user-mode callback, as win32k makes one (KeUserModeCallback): the guest
 * ntdll's KiUserCallbackDispatcher runs KernelCallbackTable[api](in, len);
 * returns its status, and the NtCallbackReturn output. */
uint32_t native32_nt_callback(uint32_t api, uint32_t in, uint32_t len, uint32_t* out, uint32_t* outlen);
/* A host function in place of a host DLL's export in its proxy image (same
 * signature): a host notes what the guest gets from the host's DLLs. */
void native32_nt_proxy_hook(const char* name, void* fn);
/* w32kgdi.c: GDI's shared state for a lifted gdi32 on host GDI (see there). */
void native32_gdi_install(void);
int native32_gdi_start(uint32_t gdi32_base);   /* GdiDllInitialize, when user32 is the host's */
/* w32kuser.c: USER's half, for a lifted user32 (with w32kgdi). */
void native32_user_install(void);
uint8_t* native32_user_wnd(void* hwnd);   /* the Windows 2000 WND user32 sees for a host window */
extern uint8_t* native32_user_psi;   /* csr32.c: SERVERINFO, Windows 2000 layout */
extern uint8_t* native32_user_ahe;   /* csr32.c: the USER handle table */
extern uint8_t* native32_user_disp;  /* csr32.c: DISPLAYINFO */
uint32_t native32_gdi_handle(uint32_t host_handle);   /* -> the guest's handle */
uint32_t native32_gdi_host(uint32_t guest_handle);     /* -> the host's, 0 if none */
uint8_t* native32_gdi_attr(uint32_t hdc);
/* a guest DC as the host's, its attributes applied and the TEB batch flushed (void*: an HDC) */
void* native32_gdi_dc(uint32_t hdc);
/* A named section the guest opens that a server process of its own OS would
 * have created (csrss's \NLS\NlsSection* for kernel32): NtOpenSection on
 * that name returns a read-only section of the file. */
void native32_nt_section_file(const wchar_t* name, const wchar_t* file);
/* csr32.c: csrss for the guest, at its LPC port. A handler for an api
 * ((server << 16) | api) gets the message's data (msg + 0x28) and capture
 * buffer and returns the status; unanswered apis are logged and succeed. */
typedef uint32_t (*native32_csr_api_fn)(uint32_t data, uint32_t capture);
void native32_csr_api(uint32_t number, native32_csr_api_fn fn);

#endif
