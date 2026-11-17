/*
 * ntposix: a lifted Windows NT userland on Linux (or any POSIX host), no
 * Wine. The POSIX counterpart of syscall32.c + csr32.c + the parts of
 * native32.c a lifted ntdll needs. Built with gcc -m32: guest addresses are
 * host addresses (RECOMP_FLAT_MEMORY). See win2000's docs/linux.md.
 *
 *   ntp_init();
 *   ntp_mount("C:\\WINNT\\system32", "/x/sys");  ntp_mount("C:", "/x/root");
 *   ntp_map("/x/sys/ntdll.dll", 0x20000000, "ntdll.dll"); ...
 *   ntp_syscalls(0x20000000);
 *   ntp_boot(...);  ntp_call(entry, 0, NULL);
 */
#ifndef NTPOSIX_H
#define NTPOSIX_H
#include <stdint.h>
#include "recomp_types.h"

void ntp_init(void);
/* guest path prefix ("C:", "C:\\WINNT\\system32") -> host directory; longest wins */
void ntp_mount(const char* guest, const char* host);
void ntp_regbox(const char* file);   /* the registry box: loaded from and saved to this file only */
/* map a (rebased) PE at its base as a lifted module; name is what the loader asks for */
uint32_t ntp_map(const char* path, uint32_t base, const char* name);
uint32_t ntp_export(uint32_t base, const char* name);
int ntp_syscalls(uint32_t ntdll);
/* \NLS\NlsSectionXxx -> host file */
void ntp_section_file(const char* name, const char* file);
/* the kernel's half of process start, then the guest ntdll's LdrInitializeThunk */
int ntp_boot(uint32_t ntdll, uint32_t exe, const char* image, const char* cmdline,
             const char* dllpath, const char* curdir, const char* nls_dir, uint16_t csd);
void ntp_call(uint32_t va, int nargs, const uint32_t* args);
void ntp_replace(uint32_t va, recomp_func_t fn);
/* a host C function in the shim ABI ([ret][args] at g_esp, pops 4 + 4*argc) */
typedef struct { const char* name; int argc; recomp_func_t fn; } ntp_stub_t;
/* a DLL the guest may load that is answered by host stubs */
void ntp_proxy(const char* dll, const ntp_stub_t* stubs, int n);
uint32_t ntp_alloc(uint32_t size);   /* committed guest memory */
uint32_t ntp_module(const char* name);   /* a mapped module's base (0: none) */
uint32_t ntp_peb(void);

/* win32k: services from 0x1000, numbered by the guest's user32/gdi32 stubs,
 * named from a "0xNNNN Name" file; answered by name (w32kposix.c) */
int ntp_win32k(const uint32_t* bases, int nbases, const char* names_file);
void ntp_win32k_override(const char* name, uint32_t (*fn)(uint32_t*));
extern void (*ntp_win32k_pre)(void);      /* before every win32k service */
/* win32k's user-mode callback: KiUserCallbackDispatcher(api, in, len) */
uint32_t ntp_callback(uint32_t api, uint32_t in, uint32_t len, uint32_t* out, uint32_t* outlen);
/* a guest stdcall function called from a service, registers kept: its eax */
uint32_t ntp_guest(uint32_t va, int nargs, const uint32_t* args);
/* csrss ClientConnect for a server other than consrv (usersrv is 3) */
extern void (*ntp_csr_connect)(uint32_t index, uint32_t info, uint32_t len);

/* the virtual clock: the guest's tick count, time and sleeps move only by
 * ntp_clock_advance (and the guest's own sleeps), so scripted runs repeat */
void ntp_clock_virtual(void);
void ntp_clock_advance(uint32_t ms);
uint32_t ntp_clock_ms(void);
void ntp_yield(void);   /* let the other guest threads run (an idle loop) */

#endif
