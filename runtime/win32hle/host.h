/*
 * host.h - the full win32hle host: ties the PE loader (pe_loader.h) to the shim
 * layer (win32hle.h) and starts the lifted program at its entry point. A game
 * links this with its generated dispatch table and calls recomp_host_main();
 * the selftest calls the three steps directly with a synthetic image.
 */
#ifndef WIN32HLE_HOST_H
#define WIN32HLE_HOST_H
#include <stdint.h>

/* Register every shim module (kernel32, gdi32, user32). Call once, first. */
void recomp_host_init(void);

/* Map the PE at `path` and bind its IAT to the registered shims. Returns 0 on
 * success (image mapped, all imports resolved), nonzero otherwise. */
int recomp_host_boot(const char *path);

/* Like recomp_host_boot, but unresolved imports bind to a self-naming stub
 * instead of failing the boot, so recomp_host_run can proceed until the program
 * actually calls one (then it aborts naming it). The bring-up loop for a new
 * title: run, see the import it reached, implement it, repeat. */
int recomp_host_boot_permissive(const char *path);

/* Call the mapped image's entry point as lifted code (CRT startup ->
 * WinMain -> the game's message loop). Returns the guest's exit code if the
 * entry returns; a real CRT exits through ExitProcess and never comes back. */
uint32_t recomp_host_run(void);

/* The mapped image's entry VA (0 before boot), for a host that wants it. */
uint32_t recomp_host_entry(void);

/* Convenience: init + boot(argv[1]) + run. Returns the exit code, or a small
 * nonzero on a boot failure. */
int recomp_host_main(int argc, char **argv);

#endif /* WIN32HLE_HOST_H */
