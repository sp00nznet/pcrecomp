/*
 * ns_runtime.h - host runtime for lifted NeXTSTEP 3.x (i386) applications.
 *
 * The app and its fixed-VM shared libraries (libsys, libNeXT, ...) are mapped
 * into one guest address space at their original VAs, so everything the lifted
 * code reads -- its own data, a shlib's globals (_iob, errno, NXApp), a branch
 * table slot, the ObjC metadata of every AppKit class -- is real.
 *
 * Nothing in a shlib is lifted. A call to a shlib address (a branch-table slot,
 * or a method IMP that objc_msgSend found) reaches recomp_lookup_import, which
 * names the address from the shlib's own symbol table ("_printf",
 * "-[Window display]") and binds it to the host shim registered under that
 * name. An address with no shim binds to a stub that reports its name once --
 * the to-do list writes itself.
 *
 * Shim ABI (cdecl, as the guest calls it): on entry g_esp points at the dummy
 * return address RECOMP_ICALL pushed, arguments follow. A shim returns through
 * NS_RET, which sets eax and pops that return address like the `ret` it
 * replaces.
 *
 * Part of the pcrecomp toolbox.
 */
#ifndef NS_RUNTIME_H
#define NS_RUNTIME_H

#include <stdint.h>
#include "recomp_types.h"

#define ARG(n)    MEM32(g_esp + 4 + 4 * (n))
#define ARGF(n)   MEMF(g_esp + 4 + 4 * (n))
#define ARGD(n)   MEMD(g_esp + 4 + 4 * (n))          /* a double occupies ARG(n), ARG(n+1) */
#define GUEST(va)  ((void *)ADDR(va))
#define GSTR(va)  ((char *)ADDR(va))
#define NS_RET(v) do { g_eax = (uint32_t)(v); g_esp += 4; } while (0)
/* A double comes back in st(0), as gcc's i386 ABI returns it. */
#define NS_RETD(v) do { g_fp_top = (g_fp_top - 1) & 7; g_st[g_fp_top] = (v); g_esp += 4; } while (0)

typedef struct { const char *name; recomp_func_t fn; } ns_shim_t;

/* Add shims to the name table. Call before ns_run; later tables win. */
void ns_register(const ns_shim_t *shims);

/* Guest heap. */
uint32_t ns_malloc(uint32_t n);
uint32_t ns_calloc(uint32_t n);
uint32_t ns_realloc(uint32_t va, uint32_t n);
void     ns_free(uint32_t va);
uint32_t ns_strdup(const char *s);

/* A shlib symbol's VA (e.g. "_NXApp"), 0 if no loaded lib defines it. */
uint32_t ns_sym(const char *name);
/* The symbol at exactly `va`, or NULL. */
const char *ns_sym_at(uint32_t va);

/* Every section of every mapped image named seg,sect (e.g. "__OBJC",
 * "__class"), app first. Returns the count written to `addr`/`size`. */
int ns_sections(const char *seg, const char *sect, uint32_t *addr, uint32_t *size, int max);

/* Guest path -> host path: an absolute guest path is taken relative to the
 * root passed to ns_run. Returns a static buffer. */
const char *ns_host_path(const char *guest);

/* The app's bundle directory as a guest path (the app's directory, relative
 * to the root). */
const char *ns_bundle_dir(void);

/* Run a lifted value on the guest stack: call the lifted (or bridged) function
 * at `va` with `n` 32-bit args, cdecl. Returns eax. */
uint32_t ns_call(uint32_t va, int n, const uint32_t *args);

/* Map the app (fat or thin Mach-O) and every LC_LOADFVMLIB it names (looked up
 * by basename in shlib_dir), build the guest stack as the kernel does, and
 * enter crt0. `root` is where absolute guest paths resolve. Does not return. */
void ns_run(const char *app, const char *shlib_dir, const char *root, int argc, char **argv);

extern int g_ns_trace;   /* NS_TRACE set: log imports and messages */

/* Subsystems ns_run initialises; each registers its own shims. */
void ns_libc_init(void);
void ns_objc_init(void);      /* after mapping: links every class it finds */
void ns_appkit_init(void);

/* ObjC entry points shared between subsystems. */
uint32_t ns_sel(const char *name);                    /* canonical SEL, interned */
uint32_t ns_class(const char *name);                  /* class object, 0 if none */
uint32_t ns_send(uint32_t self, const char *sel, int n, const uint32_t *args);
uint32_t ns_alloc_instance(uint32_t cls);

#endif
