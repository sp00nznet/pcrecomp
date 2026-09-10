/*
 * crash_report.h - crash diagnostics for recompiled 32-bit programs.
 *
 * When lifted code faults, the host debugger shows you a C function called
 * sub_004A0550 somewhere inside a 900,000-line generated file, which is true and
 * useless. What you actually need is the *simulated* machine's state: which
 * lifted function was running, the register file, and the recent indirect-call
 * history that got you there.
 *
 * Install once at startup, before entering lifted code:
 *
 *     recomp_install_crash_handler();
 *
 * The handler reports and then declines to swallow the exception, so the process
 * still dies and a debugger still gets its turn. Nothing here allocates, so it
 * stays honest inside a fault.
 *
 * Part of the pcrecomp toolbox.
 */
#ifndef RECOMP_CRASH_REPORT_H
#define RECOMP_CRASH_REPORT_H

#include <stdint.h>

/* Install the vectored exception handler. Safe to call more than once. */
void recomp_install_crash_handler(void);

/* Print the simulated machine's state. Called by the handler; also useful to
 * call directly from a shim that has detected something impossible. */
void recomp_report_state(const char* why);

/* Optional: describe a simulated VA in one line (e.g. "image", "stack",
 * "heap arena"). Set it and the crash report says where a bad pointer pointed,
 * which is usually the whole diagnosis. Leave it unset and addresses print raw.
 * The callback must not allocate and must return a static string.
 */
typedef const char* (*recomp_region_fn)(uint32_t va);
void recomp_set_region_describer(recomp_region_fn fn);

/* Optional: print whatever else matters for this target -- the handful of
 * globals whose values explain a fault in its runtime. Bring-up is mostly a
 * hunt for one such value, and having it in the crash report turns a build-run
 * cycle per guess into a single run. Called at the end of every report; must not
 * allocate.
 */
typedef void (*recomp_extra_fn)(void);
void recomp_set_extra_reporter(recomp_extra_fn fn);

#endif /* RECOMP_CRASH_REPORT_H */
