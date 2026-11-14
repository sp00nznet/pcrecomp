/* msvceh_probe host: maps the lifted ehprobe.exe on native32 and runs it.
 * run.cmd builds and runs it; ehprobe.cpp says what each case checks. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "native32.h"
#include "recomp_trace.h"
extern const uint32_t swgb_entry_va;
recomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; return NULL; }
void recomp_not_lifted(uint32_t va) { fprintf(stderr, "not lifted %08X\n", va); ExitProcess(9); }
static LONG CALLBACK crash(EXCEPTION_POINTERS* ep) {
    if ((ep->ExceptionRecord->ExceptionCode & 0xF0000000u) != 0xC0000000u) return EXCEPTION_CONTINUE_SEARCH;
    fprintf(stderr, "fault %08lX at %p in sub_%08X ebp=%08X esp=%08X, last native %s\n", ep->ExceptionRecord->ExceptionCode,
            ep->ExceptionRecord->ExceptionAddress, g_cur_func, g_ebp, g_esp, g_cur_import);
    native32_dump_icalls(8);
    recomp_trace_flush(); ExitProcess(3);
}
int main(int argc, char** argv) {
    native32_init();
    AddVectoredExceptionHandler(0, crash);
    native32_guest_seh = 1;
    for (int i = 2; i < argc; i++) { int n = recomp_trace_arg(argc, argv, i); if (n) i += n - 1; }
    if (!native32_map(argv[1], 0x00400000u)) return 8;
    if (native32_bind(0x00400000u, NULL, 0)) return 7;
    native32_call_guest(swgb_entry_va, 0, NULL);
    return (int)g_eax;
}
