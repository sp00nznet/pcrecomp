/*
 * cmdline32: the guest's own command line (native32_set_command_line).
 *
 * A host is started with its own flags (--headless --mute ...) and the guest
 * sees them: Windows 2000's notepad tried to open "--mute --watchdog 6.txt".
 * GetCommandLineA/W answer the guest's line, and so do the host msvcrt's
 * __getmainargs/__wgetmainargs, which parsed the process's real line when the
 * CRT started (their argv is rebuilt from the guest's line; envp stays).
 * Included by native32.c; installs itself through native32_redirect.
 */
#include <shellapi.h>
#pragma comment(lib, "shell32.lib")   /* CommandLineToArgvW; no host has to list it */

static char g_cmd_a[2048];
static WCHAR g_cmd_w[2048];

static LPSTR WINAPI cl_GetCommandLineA(void) { return g_cmd_a; }
static LPWSTR WINAPI cl_GetCommandLineW(void) { return g_cmd_w; }

typedef int (__cdecl *getmainargs_t)(int*, void*, void*, int, void*);

static FARPROC crt(const char* name) {
    HMODULE h = GetModuleHandleA("msvcrt.dll");
    if (!h) h = LoadLibraryA("msvcrt.dll");
    return h ? GetProcAddress(h, name) : NULL;
}

/* argv for the guest's line, from CommandLineToArgvW, in one block that
 * lives as long as the process (as the CRT's own does). */
static void* make_argv(int* argc, int wide) {
    LPWSTR* w = CommandLineToArgvW(g_cmd_w, argc);
    size_t total = (*argc + 1) * sizeof(void*);
    for (int i = 0; i < *argc; i++) total += (wcslen(w[i]) + 1) * (wide ? 2 : 2 * 2);
    char** out = (char**)calloc(1, total);
    char* pool = (char*)(out + *argc + 1);
    for (int i = 0; i < *argc; i++) {
        out[i] = pool;
        if (wide) {
            wcscpy((wchar_t*)pool, w[i]);
            pool += (wcslen(w[i]) + 1) * 2;
        } else {
            int n = WideCharToMultiByte(CP_ACP, 0, w[i], -1, pool, (int)(wcslen(w[i]) + 1) * 2, NULL, NULL);
            pool += n;
        }
    }
    LocalFree(w);
    return out;
}

static int __cdecl cl_getmainargs(int* argc, char*** argv, char*** envp, int wildcard, void* si) {
    getmainargs_t real = (getmainargs_t)crt("__getmainargs");
    int r = real ? real(argc, argv, envp, wildcard, si) : 0;
    *argv = (char**)make_argv(argc, 0);
    return r;
}

static int __cdecl cl_wgetmainargs(int* argc, wchar_t*** argv, wchar_t*** envp, int wildcard, void* si) {
    getmainargs_t real = (getmainargs_t)crt("__wgetmainargs");
    int r = real ? real(argc, argv, envp, wildcard, si) : 0;
    *argv = (wchar_t**)make_argv(argc, 1);
    return r;
}

void native32_set_command_line(const char* line) {
    strncpy(g_cmd_a, line, sizeof g_cmd_a - 1);
    MultiByteToWideChar(CP_ACP, 0, g_cmd_a, -1, g_cmd_w, 2048);
    native32_redirect("GetCommandLineA", (void*)cl_GetCommandLineA);
    native32_redirect("GetCommandLineW", (void*)cl_GetCommandLineW);
    native32_redirect("__getmainargs", (void*)cl_getmainargs);
    native32_redirect("__wgetmainargs", (void*)cl_wgetmainargs);
}
