/*
 * win32_compat.h - Win32 API Compatibility Layer for SoF Static Recompilation
 *
 * Maps all Win32 API calls from the original SoF v1.00 binaries to modern
 * cross-platform equivalents (SDL2) or compatibility shims.
 *
 * Original binaries import from 10 DLLs with ~275 unique API calls total.
 * This header categorizes every import and defines the replacement strategy.
 *
 * Categories:
 *   KEEP    - Works identically on modern Windows, no changes needed
 *   SHIM    - Needs thin wrapper for compatibility (version lies, path redirect)
 *   SDL2    - Replace with SDL2 equivalent for cross-platform support
 *   STUB    - Dead/obsolete functionality, stub to no-op
 *   CRT     - MSVC CRT internals, replaced by modern compiler's CRT
 */

#ifndef SOF_WIN32_COMPAT_H
#define SOF_WIN32_COMPAT_H

#include <SDL2/SDL.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <windows.h>
#endif

/* ==========================================================================
   WINSOCK ORDINAL MAP
   WSOCK32.dll imports by ordinal — map to Winsock function names
   SoF.exe only; 21 functions for UDP/IPX networking + WON SDK
   Strategy: Replace with modern Winsock2 (ws2_32) or cross-platform sockets
   ========================================================================== */

/*
 * Ordinal  Function              Category  Notes
 * -------  --------------------  --------  ---------------------------------
 *    2     bind                  SDL2      SDL_net or raw sockets
 *    3     closesocket           SDL2      SDL_net or raw sockets
 *    4     connect               SDL2      SDL_net or raw sockets
 *    6     gethostbyname         SDL2      SDL_net or getaddrinfo()
 *    9     getpeername           SDL2      Raw sockets
 *   10     getsockname           SDL2      Raw sockets
 *   12     htonl                 KEEP      Byte-order macro (endian.h)
 *   14     inet_addr             SDL2      Use getaddrinfo()
 *   15     inet_ntoa             SDL2      Use inet_ntop()
 *   16     ioctlsocket           SDL2      fcntl() on POSIX
 *   17     listen                STUB      Server-only, TCP (unused path?)
 *   19     ntohl                 KEEP      Byte-order macro
 *   20     ntohs                 KEEP      Byte-order macro
 *   21     recv                  SDL2      SDL_net or raw sockets
 *   22     recvfrom              SDL2      Core UDP receive
 *   23     select                SDL2      poll()/SDL_net
 *   52     gethostname           SDL2      Platform-specific
 *   57     htons                 KEEP      Byte-order macro
 *  111     WSAGetLastError       SDL2      errno on POSIX
 *  115     WSAStartup            SDL2      No-op on POSIX
 *  116     WSACleanup            SDL2      No-op on POSIX
 */

/* ==========================================================================
   KERNEL32.dll — 118 unique functions across all modules
   Most are standard Win32 kernel APIs that work on modern Windows.
   For cross-platform: file I/O → C stdio, threads → SDL2/pthreads
   ========================================================================== */

/* --- File I/O (KEEP on Windows, shim for cross-platform) --- */
/*
 * CreateFileA          KEEP    Still works; cross-plat: fopen/SDL_RWops
 * ReadFile             KEEP    Still works; cross-plat: fread
 * WriteFile            KEEP    Still works; cross-plat: fwrite
 * SetFilePointer       KEEP    Still works; cross-plat: fseek
 * SetEndOfFile         KEEP    Still works; cross-plat: ftruncate
 * FlushFileBuffers     KEEP    Still works; cross-plat: fflush
 * CloseHandle          KEEP    Still works; cross-plat: fclose
 * CreateDirectoryA     KEEP    Still works; cross-plat: mkdir
 * DeleteFileA          KEEP    Still works; cross-plat: remove
 * MoveFileA            KEEP    Still works; cross-plat: rename
 * FindFirstFileA       KEEP    Still works; cross-plat: opendir/readdir
 * FindNextFileA        KEEP    Still works
 * FindClose            KEEP    Still works
 * GetFullPathNameA     KEEP    Still works; cross-plat: realpath
 * GetCurrentDirectoryA KEEP    Still works; cross-plat: getcwd
 * GetTempPathA         KEEP    Still works; cross-plat: SDL_GetPrefPath
 * GetDiskFreeSpaceA    KEEP    Still works; cross-plat: statvfs
 * GetDriveTypeA        KEEP    Still works; SoF-only (CD check?)
 * GetLogicalDrives     KEEP    Still works; SoF-only
 * GetVolumeInformationA KEEP   Still works; SoF-only (CD check?)
 */

/* --- Memory Management (KEEP — standard heap APIs) --- */
/*
 * HeapCreate           KEEP    Still works; cross-plat: malloc arena
 * HeapDestroy          KEEP    Still works
 * HeapAlloc            KEEP    Still works; cross-plat: malloc
 * HeapFree             KEEP    Still works; cross-plat: free
 * HeapReAlloc          KEEP    Still works; cross-plat: realloc
 * HeapSize             KEEP    Still works
 * VirtualAlloc         KEEP    Still works; cross-plat: mmap
 * VirtualFree          KEEP    Still works; cross-plat: munmap
 * GlobalMemoryStatus   KEEP    Still works
 * GlobalLock           KEEP    Still works (clipboard support)
 * GlobalUnlock         KEEP    Still works
 * GlobalSize           KEEP    Still works
 * SetProcessWorkingSetSize KEEP Still works (memory hint)
 */

/* --- Synchronization (KEEP on Windows, SDL2 for cross-platform) --- */
/*
 * InitializeCriticalSection  KEEP  cross-plat: SDL_CreateMutex
 * EnterCriticalSection       KEEP  cross-plat: SDL_LockMutex
 * LeaveCriticalSection       KEEP  cross-plat: SDL_UnlockMutex
 * DeleteCriticalSection      KEEP  cross-plat: SDL_DestroyMutex
 * CreateEventA               KEEP  cross-plat: SDL_CreateSemaphore
 * SetEvent                   KEEP  cross-plat: SDL_SemPost
 * ResetEvent                 KEEP  cross-plat: N/A (manual reset)
 * WaitForSingleObject        KEEP  cross-plat: SDL_SemWait
 * InterlockedIncrement        KEEP  cross-plat: SDL_AtomicIncRef
 * InterlockedDecrement        KEEP  cross-plat: SDL_AtomicDecRef
 * Sleep                      KEEP  cross-plat: SDL_Delay
 */

/* --- Process/Module (KEEP — standard) --- */
/*
 * GetModuleHandleA     KEEP    Still works
 * GetModuleFileNameA   KEEP    Still works; cross-plat: SDL_GetBasePath
 * LoadLibraryA         KEEP    Still works; cross-plat: SDL_LoadObject
 * FreeLibrary          KEEP    Still works; cross-plat: SDL_UnloadObject
 * GetProcAddress       KEEP    Still works; cross-plat: SDL_LoadFunction
 * CreateProcessA       KEEP    Still works; cross-plat: fork/exec
 * ExitProcess          KEEP    Still works; cross-plat: exit()
 * TerminateProcess     KEEP    Still works
 * GetCurrentProcess    KEEP    Still works
 * GetCurrentThreadId   KEEP    Still works; cross-plat: SDL_ThreadID
 * DisableThreadLibraryCalls KEEP DLL-only, no-op in recomp
 * GetCommandLineA      KEEP    Still works; cross-plat: argc/argv
 * GetStartupInfoA      KEEP    Still works; only in CRT init
 */

/* --- Version/System Info (SHIM — needs compatibility fixes) --- */
/*
 * GetVersion           SHIM    LIES on Win10+ without manifest!
 *                              SoF checks for Win95/98/NT — return Win2000
 * GetVersionExA        SHIM    Same issue — return Win2000 (5.0)
 * GetSystemTime        KEEP    Still works
 * GetLocalTime         KEEP    Still works
 * GetTickCount         KEEP    Still works; consider QueryPerformanceCounter
 * GetSystemTimeAsFileTime KEEP Still works
 * GetSystemDirectoryA  KEEP    Still works
 */

/* --- String/Locale (CRT — handled by modern compiler) --- */
/*
 * MultiByteToWideChar  KEEP    Still works (Unicode conversion)
 * WideCharToMultiByte  KEEP    Still works
 * CompareStringA/W     CRT     MSVC CRT internal
 * GetStringTypeA/W     CRT     MSVC CRT internal
 * LCMapStringA/W       CRT     MSVC CRT internal
 * GetACP               CRT     MSVC CRT internal
 * GetOEMCP             CRT     MSVC CRT internal
 * GetCPInfo            CRT     MSVC CRT internal
 * GetLocaleInfoA/W     CRT     MSVC CRT internal
 * GetUserDefaultLCID   CRT     MSVC CRT internal
 * GetUserDefaultLangID CRT     MSVC CRT internal
 * EnumSystemLocalesA   CRT     MSVC CRT internal
 * IsValidLocale        CRT     MSVC CRT internal
 * IsValidCodePage      CRT     MSVC CRT internal
 * lstrcatA             KEEP    Still works; use strcat
 * lstrcpyA             KEEP    Still works; use strcpy
 * wsprintfA (USER32)   KEEP    Still works; use sprintf
 */

/* --- Console (KEEP — dedicated server / debug) --- */
/*
 * AllocConsole           KEEP  For dedicated server mode
 * FreeConsole            KEEP
 * GetConsoleMode         KEEP
 * SetConsoleMode         KEEP
 * GetStdHandle           KEEP
 * SetStdHandle           KEEP
 * GetNumberOfConsoleInputEvents KEEP
 * PeekConsoleInputA      KEEP
 * ReadConsoleInputA      KEEP
 * SetConsoleCtrlHandler  KEEP
 * OutputDebugStringA     KEEP  cross-plat: fprintf(stderr, ...)
 */

/* --- Error Handling (KEEP) --- */
/*
 * GetLastError                 KEEP
 * SetUnhandledExceptionFilter  KEEP  cross-plat: signal handlers
 * UnhandledExceptionFilter     KEEP
 * RaiseException               KEEP
 * RtlUnwind                    CRT   SEH internal
 * IsBadCodePtr                 KEEP  Deprecated but functional
 * IsBadReadPtr                 KEEP  Deprecated but functional
 * IsBadWritePtr                KEEP  Deprecated but functional
 */

/* --- Environment (CRT — handled by modern compiler) --- */
/*
 * GetEnvironmentStrings     CRT  MSVC CRT internal
 * GetEnvironmentStringsW    CRT  MSVC CRT internal
 * FreeEnvironmentStringsA   CRT  MSVC CRT internal
 * FreeEnvironmentStringsW   CRT  MSVC CRT internal
 * SetEnvironmentVariableA   KEEP
 * SetEnvironmentVariableW   KEEP
 * GetFileType               CRT  MSVC CRT internal
 * SetHandleCount            CRT  MSVC CRT internal (no-op since Win2000)
 * SetFileTime               KEEP
 * FileTimeToLocalFileTime   KEEP
 * FileTimeToSystemTime      KEEP
 * LocalFileTimeToFileTime   KEEP
 * SystemTimeToFileTime      KEEP
 * CompareFileTime           KEEP
 * GetTimeZoneInformation    KEEP
 */

/* ==========================================================================
   USER32.dll — 42 unique functions
   Windowing, input, and message handling → SDL2
   ========================================================================== */

/* --- Windowing (SDL2 replacement) --- */
/*
 * CreateWindowExA      SDL2    → SDL_CreateWindow
 * DestroyWindow        SDL2    → SDL_DestroyWindow
 * ShowWindow           SDL2    → SDL_ShowWindow / SDL_HideWindow
 * MoveWindow           SDL2    → SDL_SetWindowPosition + SDL_SetWindowSize
 * AdjustWindowRect     SDL2    → Not needed with SDL2 (handles decorations)
 * SetForegroundWindow  SDL2    → SDL_RaiseWindow
 * SetFocus             SDL2    → SDL_RaiseWindow
 * RegisterClassA       SDL2    → Not needed (SDL handles WNDCLASS)
 * UnregisterClassA     SDL2    → Not needed
 * DefWindowProcA       SDL2    → SDL event loop replaces message pump
 * GetWindowLongA       SDL2    → SDL_GetWindowData / internal state
 * SetWindowLongA       SDL2    → SDL_SetWindowData
 * GetWindowRect        SDL2    → SDL_GetWindowPosition + SDL_GetWindowSize
 * FindWindowA          STUB    Used to detect existing instance (single-instance check)
 */

/* --- Message Pump (SDL2 replacement) --- */
/*
 * GetMessageA          SDL2    → SDL_WaitEvent
 * PeekMessageA         SDL2    → SDL_PollEvent
 * DispatchMessageA     SDL2    → Handled within SDL event loop
 * TranslateMessage     SDL2    → Handled within SDL event loop
 * SendMessageA         SDL2    → SDL_PushEvent
 * RegisterWindowMessageA STUB  Inter-app messaging (force feedback)
 */

/* --- Input (SDL2 replacement) --- */
/*
 * GetCursorPos         SDL2    → SDL_GetMouseState / SDL_GetGlobalMouseState
 * SetCursorPos         SDL2    → SDL_WarpMouseInWindow
 * ClipCursor           SDL2    → SDL_SetWindowGrab / SDL_SetRelativeMouseMode
 * ShowCursor           SDL2    → SDL_ShowCursor
 * SetCapture           SDL2    → SDL_CaptureMouse
 * ReleaseCapture       SDL2    → SDL_CaptureMouse(SDL_FALSE)
 * GetSystemMetrics     SDL2    → SDL_GetDesktopDisplayMode (for SM_CXSCREEN/SM_CYSCREEN)
 * SystemParametersInfoA SHIM   → Used for mouse settings, can be stubbed
 * RegisterHotKey       STUB    → Alt+Enter handled in SDL event loop
 * UnregisterHotKey     STUB
 */

/* --- Display Mode (SDL2 replacement, renderer only) --- */
/*
 * ChangeDisplaySettingsA SDL2  → SDL_SetWindowFullscreen
 */

/* --- Clipboard (SDL2 replacement) --- */
/*
 * OpenClipboard        SDL2    → SDL_GetClipboardText
 * GetClipboardData     SDL2    → SDL_GetClipboardText
 * CloseClipboard       SDL2    → (automatic in SDL2)
 */

/* --- Dialogs (SDL2 replacement) --- */
/*
 * MessageBoxA          SDL2    → SDL_ShowSimpleMessageBox
 * GetActiveWindow      SDL2    → SDL_GetKeyboardFocus
 */

/* --- GDI32.dll — 4 functions (renderer only, SDL2+GL replacement) --- */
/*
 * ChoosePixelFormat    SDL2    → SDL_GL_SetAttribute + SDL_GL_CreateContext
 * SetPixelFormat       SDL2    → Handled by SDL_GL_CreateContext
 * DescribePixelFormat  SDL2    → SDL_GL_GetAttribute
 * GetDeviceCaps        SDL2    → SDL_GetDesktopDisplayMode
 */

/* --- Display (SDL2 replacement, renderer only) --- */
/*
 * GetDC                SDL2    → Not needed (SDL manages GL context)
 * ReleaseDC            SDL2    → Not needed
 * LoadCursorA          SDL2    → SDL_CreateSystemCursor
 * LoadIconA            SDL2    → SDL_SetWindowIcon
 */

/* ==========================================================================
   ADVAPI32.dll — 9 functions (registry access)
   Strategy: Redirect to INI file / SDL_GetPrefPath for portable config
   ========================================================================== */

/*
 * RegOpenKeyExA        SHIM    → Read from sof.ini in SDL_GetPrefPath
 * RegCreateKeyExA      SHIM    → Create sof.ini if missing
 * RegQueryValueExA     SHIM    → Read key=value from sof.ini
 * RegSetValueExA       SHIM    → Write key=value to sof.ini
 * RegDeleteKeyA        SHIM    → Remove section from sof.ini
 * RegDeleteValueA      SHIM    → Remove key from sof.ini
 * RegEnumKeyExA        SHIM    → Enumerate sections in sof.ini
 * RegEnumValueA        SHIM    → Enumerate keys in sof.ini section
 * RegCloseKey          SHIM    → No-op (file closed after each operation)
 *
 * Original registry path: HKLM\Software\Raven Software\SoF
 * Known keys: InstallPath, CDPath, Version, various settings
 */

/* ==========================================================================
   WINMM.dll — 7 functions
   Timer + Joystick + CD Audio → SDL2
   ========================================================================== */

/*
 * timeGetTime          SDL2    → SDL_GetTicks (1ms resolution)
 * timeBeginPeriod      SDL2    → Not needed (SDL handles timer resolution)
 * timeEndPeriod        SDL2    → Not needed
 * joyGetNumDevs        SDL2    → SDL_NumJoysticks
 * joyGetDevCapsA       SDL2    → SDL_JoystickGetDeviceGUID + properties
 * joyGetPosEx          SDL2    → SDL_JoystickGetAxis / SDL_JoystickGetButton
 * mciSendCommandA      SDL2    → SDL_mixer for CD audio tracks, or stub
 *                               SoF uses MCI for CD music playback
 */

/* ==========================================================================
   FFC10.dll — 42 functions (Immersion Feelit Force Feedback)
   Strategy: STUB everything — hardware is extinct
   ========================================================================== */

/*
 * CFeelConstant, CFeelDXDevice, CFeelMouse, CFeelPeriodic, CFeelSpring,
 * CFeelEffect, CFeelCondition, CFeelProject, CFeelDevice
 *
 * Immersion "Feelit" SDK for force feedback mice and joysticks (late 90s).
 * All 42 C++ class methods can be stubbed to return failure/no-op.
 * The engine already has graceful fallback when force feedback init fails.
 */

/* ==========================================================================
   AVIFIL32.dll — 10 functions (AVI Video Recording)
   Strategy: STUB — debug/screenshot feature, not needed for gameplay
   ========================================================================== */

/*
 * AVIFileInit          STUB    Developer screenshot/video recording
 * AVIFileExit          STUB
 * AVIFileOpenA         STUB    → return failure
 * AVIFileRelease       STUB
 * AVIFileCreateStreamA STUB
 * AVIMakeCompressedStream STUB
 * AVISaveOptions       STUB
 * AVIStreamRelease     STUB
 * AVIStreamSetFormat   STUB
 * AVIStreamWrite       STUB
 *
 * ref_gl.dll has a built-in AVI recorder (probably for marketing/QA).
 * Stubbing all to return error codes will gracefully disable the feature.
 * Could be reimplemented later with FFmpeg if desired.
 */

/* ==========================================================================
   VERSION.dll — 2 functions
   Strategy: SHIM — return canned version info
   ========================================================================== */

/*
 * GetFileVersionInfoA  SHIM    → Return SoF 1.00 version data
 * VerQueryValueA       SHIM    → Return fixed version struct
 *
 * Used to read SoF.exe's own version resource. In a recompiled build,
 * we can just return hardcoded version info (1.0.0.0).
 */

/* ==========================================================================
   ole32.dll — 3 functions (COM for DirectSound/EAX)
   Strategy: STUB — COM is only used to create DirectSound/EAX objects
   ========================================================================== */

/*
 * CoInitialize         STUB    → Return S_OK
 * CoUninitialize       STUB    → No-op
 * CoCreateInstance      STUB    → Return E_NOINTERFACE
 *
 * Used in SoF.exe for force feedback COM objects
 * Used in EAXSnd.dll / A3Dsnd.dll for DirectSound COM creation
 * SDL2 audio backend handles all of this internally
 */

/* ==========================================================================
   SoF.exe exports — 20 functions consumed by sound DLLs
   Strategy: These become direct function calls in the unified recomp binary
   ========================================================================== */

/*
 * In the original, sound DLLs (Defsnd.dll, EAXSnd.dll, A3Dsnd.dll) import
 * these 20 functions from SoF.exe at load time:
 *
 *   CL_GetEntitySoundOrigin  — 3D sound positioning
 *   Cmd_AddCommand           — Console command registration
 *   Cmd_Argc / Cmd_Argv      — Console command argument parsing
 *   Cmd_RemoveCommand         — Console command cleanup
 *   Com_DPrintf              — Debug console output
 *   Com_Error                — Fatal error handling
 *   Com_Printf               — Console output
 *   Com_sprintf               — Safe string formatting
 *   Cvar_Get                 — Console variable access
 *   FS_FCloseFile            — File system close
 *   FS_FOpenFile             — File system open
 *   FS_FreeFile              — File system memory free
 *   FS_LoadFile              — File system load-to-memory
 *   VectorLength             — 3D vector math
 *   VectorNormalize          — 3D vector math
 *   Z_Free                   — Zone memory free
 *   Z_Malloc                 — Zone memory alloc
 *   Z_Touch                  — Zone memory touch (prevent eviction)
 *   irand                    — Integer random number
 *
 * In the recompiled binary, these are just normal function calls —
 * no DLL boundary, no import table. The sound subsystem is compiled
 * directly into the engine.
 */

/* ==========================================================================
   IMPLEMENTATION — Compatibility Shims
   ========================================================================== */

/* --- Platform Abstraction Types --- */

typedef struct {
    SDL_Window      *window;
    SDL_GLContext   gl_context;
    int             fullscreen;
    int             width;
    int             height;
} sof_display_t;

typedef struct {
    int     mouse_x, mouse_y;
    int     mouse_grabbed;
    int     cursor_visible;
} sof_input_t;

typedef struct {
    char    ini_path[260];  /* Path to sof.ini config file */
    char    game_path[260]; /* Game installation directory */
    char    save_path[260]; /* User save/config directory */
} sof_paths_t;

/* --- Global State --- */
extern sof_display_t    g_display;
extern sof_input_t      g_input;
extern sof_paths_t      g_paths;

/* --- Platform Init/Shutdown --- */
int     Sys_PlatformInit(int argc, char **argv);
void    Sys_PlatformShutdown(void);

/* --- Registry → INI File Redirection --- */

/* Redirect all HKLM\Software\Raven Software\SoF to sof.ini */
int     Sys_RegReadString(const char *key, char *buf, int bufsize);
int     Sys_RegWriteString(const char *key, const char *value);
int     Sys_RegReadInt(const char *key, int *value);
int     Sys_RegWriteInt(const char *key, int value);
int     Sys_RegDeleteKey(const char *key);

/* --- Version Shim --- */

/* Return Win2000 (5.0) to match what SoF expects */
/* SoF's Qcommon_Init checks OS version to set console behavior */
typedef struct {
    uint32_t    dwMajorVersion;     /* 5 (Win2000) */
    uint32_t    dwMinorVersion;     /* 0 */
    uint32_t    dwBuildNumber;      /* 2195 */
    uint32_t    dwPlatformId;       /* 2 (VER_PLATFORM_WIN32_NT) */
} sof_osversion_t;

void    Sys_GetOSVersion(sof_osversion_t *ver);

/* --- Timer --- */

/* High-resolution timer using SDL2 — declared in qcommon.h as int */
/* uint32_t Sys_Milliseconds(void); — see qcommon.h */

/* --- Window Management (wraps SDL2) --- */

int     Sys_CreateWindow(int width, int height, int fullscreen);
void    Sys_DestroyWindow(void);
void    Sys_SetWindowTitle(const char *title);
int     Sys_SetDisplayMode(int width, int height, int fullscreen);
void    Sys_GetDesktopSize(int *width, int *height);
void    Sys_SwapBuffers(void);

/* --- Input (wraps SDL2) --- */

void    Sys_GrabMouse(int grab);
void    Sys_WarpMouse(int x, int y);
void    Sys_GetMousePos(int *x, int *y);
void    Sys_ShowCursor(int show);
void    Sys_PumpEvents(void);   /* Replaces PeekMessageA/DispatchMessageA loop */

/* --- OpenGL Context (wraps SDL2) --- */

void   *Sys_GL_GetProcAddress(const char *name);  /* Replaces wglGetProcAddress */
int     Sys_GL_SetAttribute(int attr, int value);
int     Sys_GL_MakeCurrent(void);

/* --- Message Box --- */

void    Sys_MessageBox(const char *title, const char *message, int error);

/* --- Force Feedback Stubs --- */

/* All 42 FFC10.dll functions resolve to these no-ops */
#define FEELIT_STUB_VOID()  do { } while(0)
#define FEELIT_STUB_INT()   (0)
#define FEELIT_STUB_PTR()   (NULL)

/* --- AVI Recording Stubs --- */

/* All 10 AVIFIL32 functions resolve to failure returns */
#define AVI_STUB_OK         (0)
#define AVI_STUB_FAIL       (-1)

/* --- CD Audio → SDL_mixer or Stub --- */

int     CDAudio_Init(void);
void    CDAudio_Shutdown(void);
int     CDAudio_Play(int track, int looping);
void    CDAudio_Stop(void);
void    CDAudio_Update(void);

/* ==========================================================================
   IMPORT BUDGET SUMMARY
   Total unique Win32 API calls across all SoF modules: ~275

   KEEP  (works on modern Windows as-is):           ~105 (38%)
     Mostly KERNEL32 file I/O, memory, process, sync
     These "just work" — no changes needed

   CRT   (MSVC 6.0 CRT internals, replaced by modern CRT): ~30 (11%)
     Locale, environment, string type queries
     Modern MSVC/GCC/Clang CRT handles these transparently

   SDL2  (replace with SDL2 for cross-platform):     ~55 (20%)
     All USER32 windowing/input, GDI32 pixel format,
     WINMM timers/joystick/CD audio, WSOCK32 networking

   SHIM  (thin compatibility wrapper):                ~15 (5%)
     Registry → INI file, GetVersion → hardcoded Win2000,
     SystemParametersInfo → defaults, VERSION.dll → hardcoded

   STUB  (dead functionality, no-op):                 ~70 (26%)
     FFC10.dll force feedback (42), AVIFIL32 AVI recording (10),
     ole32 COM (3), various unused paths

   The recompilation eliminates DLL boundaries entirely:
   - SoF.exe + ref_gl.dll + gamex86.dll + player.dll + sound
     become a single unified executable
   - The 20 SoF.exe exports consumed by sound DLLs become
     direct function calls
   - Game DLL (GetGameAPI) is statically linked
   - Renderer (GetRefAPI) is statically linked
   - Player model (GetPlayerClientAPI/GetPlayerServerAPI) is
     statically linked
   ========================================================================== */

#endif /* SOF_WIN32_COMPAT_H */
