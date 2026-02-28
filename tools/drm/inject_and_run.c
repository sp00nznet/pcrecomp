#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>

// Minimal version.dll injector for SafeDiscLoader2
// Creates the game process suspended, injects version.dll, resumes.

int main(int argc, char* argv[])
{
    const char* exePath = NULL;
    if (argc >= 2)
        exePath = argv[1];
    else {
        printf("Usage: inject_and_run.exe <game_exe>\n");
        printf("  Places version.dll + version.json in same dir as game_exe\n");
        return 1;
    }

    // Get directory of the target exe
    char exeDir[MAX_PATH];
    char dllPath[MAX_PATH];
    strcpy(exeDir, exePath);
    char* lastSlash = strrchr(exeDir, '\\');
    if (!lastSlash) lastSlash = strrchr(exeDir, '/');
    if (lastSlash) *(lastSlash + 1) = 0;
    else strcpy(exeDir, ".\\");

    // Build full path to version.dll
    sprintf(dllPath, "%sversion.dll", exeDir);

    if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) {
        printf("ERROR: Cannot find %s\n", dllPath);
        return 1;
    }

    // Get absolute path
    char fullDllPath[MAX_PATH];
    GetFullPathNameA(dllPath, MAX_PATH, fullDllPath, NULL);
    printf("DLL to inject: %s\n", fullDllPath);

    // Create process suspended
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    printf("Launching: %s\n", exePath);
    if (!CreateProcessA(exePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, exeDir, &si, &pi)) {
        printf("ERROR: CreateProcess failed (error %lu)\n", GetLastError());
        return 1;
    }
    printf("Process created (PID %lu), suspended.\n", pi.dwProcessId);

    // Inject version.dll via CreateRemoteThread + LoadLibraryA
    LPVOID loadLib = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, strlen(fullDllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        printf("ERROR: VirtualAllocEx failed\n");
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    WriteProcessMemory(pi.hProcess, remoteMem, fullDllPath, strlen(fullDllPath) + 1, NULL);

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLib, remoteMem, 0, NULL);
    if (!hThread) {
        printf("ERROR: CreateRemoteThread failed (error %lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    printf("Injecting version.dll...\n");
    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    printf("LoadLibrary returned: 0x%08lX %s\n", exitCode, exitCode ? "(SUCCESS)" : "(FAILED)");
    CloseHandle(hThread);

    VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);

    // Resume main thread
    printf("Resuming game process...\n");
    ResumeThread(pi.hThread);

    // Wait for the process to finish (so we can see the dump output)
    printf("Waiting for game to exit (or press Ctrl+C)...\n");
    WaitForSingleObject(pi.hProcess, INFINITE);

    GetExitCodeProcess(pi.hProcess, &exitCode);
    printf("Game exited with code %lu\n", exitCode);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
