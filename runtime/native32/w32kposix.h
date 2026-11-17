/*
 * w32kposix: a win32k for a lifted Windows 2000 user32 + gdi32 on POSIX,
 * drawing into an offscreen 32-bit framebuffer (no X11, no Wine). Built on
 * ntposix.c (the NT layer) and w32klayout.c (the shared state's layouts).
 */
#ifndef W32KPOSIX_H
#define W32KPOSIX_H

/* the services, the csrss usersrv connect; fontdir holds Windows 2000's
 * sserife.fon / vgasys.fon (menus, captions, dialogs) */
void w2kx_install(int cx, int cy, const char* fontdir);
/* a script option at argv[i] (--click X,Y@T, --command ID@T, --post M,W,L@T,
 * --dlgcommand ID@T, --type ID=TEXT@T, --shot T, --secs S, --out PREFIX):
 * how many arguments it took (0: not one of them). Times are on the
 * virtual clock (ntp_clock_virtual), so a run is the same every time. */
int w2kx_script_arg(int argc, char** argv, int i);
/* after the loader: the thread becomes a GUI thread (user32's ClientThreadSetup) */
void w2kx_start(void);
/* one screen (live): a launched runner draws into the shell's X window. Before the fork the shell
 * makes the child's shared surface (a file in the scratch directory: its screen, its top-level
 * windows, the input the shell sends it); the child finds it in W2K_SHM. -1: not composited
 * (no live window here, or this process is itself a child) */
int w2kx_child(const char* path);
void w2kx_child_pid(int k, int pid);

#endif
