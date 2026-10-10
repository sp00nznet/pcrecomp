/*
 * dos32 - a DOS/4GW-style host for lifted 32-bit DOS-extender programs.
 *
 * Lifted with Lifter(dos=True), an LE program's int, in/out, cli/sti and
 * segment loads call into this host (recomp_types.h, "DOS-extender hooks").
 * It provides what DOS/4GW, DOS and the BIOS gave the program: a flat 32-bit
 * address space with conventional memory and the VGA window in it, DPMI
 * (int 31h), DOS files (int 21h), video (int 10h), keyboard (int 16h, IRQ 1,
 * port 60h), mouse (int 33h) and the timer (PIT, IRQ 0).
 *
 * Nothing here draws or plays: the platform layer (the game's host) reads the
 * screen with dos32_frame, and feeds keys and the mouse in. It runs the guest
 * on a thread of its own; dos32_* calls from other threads are safe.
 *
 * docs: pcrecomp docs/DOS32.md
 */
#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char* root;      /* host folder that is drive C: */
    const char* overlay;   /* optional: a folder laid over root for files opened
                            * read-only (mods); same layout, missing files fall
                            * through to root */
    const char* cwd;       /* DOS current directory, e.g. "\\GAME" */
    const char* progname;  /* DOS path of the program, e.g. "C:\\GAME\\MAIN.EXE" */
    const char* args;      /* command tail, without the program name */
    const uint8_t* image;  /* the relocated LE image (tools/le/le_parse.py) */
    uint32_t image_base, image_size, entry, stack;
    int log;               /* 1: log every int and unknown port to stderr */
} dos32_config;

/* Map guest memory, load the image, and run the program to its exit on the
 * calling thread. Returns the program's exit code. */
int dos32_run(const dos32_config* cfg);

/* Guest memory, for the platform layer (game-specific readers, mods). */
uint8_t* dos32_mem(uint32_t va);

/* The screen as 0x00RRGGBB pixels, at most maxw*maxh. Returns 0 while the
 * program is still in a text mode. Safe from any thread (it may tear). */
int dos32_frame(uint32_t* out, int maxw, int maxh, int* w, int* h);
int dos32_video_mode(void);

/* Input from the platform layer. scancode is a set-1 make code; extended
 * keys carry 0xE0 in bits 8-15. Mouse position is in screen pixels. */
void dos32_key(int scancode, int down);
void dos32_mouse(int x, int y, int buttons);
/* The mouse as relative motion (screen pixels, fractions kept): what a game
 * that reads motion and moves the cursor itself (int 33h AX=04h) needs, and
 * what keeps working at the edge of the screen. The host captures the
 * pointer to feed it. dos32_mouse switches back to absolute. */
void dos32_mouse_move(double dx, double dy, int buttons);

/* Pace: the guest thread calls this between frames when it waits on the
 * retrace; the platform layer may set it to throttle or to speed up. */
extern double dos32_speed;        /* 1.0 = the PIT runs at its real rate */
extern volatile int dos32_quit;   /* set to ask the program to stop */

/* Wait `seconds` of real time on the guest thread, still delivering timer,
 * keyboard and mouse interrupts: how a host paces a program that ran flat
 * out on the CPUs of its day. */
void dos32_idle(double seconds);

/* The DPMI heap (int 31h 0501h), for a host that needs to hold memory back
 * from a program that grabs all it can. 0 if there is none. */
uint32_t dos32_heap_alloc(uint32_t bytes);
void     dos32_heap_free(uint32_t va);

/* Virtual clock: guest time moves only by dos32_advance (and a fixed sliver
 * per read), never by the host's clock. For reproducible headless runs. */
extern int dos32_virtual_clock;
void dos32_advance(double seconds);

/* Called on the guest thread at every retrace the program waits for:
 * frame capture for --record, scripted input. May be NULL. */
extern void (*dos32_on_retrace)(void);

#ifdef __cplusplus
}
#endif
