/*
 * dos_compat.h - DOS API Compatibility Layer
 *
 * Replaces INT 21h DOS services, INT 10h video BIOS, INT 16h keyboard,
 * and INT 33h mouse driver with native Win32/C implementations.
 *
 * Part of the Civ Recomp project (sp00nznet/civ)
 */

#ifndef CIV_DOS_COMPAT_H
#define CIV_DOS_COMPAT_H

#include <stdio.h>

#include "recomp/cpu.h"
#include "hal/video.h"
#include "hal/input.h"
#include "hal/timer.h"

/* Maximum open file handles */
#define DOS_MAX_HANDLES 32

/* DOS file handle table */
typedef struct {
    FILE *files[DOS_MAX_HANDLES];
    int   next_handle;
} DosFileTable;

/* Callback type for pumping the platform event loop.
 * Called when the game blocks waiting for input or timer events.
 * The platform layer fills the keyboard/mouse buffers via this callback. */
typedef void (*dos_poll_fn)(void *platform_ctx, void *dos_state, const void *cpu);

/* Global DOS state */
typedef struct {
    DosFileTable    file_table;
    VideoState      video;
    KeyboardState   keyboard;
    MouseState      mouse;
    TimerState      timer;
    char            game_dir[260];  /* Path to game data files */

    /* DOS memory manager (simplified) */
    uint16_t        mem_top;        /* Top of available memory (segment) */

    /* Interrupt vector table (for get/set vector) */
    uint32_t        ivt[256];       /* seg:off packed as uint32 */

    /* Platform event loop callback (set by main.c) */
    dos_poll_fn     poll_events;
    void           *platform_ctx;   /* Opaque pointer to Platform struct */
} DosState;

/* Initialize DOS compatibility layer */
void dos_init(DosState *ds, CPU *cpu, const char *game_dir);

/* Interrupt handlers */
void dos_int21(CPU *cpu);       /* DOS API */
void bios_int10(CPU *cpu);      /* Video BIOS */
void bios_int16(CPU *cpu);      /* Keyboard BIOS */
void mouse_int33(CPU *cpu);     /* Mouse driver */
void int_handler(CPU *cpu, uint8_t num);  /* Generic interrupt */

/* Port I/O dispatch */
void port_out8(CPU *cpu, uint16_t port, uint8_t value);
uint8_t port_in8(CPU *cpu, uint16_t port);

/* Get global DOS state (stored in CPU context) */
DosState *get_dos_state(CPU *cpu);

#endif /* CIV_DOS_COMPAT_H */
