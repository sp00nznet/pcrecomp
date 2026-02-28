/*
 * timer.h - PIT Timer Emulation
 *
 * Emulates the 8253/8254 PIT (Programmable Interval Timer) that
 * drives the DOS 18.2 Hz system tick (INT 08h/1Ch).
 *
 * Part of the Civ Recomp project (sp00nznet/civ)
 */

#ifndef CIV_HAL_TIMER_H
#define CIV_HAL_TIMER_H

#include <stdint.h>

#define PIT_FREQUENCY   1193182  /* PIT oscillator frequency in Hz */
#define DOS_TICK_HZ     18.2065  /* Standard DOS timer tick rate */

typedef struct {
    uint32_t tick_count;         /* BIOS tick counter (at 0040:006C) */
    uint64_t start_ms;           /* SDL tick at init */
    uint16_t pit_reload;         /* PIT channel 0 reload value */
    double   tick_rate_hz;       /* Current effective tick rate */
} TimerState;

void timer_init(TimerState *ts);

/* Update tick count based on elapsed time */
void timer_update(TimerState *ts, uint64_t current_ms);

/* Get current tick count (for BIOS data area) */
uint32_t timer_get_ticks(const TimerState *ts);

/* PIT port I/O */
void timer_port_write(TimerState *ts, uint16_t port, uint8_t value);
uint8_t timer_port_read(TimerState *ts, uint16_t port);

#endif /* CIV_HAL_TIMER_H */
