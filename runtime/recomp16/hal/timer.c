/*
 * timer.c - PIT Timer Emulation Implementation
 *
 * Part of the Civ Recomp project (sp00nznet/civ)
 */

#include "hal/timer.h"
#include <string.h>

void timer_init(TimerState *ts)
{
    memset(ts, 0, sizeof(*ts));
    ts->pit_reload = 0;  /* 0 = 65536 = standard 18.2 Hz */
    ts->tick_rate_hz = DOS_TICK_HZ;
}

void timer_update(TimerState *ts, uint64_t current_ms)
{
    if (ts->start_ms == 0) {
        ts->start_ms = current_ms;
        return;
    }

    uint64_t elapsed = current_ms - ts->start_ms;
    /* Standard DOS: 18.2065 ticks per second */
    ts->tick_count = (uint32_t)(elapsed * ts->tick_rate_hz / 1000.0);
}

uint32_t timer_get_ticks(const TimerState *ts)
{
    return ts->tick_count;
}

void timer_port_write(TimerState *ts, uint16_t port, uint8_t value)
{
    static uint8_t pit_latch = 0;
    static int pit_byte = 0;

    switch (port) {
    case 0x43: /* PIT command register */
        /* Parse command: bits 7-6 = channel, 5-4 = access mode, 3-1 = mode */
        pit_latch = value;
        pit_byte = 0;
        break;

    case 0x40: /* PIT channel 0 data */
        if (pit_byte == 0) {
            ts->pit_reload = (ts->pit_reload & 0xFF00) | value;
            pit_byte = 1;
        } else {
            ts->pit_reload = (ts->pit_reload & 0x00FF) | ((uint16_t)value << 8);
            pit_byte = 0;
            /* Recalculate tick rate */
            uint32_t reload = ts->pit_reload ? ts->pit_reload : 65536;
            ts->tick_rate_hz = (double)PIT_FREQUENCY / reload;
        }
        break;
    }
}

uint8_t timer_port_read(TimerState *ts, uint16_t port)
{
    (void)ts;
    if (port == 0x40) {
        /* Return low byte of current counter (approximate) */
        return 0;
    }
    return 0;
}
