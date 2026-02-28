/*
 * input.c - Keyboard & Mouse Input HAL Implementation
 *
 * Part of the Civ Recomp project (sp00nznet/civ)
 */

#include "hal/input.h"
#include <string.h>

void keyboard_init(KeyboardState *ks)
{
    memset(ks, 0, sizeof(*ks));
}

void mouse_init(MouseState *ms)
{
    memset(ms, 0, sizeof(*ms));
    ms->max_x = 319;
    ms->max_y = 199;
    ms->visible = 0;
}

void keyboard_push(KeyboardState *ks, uint8_t scancode, uint8_t ascii)
{
    int next = (ks->tail + 1) % 32;
    if (next == ks->head) return;  /* buffer full */
    ks->keybuf[ks->tail] = ((uint16_t)scancode << 8) | ascii;
    ks->tail = next;
    ks->keystate[scancode] = 1;
}

int keyboard_available(const KeyboardState *ks)
{
    return ks->head != ks->tail;
}

uint16_t keyboard_read(KeyboardState *ks)
{
    /* Non-blocking read: returns 0 if no key available.
     * For blocking behavior, the caller should loop with event pumping. */
    if (ks->head == ks->tail) return 0;
    uint16_t key = ks->keybuf[ks->head];
    ks->head = (ks->head + 1) % 32;
    uint8_t sc = (uint8_t)(key >> 8);
    ks->keystate[sc] = 0;
    return key;
}

void mouse_update(MouseState *ms, int x, int y, uint16_t buttons)
{
    ms->x = (int16_t)x;
    ms->y = (int16_t)y;
    ms->buttons = buttons;

    /* Clamp to range */
    if (ms->x < ms->min_x) ms->x = ms->min_x;
    if (ms->x > ms->max_x) ms->x = ms->max_x;
    if (ms->y < ms->min_y) ms->y = ms->min_y;
    if (ms->y > ms->max_y) ms->y = ms->max_y;
}
