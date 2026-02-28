/*
 * input.h - Keyboard & Mouse Input HAL
 *
 * Replaces INT 16h (keyboard BIOS) and INT 33h (mouse driver).
 * Civilization uses mouse for unit movement and menu interaction,
 * and keyboard for shortcuts and text input.
 *
 * Part of the Civ Recomp project (sp00nznet/civ)
 */

#ifndef CIV_HAL_INPUT_H
#define CIV_HAL_INPUT_H

#include <stdint.h>

/* Keyboard state */
typedef struct {
    /* Keyboard buffer (circular) */
    uint16_t keybuf[32];    /* scancode in high byte, ASCII in low byte */
    int      head;
    int      tail;

    /* Key state array (indexed by scancode) */
    uint8_t  keystate[256];
} KeyboardState;

/* Mouse state */
typedef struct {
    int16_t  x;
    int16_t  y;
    uint16_t buttons;       /* bit 0 = left, bit 1 = right, bit 2 = middle */
    int      visible;
    int16_t  min_x, max_x;
    int16_t  min_y, max_y;
} MouseState;

void keyboard_init(KeyboardState *ks);
void mouse_init(MouseState *ms);

/* Push a keypress into the buffer */
void keyboard_push(KeyboardState *ks, uint8_t scancode, uint8_t ascii);

/* Check if key available (INT 16h AH=01) */
int keyboard_available(const KeyboardState *ks);

/* Read key (INT 16h AH=00 - blocks until available) */
uint16_t keyboard_read(KeyboardState *ks);

/* Update mouse position (called from SDL event loop) */
void mouse_update(MouseState *ms, int x, int y, uint16_t buttons);

#endif /* CIV_HAL_INPUT_H */
