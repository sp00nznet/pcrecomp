/*
 * bda_kbd.h - the BIOS keyboard buffer, kept where the BIOS keeps it.
 *
 * DOS games read the keyboard three ways: INT 16h, INT 21h, and straight from
 * the BIOS data area, where the BIOS's INT 9 leaves each key:
 *
 *   0040:0017  shift flags (bit 0 right shift, 1 left shift, 2 ctrl, 3 alt,
 *              4 scroll, 5 num, 6 caps, 7 insert lock)
 *   0040:001A  head: offset (from 0040:0000) of the next key to read
 *   0040:001C  tail: where the next key goes
 *   0040:001E  the buffer, 16 words (scan << 8 | ascii) up to 003D
 *   0040:0080  buffer start, 0040:0082 buffer end (AT BIOS: the bounds a
 *              program may have moved)
 *
 * MechWarrior's BTECH reads keys from head..tail itself; MW_MAIN's INT 9 hook
 * empties the buffer by setting tail = head. A runtime that keeps keys in a
 * private queue breaks both. Use these for INT 9's store and INT 16h's reads
 * and the guest sees the real thing. Header-only; mem is the 1 MB guest image.
 *
 *   bda_kbd_init(mem)                 at boot
 *   bda_kbd_push(mem, scan, ascii)    INT 9 stored a key (0: buffer full)
 *   bda_kbd_peek(mem, &key)           INT 16h/01: 1 if a key is waiting
 *   bda_kbd_pop(mem, &key)            INT 16h/00
 *   bda_kbd_flush(mem)
 *
 *   cc -DBDA_KBD_SELFTEST -x c bda_kbd.h -o t && ./t
 */
#ifndef RECOMP16_BDA_KBD_H
#define RECOMP16_BDA_KBD_H
#include <stdint.h>

#define BDA_KBD_FLAGS  0x417
#define BDA_KBD_HEAD   0x41A
#define BDA_KBD_TAIL   0x41C
#define BDA_KBD_START  0x480
#define BDA_KBD_END    0x482

static inline uint16_t bda_kbd_rd(const uint8_t *mem, uint32_t a) { return (uint16_t)(mem[a] | mem[a + 1] << 8); }
static inline void bda_kbd_wr(uint8_t *mem, uint32_t a, uint16_t v) { mem[a] = (uint8_t)v; mem[a + 1] = (uint8_t)(v >> 8); }

static inline void bda_kbd_init(uint8_t *mem)
{
    bda_kbd_wr(mem, BDA_KBD_START, 0x1E);
    bda_kbd_wr(mem, BDA_KBD_END, 0x3E);
    bda_kbd_wr(mem, BDA_KBD_HEAD, 0x1E);
    bda_kbd_wr(mem, BDA_KBD_TAIL, 0x1E);
}

/* the buffer's bounds, as the guest has them (or the defaults if unset) */
static inline void bda_kbd_bounds(const uint8_t *mem, uint16_t *lo, uint16_t *hi)
{
    *lo = bda_kbd_rd(mem, BDA_KBD_START); *hi = bda_kbd_rd(mem, BDA_KBD_END);
    if (*lo < 0x1E || *hi <= *lo || *hi > 0x100 || ((*hi - *lo) & 1)) { *lo = 0x1E; *hi = 0x3E; }
}

static inline uint16_t bda_kbd_next(const uint8_t *mem, uint16_t p)
{
    uint16_t lo, hi;
    bda_kbd_bounds(mem, &lo, &hi);
    p = (uint16_t)(p + 2);
    return p >= hi ? lo : p;
}

static inline int bda_kbd_push(uint8_t *mem, uint8_t scan, uint8_t ascii)
{
    uint16_t t = bda_kbd_rd(mem, BDA_KBD_TAIL), n = bda_kbd_next(mem, t);
    if (n == bda_kbd_rd(mem, BDA_KBD_HEAD)) return 0;            /* full: the BIOS beeps */
    bda_kbd_wr(mem, 0x400u + t, (uint16_t)(scan << 8 | ascii));
    bda_kbd_wr(mem, BDA_KBD_TAIL, n);
    return 1;
}

static inline int bda_kbd_peek(const uint8_t *mem, uint16_t *key)
{
    uint16_t h = bda_kbd_rd(mem, BDA_KBD_HEAD);
    if (h == bda_kbd_rd(mem, BDA_KBD_TAIL)) return 0;
    *key = bda_kbd_rd(mem, 0x400u + h);
    return 1;
}

static inline int bda_kbd_pop(uint8_t *mem, uint16_t *key)
{
    if (!bda_kbd_peek(mem, key)) return 0;
    bda_kbd_wr(mem, BDA_KBD_HEAD, bda_kbd_next(mem, bda_kbd_rd(mem, BDA_KBD_HEAD)));
    return 1;
}

static inline void bda_kbd_flush(uint8_t *mem)
{
    bda_kbd_wr(mem, BDA_KBD_HEAD, bda_kbd_rd(mem, BDA_KBD_TAIL));
}

#ifdef BDA_KBD_SELFTEST
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void)
{
    static uint8_t mem[0x500];
    uint16_t k;
    bda_kbd_init(mem);
    assert(!bda_kbd_peek(mem, &k));
    assert(bda_kbd_push(mem, 0x1C, 0x0D) && bda_kbd_push(mem, 0x48, 0));
    assert(bda_kbd_peek(mem, &k) && k == 0x1C0D);                 /* peek leaves it */
    assert(mem[0x41E] == 0x0D && mem[0x41F] == 0x1C);              /* where the BIOS puts it */
    assert(bda_kbd_pop(mem, &k) && k == 0x1C0D);
    assert(bda_kbd_pop(mem, &k) && k == 0x4800 && !bda_kbd_pop(mem, &k));
    /* 15 keys fit in 16 slots; the 16th is refused; the ring wraps */
    int n = 0;
    while (bda_kbd_push(mem, 0x1E, 'a')) n++;
    assert(n == 15);
    for (int i = 0; i < 15; i++) assert(bda_kbd_pop(mem, &k) && k == 0x1E61);
    assert(bda_kbd_push(mem, 0x39, ' ') && bda_kbd_pop(mem, &k) && k == 0x3920);
    /* a program emptying it the MW_MAIN way: tail = head */
    bda_kbd_push(mem, 0x10, 'q');
    memcpy(mem + BDA_KBD_TAIL, mem + BDA_KBD_HEAD, 2);
    assert(!bda_kbd_peek(mem, &k));
    /* the guest reading it the BTECH way: word at 0040:[head], head += 2, wrap at [82h] */
    bda_kbd_push(mem, 0x2C, 'z');
    uint16_t h = bda_kbd_rd(mem, BDA_KBD_HEAD);
    assert(bda_kbd_rd(mem, 0x400 + h) == 0x2C7A);
    puts("bda_kbd: ok");
    return 0;
}
#endif
#endif
