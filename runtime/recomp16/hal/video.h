/*
 * video.h - VGA Mode 13h Video HAL
 *
 * Emulates the VGA 320x200 256-color framebuffer and DAC palette.
 * The original game writes directly to segment A000h (physical 0xA0000)
 * and uses port I/O (3C8h/3C9h) for palette manipulation.
 *
 * Part of the Civ Recomp project (sp00nznet/civ)
 */

#ifndef CIV_HAL_VIDEO_H
#define CIV_HAL_VIDEO_H

#include <stdint.h>

#define VGA_WIDTH   320
#define VGA_HEIGHT  200
#define VGA_FB_ADDR 0xA0000
#define VGA_FB_LEN  (VGA_WIDTH * VGA_HEIGHT)

/* VGA DAC ports */
#define VGA_DAC_WRITE_ADDR  0x3C8
#define VGA_DAC_DATA        0x3C9
#define VGA_DAC_READ_ADDR   0x3C7
#define VGA_INPUT_STATUS    0x3DA

typedef struct {
    /* 256-color palette (6-bit VGA values, 0-63) */
    uint8_t palette[256][3];    /* [index][R,G,B] */

    /* Palette port state machine */
    uint8_t dac_write_index;
    uint8_t dac_read_index;
    uint8_t dac_component;      /* 0=R, 1=G, 2=B */
    int     dac_is_write;       /* 1=writing, 0=reading */

    /* Frame dirty flag (set when framebuffer is written) */
    int dirty;

    /* VGA status register state */
    int vsync_active;
} VideoState;

/* Initialize video subsystem */
void video_init(VideoState *vs);

/* Handle port I/O writes */
void video_port_write(VideoState *vs, uint16_t port, uint8_t value);

/* Handle port I/O reads */
uint8_t video_port_read(VideoState *vs, uint16_t port);

/* Convert 6-bit VGA palette to 8-bit RGBA for display */
void video_get_rgba_palette(const VideoState *vs, uint32_t *rgba_out);

#endif /* CIV_HAL_VIDEO_H */
