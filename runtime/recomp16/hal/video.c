/*
 * video.c - VGA Mode 13h Video HAL Implementation
 *
 * Emulates the VGA 320x200 256-color mode used by Civilization.
 * Handles DAC palette manipulation via port I/O (3C8h/3C9h)
 * and tracks framebuffer dirty state for efficient rendering.
 *
 * Part of the Civ Recomp project (sp00nznet/civ)
 */

#include "hal/video.h"
#include <string.h>
#include <stdio.h>

void video_init(VideoState *vs)
{
    memset(vs, 0, sizeof(*vs));

    /* Set up default VGA palette (standard 256-color) */
    /* First 16 colors: standard CGA/EGA colors */
    static const uint8_t default_16[16][3] = {
        { 0, 0, 0}, { 0, 0,42}, { 0,42, 0}, { 0,42,42},
        {42, 0, 0}, {42, 0,42}, {42,21, 0}, {42,42,42},
        {21,21,21}, {21,21,63}, {21,63,21}, {21,63,63},
        {63,21,21}, {63,21,63}, {63,63,21}, {63,63,63},
    };
    memcpy(vs->palette, default_16, sizeof(default_16));

    /* Gray ramp for entries 16-31 */
    for (int i = 0; i < 16; i++) {
        uint8_t v = (uint8_t)(i * 63 / 15);
        vs->palette[16 + i][0] = v;
        vs->palette[16 + i][1] = v;
        vs->palette[16 + i][2] = v;
    }
}

void video_port_write(VideoState *vs, uint16_t port, uint8_t value)
{
    switch (port) {
    case VGA_DAC_WRITE_ADDR:
        vs->dac_write_index = value;
        vs->dac_component = 0;
        vs->dac_is_write = 1;
        break;

    case VGA_DAC_READ_ADDR:
        vs->dac_read_index = value;
        vs->dac_component = 0;
        vs->dac_is_write = 0;
        break;

    case VGA_DAC_DATA:
        if (vs->dac_is_write) {
            vs->palette[vs->dac_write_index][vs->dac_component] = value & 0x3F;
            vs->dac_component++;
            if (vs->dac_component >= 3) {
                vs->dac_component = 0;
                vs->dac_write_index++;
                vs->dirty = 1;
            }
        }
        break;

    default:
        /* Ignore other VGA register writes for now */
        break;
    }
}

uint8_t video_port_read(VideoState *vs, uint16_t port)
{
    switch (port) {
    case VGA_DAC_DATA:
        if (!vs->dac_is_write) {
            uint8_t val = vs->palette[vs->dac_read_index][vs->dac_component];
            vs->dac_component++;
            if (vs->dac_component >= 3) {
                vs->dac_component = 0;
                vs->dac_read_index++;
            }
            return val;
        }
        return 0;

    case VGA_INPUT_STATUS:
        /* Toggle vsync bit to prevent infinite wait loops */
        vs->vsync_active ^= 1;
        return vs->vsync_active ? 0x08 : 0x00;

    default:
        return 0;
    }
}

void video_get_rgba_palette(const VideoState *vs, uint32_t *rgba_out)
{
    for (int i = 0; i < 256; i++) {
        uint8_t r = (uint8_t)(vs->palette[i][0] * 255 / 63);
        uint8_t g = (uint8_t)(vs->palette[i][1] * 255 / 63);
        uint8_t b = (uint8_t)(vs->palette[i][2] * 255 / 63);
        rgba_out[i] = (r << 0) | (g << 8) | (b << 16) | (0xFFu << 24);
    }
}
