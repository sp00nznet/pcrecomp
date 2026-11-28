/* An emulated OPL3 (opl3.cpp, on ymfm), for the music player in mss_xmidi.c. */
#pragma once
#include <stdint.h>

#define OPL3_CLOCK 14318180u   /* a Sound Blaster's: the chip makes clock / 288 = 49716 frames a second */

#ifdef __cplusplus
extern "C" {
#endif
int  opl3_init(void);                    /* resets the chip; returns its frame rate */
void opl3_write(int reg, uint8_t v);     /* 0x000-0x1FF: both register banks */
void opl3_frame(int* left, int* right);  /* one frame of output */
#ifdef __cplusplus
}
#endif
