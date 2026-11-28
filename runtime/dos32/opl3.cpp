// opl3.cpp - a Yamaha YMF262 (OPL3, the FM chip of a Sound Blaster Pro 2 and 16), emulated by
// Aaron Giles' ymfm (BSD-3-Clause, third_party/ymfm), behind a C face for mss_xmidi.c.
//
// Nothing here is timed against the guest: the chip is written and run by the music player on
// the mixer's thread, so its timers and status register are never needed.
#include "ymfm_opl.h"
#include <stdint.h>

#include "opl3.h"

namespace {
ymfm::ymfm_interface g_iface;
ymfm::ymf262* g_chip;
}

extern "C" int opl3_init(void)
{
    if (!g_chip) g_chip = new ymfm::ymf262(g_iface);
    g_chip->reset();
    return (int)g_chip->sample_rate(OPL3_CLOCK);
}

// reg 0x000-0x0FF is the first register bank, 0x100-0x1FF the second.
extern "C" void opl3_write(int reg, uint8_t v)
{
    g_chip->write((reg & 0x100) ? 2 : 0, (uint8_t)reg);
    g_chip->write((reg & 0x100) ? 3 : 1, v);
}

// One stereo frame at the chip's rate (opl3_init's): outputs A and B, the left and right.
extern "C" void opl3_frame(int* left, int* right)
{
    ymfm::ymf262::output_data o;
    g_chip->generate(&o);
    *left = o.data[0];
    *right = o.data[1];
}
