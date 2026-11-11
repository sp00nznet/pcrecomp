/*
 * sdl2lite backend: PlayStation 3 (PSL1GHT). The RSX display buffers are
 * CPU-writable XRGB8888, the game draws at the display's size (720p, or
 * 960x540 doubled at 1080p). Audio: 48 kHz float blocks, filled from the
 * 44.1 kHz mixer on the main thread. Pad 1: Cross jump, Start pause,
 * Select restart, R1 turbo. The XMB's quit ends the game.
 * The rsx setup is the one in linksawakening-portable's platform_psl1ght.c.
 */
#include "SDL.h"
#include <malloc.h>
#include <unistd.h>
#include <ppu-types.h>
#include <sys/process.h>
#include <lv2/systime.h>
#include <rsx/rsx.h>
#include <sysutil/video.h>
#include <sysutil/sysutil.h>
#include <io/pad.h>
#include <audio/audio.h>

SYS_PROCESS_PARAM(1001, 0x100000)

#define CB_SIZE 0x100000
#define HOST_SIZE (32 * 1024 * 1024)
#define LABEL 255

static gcmContextData *context;
static u32 width, height, pitch, offset[2], depth_offset, depth_pitch, cur, first = 1, label = 1;
static u32 *buffer[2];

static void set_target(u32 i) {
    gcmSurface sf;
    memset(&sf, 0, sizeof sf);
    sf.colorFormat = GCM_TF_COLOR_X8R8G8B8;
    sf.colorTarget = GCM_TF_TARGET_0;
    sf.colorLocation[0] = sf.colorLocation[1] = sf.colorLocation[2] = sf.colorLocation[3] = GCM_LOCATION_RSX;
    sf.colorOffset[0] = offset[i];
    sf.colorPitch[0] = pitch;
    sf.colorPitch[1] = sf.colorPitch[2] = sf.colorPitch[3] = 64;
    sf.depthFormat = GCM_TF_ZETA_Z16;
    sf.depthLocation = GCM_LOCATION_RSX;
    sf.depthOffset = depth_offset;
    sf.depthPitch = depth_pitch;
    sf.type = GCM_TF_TYPE_LINEAR;
    sf.antiAlias = GCM_TF_CENTER_1;
    sf.width = width;
    sf.height = height;
    rsxSetSurface(context, &sf);
}

static void sysutil_cb(u64 status, u64 param, void *ud) {
    (void)param; (void)ud;
    if (status == SYSUTIL_EXIT_GAME) {
        SDL_Event e;
        memset(&e, 0, sizeof e);
        e.type = SDL_QUIT;
        lite_push_event(&e);
    }
}

int lite_video_init(int *w, int *h) {
    videoState state;
    videoResolution res;
    videoConfiguration vcfg;
    int i;
    context = rsxInit(CB_SIZE, HOST_SIZE, memalign(1024 * 1024, HOST_SIZE));
    videoGetState(0, 0, &state);
    videoGetResolution(state.displayMode.resolution, &res);
    memset(&vcfg, 0, sizeof vcfg);
    vcfg.resolution = state.displayMode.resolution;
    vcfg.format = VIDEO_BUFFER_FORMAT_XRGB;
    vcfg.pitch = res.width * 4;
    /* wait for the RSX to go idle before reconfiguring */
    rsxSetWriteBackendLabel(context, LABEL, label);
    rsxSetWaitLabel(context, LABEL, label);
    label++;
    rsxSetWriteBackendLabel(context, LABEL, label);
    rsxFlushBuffer(context);
    while (*(vu32 *)gcmGetLabelAddress(LABEL) != label) usleep(30);
    label++;
    videoConfigure(0, &vcfg, NULL, 0);
    gcmSetFlipMode(GCM_FLIP_VSYNC);
    width = res.width; height = res.height; pitch = width * 4;
    for (i = 0; i < 2; i++) {
        buffer[i] = rsxMemalign(64, height * pitch);
        rsxAddressToOffset(buffer[i], &offset[i]);
        gcmSetDisplayBuffer(i, offset[i], pitch, width, height);
    }
    depth_pitch = width * 4;
    rsxAddressToOffset(rsxMemalign(64, height * depth_pitch * 2), &depth_offset);
    set_target(cur);
    sysUtilRegisterCallback(SYSUTIL_EVENT_SLOT0, sysutil_cb, NULL);
    ioPadInit(7);
    *w = (int)width; *h = (int)height;
    return 0;
}

void lite_video_present(const Uint32 *px, int w, int h) {
    if (w != (int)width || h != (int)height) return;
    memcpy(buffer[cur], px, (size_t)h * pitch);
    if (!first) while (gcmGetFlipStatus() != 0) usleep(200);
    gcmResetFlipStatus();
    gcmSetFlip(context, cur);
    rsxFlushBuffer(context);
    gcmSetWaitFlip(context);
    cur ^= 1;
    set_target(cur);
    first = 0;
}

static int audio_ok;
static u32 port;
static audioPortConfig acfg;
static u64 block = 1, made;   /* made: 48 kHz frames written so far */

int lite_audio_start(void) {
    audioPortParam p;
    if (audioInit() != 0) return -1;
    p.numChannels = AUDIO_PORT_2CH;
    p.numBlocks = AUDIO_BLOCK_8;
    p.attrib = 0;
    p.level = 1.0f;
    if (audioPortOpen(&p, &port) != 0 || audioGetPortConfig(port, &acfg) != 0) return -1;
    audioPortStart(port);
    audio_ok = 1;
    return 0;
}

/* fill every block up to the hardware's read position */
static void audio_pump(void) {
    static Sint16 in[2 * (AUDIO_BLOCK_SAMPLES + 2)];
    u64 hw;
    if (!audio_ok) return;
    hw = *(u64 *)(u64)acfg.readIndex;
    while (block != hw) {
        float *blk = (float *)(u64)acfg.audioDataStart + 2 * AUDIO_BLOCK_SAMPLES * block;
        u64 from = made * 44100 / 48000, to = (made + AUDIO_BLOCK_SAMPLES) * 44100 / 48000;
        int n = (int)(to - from), i;
        lite_audio_mix(in, n);
        for (i = 0; i < AUDIO_BLOCK_SAMPLES; i++) {
            int s = (int)((made + i) * 44100 / 48000 - from);
            if (s >= n) s = n - 1;
            blk[i * 2] = in[s * 2] / 32768.0f;
            blk[i * 2 + 1] = in[s * 2 + 1] / 32768.0f;
        }
        made += AUDIO_BLOCK_SAMPLES;
        block = (block + 1) % AUDIO_BLOCK_8;
    }
}

Uint32 lite_ticks(void) { return (Uint32)(sysGetSystemTime() / 1000); }
void lite_sleep(Uint32 ms) { audio_pump(); usleep(ms * 1000); }

void lite_poll(void) {
    static Uint32 buttons;
    static Sint16 lx, ly;
    padInfo pi;
    padData pd;
    sysUtilCheckCallback();
    audio_pump();
    ioPadGetInfo(&pi);
    if (pi.status[0] && ioPadGetData(0, &pd) == 0 && pd.len > 0) {   /* len 0: nothing changed */
        buttons = (pd.BTN_CROSS ? 1u << SDL_CONTROLLER_BUTTON_A : 0) |
                  (pd.BTN_CIRCLE ? 1u << SDL_CONTROLLER_BUTTON_B : 0) |
                  (pd.BTN_SQUARE ? 1u << SDL_CONTROLLER_BUTTON_X : 0) |
                  (pd.BTN_TRIANGLE ? 1u << SDL_CONTROLLER_BUTTON_Y : 0) |
                  (pd.BTN_SELECT ? 1u << SDL_CONTROLLER_BUTTON_BACK : 0) |
                  (pd.BTN_START ? 1u << SDL_CONTROLLER_BUTTON_START : 0) |
                  (pd.BTN_L1 ? 1u << SDL_CONTROLLER_BUTTON_LEFTSHOULDER : 0) |
                  (pd.BTN_R1 ? 1u << SDL_CONTROLLER_BUTTON_RIGHTSHOULDER : 0) |
                  (pd.BTN_UP ? 1u << SDL_CONTROLLER_BUTTON_DPAD_UP : 0) |
                  (pd.BTN_DOWN ? 1u << SDL_CONTROLLER_BUTTON_DPAD_DOWN : 0) |
                  (pd.BTN_LEFT ? 1u << SDL_CONTROLLER_BUTTON_DPAD_LEFT : 0) |
                  (pd.BTN_RIGHT ? 1u << SDL_CONTROLLER_BUTTON_DPAD_RIGHT : 0);
        lx = (Sint16)(((int)pd.ANA_L_H - 128) * 256);
        ly = (Sint16)(((int)pd.ANA_L_V - 128) * 256);
    }
    lite_pad(buttons, lx, ly);
}
