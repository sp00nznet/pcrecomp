/*
 * sdl2lite: the slice of SDL2 SkiFree's lite build uses, in software,
 * for consoles whose toolchains have no SDL2 (PS3, Dreamcast, Xbox 360).
 * One 32-bit framebuffer is the window; a tiny per-platform backend
 * (backend_*.c) shows it, reads the pad, plays audio and keeps time.
 * Only what the game calls is here; the rest is left out on purpose.
 */
#ifndef SDL2LITE_SDL_H
#define SDL2LITE_SDL_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

typedef uint8_t Uint8;   typedef int8_t Sint8;
typedef uint16_t Uint16; typedef int16_t Sint16;
typedef uint32_t Uint32; typedef int32_t Sint32;
typedef uint64_t Uint64; typedef int64_t Sint64;
typedef enum { SDL_FALSE = 0, SDL_TRUE = 1 } SDL_bool;

#define SDL_LIL_ENDIAN 1234
#define SDL_BIG_ENDIAN 4321
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define SDL_BYTEORDER SDL_BIG_ENDIAN
#else
#define SDL_BYTEORDER SDL_LIL_ENDIAN
#endif

/* stdinc */
#define SDL_zero(x) memset(&(x), 0, sizeof(x))
#define SDL_malloc malloc
#define SDL_free free
#define SDL_memcpy memcpy
#define SDL_snprintf snprintf
size_t SDL_strlcpy(char *dst, const char *src, size_t maxlen);

/* init, errors, time */
#define SDL_INIT_TIMER 0x01u
#define SDL_INIT_AUDIO 0x10u
#define SDL_INIT_VIDEO 0x20u
#define SDL_INIT_GAMECONTROLLER 0x2000u
int SDL_Init(Uint32 flags);
const char *SDL_GetError(void);
Uint32 SDL_GetTicks(void);
typedef int SDL_TimerID;   /* declared by data.h, never used */
void SDL_Delay(Uint32 ms);

/* rects, colors, pixel formats */
typedef struct SDL_Rect { int x, y, w, h; } SDL_Rect;
typedef struct SDL_Color { Uint8 r, g, b, a; } SDL_Color;
typedef struct SDL_Palette { int ncolors; SDL_Color *colors; } SDL_Palette;
typedef struct SDL_PixelFormat {
    Uint32 format;
    SDL_Palette *palette;
    Uint8 BitsPerPixel, BytesPerPixel;
    Uint32 Rmask, Gmask, Bmask, Amask;
    Uint8 Rshift, Gshift, Bshift, Ashift;
} SDL_PixelFormat;

#define SDL_PIXELFORMAT_INDEX8   0x13000801u
#define SDL_PIXELFORMAT_ARGB8888 0x16362004u
#define SDL_PIXELFORMAT_RGBA8888 0x16462004u
#define SDL_PIXELFORMAT_ABGR8888 0x16762004u
#if SDL_BYTEORDER == SDL_BIG_ENDIAN
#define SDL_PIXELFORMAT_RGBA32 SDL_PIXELFORMAT_RGBA8888
#else
#define SDL_PIXELFORMAT_RGBA32 SDL_PIXELFORMAT_ABGR8888
#endif

typedef enum { SDL_BLENDMODE_NONE = 0, SDL_BLENDMODE_BLEND = 1 } SDL_BlendMode;

/* surfaces: 8-bit indexed (from BMPs) or 32-bit with any masks */
typedef struct SDL_Surface {
    Uint32 flags;
    SDL_PixelFormat *format;
    int w, h, pitch;
    void *pixels;
    /* sdl2lite's own */
    int has_key; Uint32 key;
    SDL_BlendMode blend;
} SDL_Surface;

SDL_Surface *SDL_CreateRGBSurface(Uint32 flags, int w, int h, int depth, Uint32 R, Uint32 G, Uint32 B, Uint32 A);
SDL_Surface *SDL_CreateRGBSurfaceWithFormat(Uint32 flags, int w, int h, int depth, Uint32 format);
SDL_Surface *SDL_CreateRGBSurfaceWithFormatFrom(void *pixels, int w, int h, int depth, int pitch, Uint32 format);
void SDL_FreeSurface(SDL_Surface *s);
int SDL_FillRect(SDL_Surface *s, const SDL_Rect *r, Uint32 color);
int SDL_BlitSurface(SDL_Surface *src, const SDL_Rect *srcrect, SDL_Surface *dst, SDL_Rect *dstrect);
int SDL_SetColorKey(SDL_Surface *s, int flag, Uint32 key);
int SDL_SetSurfaceBlendMode(SDL_Surface *s, SDL_BlendMode mode);
Uint32 SDL_MapRGB(const SDL_PixelFormat *f, Uint8 r, Uint8 g, Uint8 b);
Uint32 SDL_MapRGBA(const SDL_PixelFormat *f, Uint8 r, Uint8 g, Uint8 b, Uint8 a);

/* RWops: memory only */
typedef struct SDL_RWops { const Uint8 *base; size_t size, pos; } SDL_RWops;
SDL_RWops *SDL_RWFromConstMem(const void *mem, int size);
int SDL_RWclose(SDL_RWops *rw);
SDL_Surface *SDL_LoadBMP_RW(SDL_RWops *rw, int freesrc);

/* window and renderer: one of each, the console's screen */
typedef struct SDL_Window SDL_Window;
typedef struct SDL_Renderer SDL_Renderer;
typedef struct SDL_Texture SDL_Texture;
typedef struct SDL_RendererInfo { const char *name; Uint32 flags; } SDL_RendererInfo;
#define SDL_WINDOWPOS_CENTERED 0x2FFF0000
#define SDL_WINDOW_FULLSCREEN 0x1u
#define SDL_WINDOW_SHOWN 0x4u
#define SDL_WINDOW_RESIZABLE 0x20u
#define SDL_WINDOW_FULLSCREEN_DESKTOP 0x1001u
#define SDL_TEXTUREACCESS_STATIC 0
#define SDL_TEXTUREACCESS_STREAMING 1
SDL_Window *SDL_CreateWindow(const char *title, int x, int y, int w, int h, Uint32 flags);
void SDL_DestroyWindow(SDL_Window *w);
Uint32 SDL_GetWindowID(SDL_Window *w);
void SDL_SetWindowTitle(SDL_Window *w, const char *title);
void SDL_MinimizeWindow(SDL_Window *w);
SDL_Renderer *SDL_CreateRenderer(SDL_Window *w, int index, Uint32 flags);
void SDL_DestroyRenderer(SDL_Renderer *r);
int SDL_GetRendererInfo(SDL_Renderer *r, SDL_RendererInfo *info);
int SDL_GetRendererOutputSize(SDL_Renderer *r, int *w, int *h);
int SDL_RenderSetLogicalSize(SDL_Renderer *r, int w, int h);
int SDL_SetRenderDrawColor(SDL_Renderer *r, Uint8 red, Uint8 g, Uint8 b, Uint8 a);
int SDL_SetRenderDrawBlendMode(SDL_Renderer *r, SDL_BlendMode mode);
int SDL_RenderClear(SDL_Renderer *r);
int SDL_RenderFillRect(SDL_Renderer *r, const SDL_Rect *rect);
int SDL_RenderDrawRect(SDL_Renderer *r, const SDL_Rect *rect);
int SDL_RenderCopy(SDL_Renderer *r, SDL_Texture *t, const SDL_Rect *src, const SDL_Rect *dst);
void SDL_RenderPresent(SDL_Renderer *r);
SDL_Texture *SDL_CreateTexture(SDL_Renderer *r, Uint32 format, int access, int w, int h);
SDL_Texture *SDL_CreateTextureFromSurface(SDL_Renderer *r, SDL_Surface *s);
int SDL_UpdateTexture(SDL_Texture *t, const SDL_Rect *rect, const void *pixels, int pitch);
int SDL_SetTextureColorMod(SDL_Texture *t, Uint8 r, Uint8 g, Uint8 b);

#define SDL_MESSAGEBOX_ERROR 0x10u
#define SDL_MESSAGEBOX_WARNING 0x20u
#define SDL_MESSAGEBOX_INFORMATION 0x40u
int SDL_ShowSimpleMessageBox(Uint32 flags, const char *title, const char *message, SDL_Window *w);

/* audio */
typedef Uint16 SDL_AudioFormat;
#define AUDIO_U8 0x0008
#define AUDIO_S8 0x8008
#define AUDIO_S16LSB 0x8010
#define AUDIO_S16MSB 0x9010
#if SDL_BYTEORDER == SDL_BIG_ENDIAN
#define AUDIO_S16SYS AUDIO_S16MSB
#else
#define AUDIO_S16SYS AUDIO_S16LSB
#endif
typedef void (*SDL_AudioCallback)(void *userdata, Uint8 *stream, int len);
typedef struct SDL_AudioSpec {
    int freq; SDL_AudioFormat format; Uint8 channels, silence; Uint16 samples, padding; Uint32 size;
    SDL_AudioCallback callback; void *userdata;
} SDL_AudioSpec;
typedef struct SDL_AudioCVT {
    int needed; SDL_AudioFormat src_format, dst_format;
    Uint8 *buf; int len, len_cvt, len_mult;
    int src_channels, dst_channels, src_rate, dst_rate;   /* sdl2lite's own */
} SDL_AudioCVT;
typedef Uint32 SDL_AudioDeviceID;
SDL_AudioSpec *SDL_LoadWAV_RW(SDL_RWops *rw, int freesrc, SDL_AudioSpec *spec, Uint8 **buf, Uint32 *len);
void SDL_FreeWAV(Uint8 *buf);
int SDL_BuildAudioCVT(SDL_AudioCVT *cvt, SDL_AudioFormat sf, Uint8 sc, int sr, SDL_AudioFormat df, Uint8 dc, int dr);
int SDL_ConvertAudio(SDL_AudioCVT *cvt);
SDL_AudioDeviceID SDL_OpenAudioDevice(const char *dev, int iscapture, const SDL_AudioSpec *want, SDL_AudioSpec *have, int allowed);
void SDL_CloseAudioDevice(SDL_AudioDeviceID dev);
void SDL_PauseAudioDevice(SDL_AudioDeviceID dev, int pause);
#define SDL_LockAudioDevice(d) ((void)(d))     /* ponytail: audio is mixed on the main thread, so no lock */
#define SDL_UnlockAudioDevice(d) ((void)(d))

/* keys: only the codes the game names */
typedef Sint32 SDL_Keycode;
#define SDLK_RETURN '\r'
#define SDLK_ESCAPE '\033'
#define SDLK_SPACE ' '
#define SDLK_f 'f'
#define SDLK_F2 0x4000003B
#define SDLK_F3 0x4000003C
#define SDLK_F5 0x4000003E
#define SDLK_F6 0x4000003F
#define SDLK_F7 0x40000040
#define SDLK_F9 0x40000042
#define SDLK_RIGHT 0x4000004F
#define SDLK_LEFT 0x40000050
#define SDLK_DOWN 0x40000051
#define SDLK_UP 0x40000052
#define SDLK_KP_7 0x4000005F
#define SDLK_KP_9 0x40000061

/* game controller */
typedef struct SDL_GameController SDL_GameController;
enum {
    SDL_CONTROLLER_BUTTON_A, SDL_CONTROLLER_BUTTON_B, SDL_CONTROLLER_BUTTON_X, SDL_CONTROLLER_BUTTON_Y,
    SDL_CONTROLLER_BUTTON_BACK, SDL_CONTROLLER_BUTTON_GUIDE, SDL_CONTROLLER_BUTTON_START,
    SDL_CONTROLLER_BUTTON_LEFTSTICK, SDL_CONTROLLER_BUTTON_RIGHTSTICK,
    SDL_CONTROLLER_BUTTON_LEFTSHOULDER, SDL_CONTROLLER_BUTTON_RIGHTSHOULDER,
    SDL_CONTROLLER_BUTTON_DPAD_UP, SDL_CONTROLLER_BUTTON_DPAD_DOWN,
    SDL_CONTROLLER_BUTTON_DPAD_LEFT, SDL_CONTROLLER_BUTTON_DPAD_RIGHT, SDL_CONTROLLER_BUTTON_MAX
};
enum { SDL_CONTROLLER_AXIS_LEFTX, SDL_CONTROLLER_AXIS_LEFTY };
int SDL_NumJoysticks(void);
SDL_bool SDL_IsGameController(int i);
SDL_GameController *SDL_GameControllerOpen(int i);
void SDL_GameControllerClose(SDL_GameController *c);
const char *SDL_GameControllerName(SDL_GameController *c);

/* events */
enum {
    SDL_QUIT = 0x100, SDL_WINDOWEVENT = 0x200, SDL_KEYDOWN = 0x300, SDL_TEXTINPUT = 0x303,
    SDL_MOUSEMOTION = 0x400, SDL_MOUSEBUTTONDOWN = 0x401,
    SDL_CONTROLLERAXISMOTION = 0x650, SDL_CONTROLLERBUTTONDOWN, SDL_CONTROLLERBUTTONUP, SDL_CONTROLLERDEVICEADDED
};
enum {
    SDL_WINDOWEVENT_MINIMIZED = 7, SDL_WINDOWEVENT_RESTORED = 9, SDL_WINDOWEVENT_SIZE_CHANGED = 6,
    SDL_WINDOWEVENT_FOCUS_GAINED = 12, SDL_WINDOWEVENT_FOCUS_LOST = 13, SDL_WINDOWEVENT_CLOSE = 14
};
#define SDL_BUTTON_LEFT 1
typedef struct { Uint32 type, timestamp, windowID; Uint8 event; Sint32 data1, data2; } SDL_WindowEvent;
typedef struct { Sint32 scancode; SDL_Keycode sym; Uint16 mod; } SDL_Keysym;
typedef struct { Uint32 type, timestamp, windowID; Uint8 state, repeat; SDL_Keysym keysym; } SDL_KeyboardEvent;
typedef struct { Uint32 type, timestamp, windowID; char text[32]; } SDL_TextInputEvent;
typedef struct { Uint32 type, timestamp, windowID; Sint32 x, y; } SDL_MouseMotionEvent;
typedef struct { Uint32 type, timestamp, windowID; Uint8 button, state; Sint32 x, y; } SDL_MouseButtonEvent;
typedef struct { Uint32 type, timestamp; Sint32 which; Uint8 axis; Sint16 value; } SDL_ControllerAxisEvent;
typedef struct { Uint32 type, timestamp; Sint32 which; Uint8 button, state; } SDL_ControllerButtonEvent;
typedef struct { Uint32 type, timestamp; Sint32 which; } SDL_ControllerDeviceEvent;
typedef union SDL_Event {
    Uint32 type;
    SDL_WindowEvent window;
    SDL_KeyboardEvent key;
    SDL_TextInputEvent text;
    SDL_MouseMotionEvent motion;
    SDL_MouseButtonEvent button;
    SDL_ControllerAxisEvent caxis;
    SDL_ControllerButtonEvent cbutton;
    SDL_ControllerDeviceEvent cdevice;
} SDL_Event;
int SDL_PollEvent(SDL_Event *e);

/* ---- the backend contract (backend_<platform>.c) ---- */
int  lite_video_init(int *w, int *h);              /* the screen's size; 0 on success */
void lite_video_present(const Uint32 *xrgb, int w, int h);   /* 0x00RRGGBB, native order */
void lite_poll(void);                              /* calls lite_pad / lite_push_event */
int  lite_audio_start(void);                       /* 44100 Hz S16 stereo; 0 on success */
Uint32 lite_ticks(void);
void lite_sleep(Uint32 ms);
/* ...and what sdl2lite gives the backend */
void lite_push_event(const SDL_Event *e);
void lite_pad(Uint32 buttons, Sint16 lx, Sint16 ly);   /* bit n = SDL_CONTROLLER_BUTTON n */
void lite_audio_mix(Sint16 *out, int frames);          /* call from the main thread only */

#endif
