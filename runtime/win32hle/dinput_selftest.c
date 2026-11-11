/*
 * dinput_selftest.c - DirectInput's buffered data, through the shims as a
 * guest calls them (hle_call_guest on their import VAs), fed by the input a
 * host gives (hle_input_mouse, hle_input_key):
 *
 *   - a buffered mouse reports movement and buttons as events, in
 *     order, and does so with no window to message (input before a game's
 *     window, or over none of it);
 *   - DIGDD_PEEK leaves the events queued; a read takes as many as asked,
 *     oldest first; a count (no buffer) says how many wait, and without
 *     DIGDD_PEEK flushes them;
 *   - a read without a count to read up to is DIERR_INVALIDPARAM, and leaves
 *     the queue alone;
 *   - a buffered keyboard reports a key's DIK code going down and up.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "win32hle.h"
#include "host.h"

static int fails;
static void ok(const char *what, int cond) { if (!cond) { printf("FAIL %s\n", what); fails++; } }
static uint32_t call(const char *name, int n, const uint32_t *a) { return hle_call_guest(hle_resolve(name), n, a); }
#define A(p) hle_va(p)

const recomp_dispatch_entry_t recomp_dispatch_table[1];
const uint32_t recomp_dispatch_count = 0;

#define WM_MOUSEMOVE   0x0200u
#define WM_LBUTTONDOWN 0x0201u
#define WM_LBUTTONUP   0x0202u
#define INFINITE       0xFFFFFFFFu
#define DIGDD_PEEK     1u
#define DIERR_INVALIDPARAM 0x80070057u

typedef struct { uint32_t ofs, data, time, seq; } dod_t;   /* DIDEVICEOBJECTDATA */

/* A device of the system's (GUID_SysMouse or GUID_SysKeyboard, by their
 * first word), its data format set, buffered for 32 events, acquired. */
static uint32_t device(uint32_t di, uint32_t guid_d1, uint32_t data_size, uint32_t nobjs) {
    uint32_t *guid = (uint32_t *)hle_alloc(16), *out = (uint32_t *)hle_alloc(4);
    memset(guid, 0, 16);
    guid[0] = guid_d1;
    uint32_t a[4] = { di, A(guid), A(out), 0 };
    ok("CreateDevice", call("IDirectInputA::CreateDevice", 4, a) == 0 && *out);
    uint32_t dev = *out;
    uint32_t *fmt = (uint32_t *)hle_alloc(24);           /* DIDATAFORMAT: size, objsize, flags (relative), datasize, nobjs, objs */
    fmt[0] = 24, fmt[1] = 16, fmt[2] = 2, fmt[3] = data_size, fmt[4] = nobjs, fmt[5] = 0;
    uint32_t f[2] = { dev, A(fmt) };
    ok("SetDataFormat", call("IDirectInputDeviceA::SetDataFormat", 2, f) == 0);
    uint32_t *prop = (uint32_t *)hle_alloc(20);          /* DIPROPDWORD: header (size, header size, obj, how), data */
    prop[0] = 20, prop[1] = 16, prop[2] = 0, prop[3] = 0, prop[4] = 32;
    uint32_t p[3] = { dev, 1 /* DIPROP_BUFFERSIZE */, A(prop) };
    ok("SetProperty(DIPROP_BUFFERSIZE)", call("IDirectInputDeviceA::SetProperty", 3, p) == 0);
    uint32_t c[3] = { dev, 0, 0x5 /* DISCL_EXCLUSIVE | DISCL_FOREGROUND */ };
    call("IDirectInputDeviceA::SetCooperativeLevel", 3, c);
    ok("Acquire", call("IDirectInputDeviceA::Acquire", 1, &dev) == 0);
    return dev;
}
/* GetDeviceData into buf (or a count, buf 0), *io in and out. */
static uint32_t data(uint32_t dev, dod_t *buf, uint32_t *io, uint32_t flags) {
    uint32_t a[5] = { dev, 16, buf ? A(buf) : 0, io ? A(io) : 0, flags };
    return call("IDirectInputDeviceA::GetDeviceData", 5, a);
}

int main(void) {
    recomp_host_init();
    uint32_t *out = (uint32_t *)hle_alloc(4);
    uint32_t a0[4] = { 0, 0x500, A(out), 0 };
    ok("DirectInputCreateA", call("DirectInputCreateA", 4, a0) == 0 && *out);
    uint32_t di = *out;
    dod_t *buf = (dod_t *)hle_alloc(16 * sizeof(dod_t));
    uint32_t *io = (uint32_t *)hle_alloc(4);

    /* the mouse: movement and a click, with no window anywhere */
    uint32_t mouse = device(di, 0x6F1D2B60u, 16, 7);
    hle_input_mouse(WM_MOUSEMOVE, 10, 5);
    hle_input_mouse(WM_LBUTTONDOWN, 10, 5);
    hle_input_mouse(WM_LBUTTONUP, 10, 5);

    *io = INFINITE;
    ok("a count, peeking", data(mouse, NULL, io, DIGDD_PEEK) == 0 && *io == 4);
    *io = 16;
    ok("a peek", data(mouse, buf, io, DIGDD_PEEK) == 0 && *io == 4);
    ok("...x moved 10, y 5, the button down then up, in order",
       buf[0].ofs == 0 && buf[0].data == 10 && buf[1].ofs == 4 && buf[1].data == 5 &&
       buf[2].ofs == 12 && buf[2].data == 0x80 && buf[3].ofs == 12 && buf[3].data == 0);
    ok("...each later than the one before", buf[1].seq > buf[0].seq && buf[3].seq > buf[2].seq);
    *io = 16;
    ok("a peek leaves them", data(mouse, buf, io, DIGDD_PEEK) == 0 && *io == 4 && buf[0].ofs == 0);

    ok("a read without a count is DIERR_INVALIDPARAM", data(mouse, buf, NULL, 0) == DIERR_INVALIDPARAM);
    *io = INFINITE;
    ok("...and leaves the queue alone", data(mouse, NULL, io, DIGDD_PEEK) == 0 && *io == 4);

    *io = 2;
    ok("a read of two", data(mouse, buf, io, 0) == 0 && *io == 2 && buf[0].ofs == 0 && buf[1].ofs == 4);
    *io = 16;
    ok("...takes the oldest two", data(mouse, buf, io, DIGDD_PEEK) == 0 && *io == 2 && buf[0].ofs == 12);

    *io = INFINITE;
    ok("a flush says how many went", data(mouse, NULL, io, 0) == 0 && *io == 2);
    *io = INFINITE;
    ok("...and none are left", data(mouse, NULL, io, DIGDD_PEEK) == 0 && *io == 0);

    /* the keyboard: a key down and up, by its DIK code */
    uint32_t keyboard = device(di, 0x6F1D2B61u, 256, 256);
    hle_input_key(1, 0x41, 0x1E);                         /* 'A' */
    hle_input_key(0, 0x41, 0x1E);
    *io = 16;
    ok("a key down and up", data(keyboard, buf, io, 0) == 0 && *io == 2 &&
       buf[0].ofs == 0x1E && (buf[0].data & 0x80) && buf[1].ofs == 0x1E && !(buf[1].data & 0x80));

    if (fails) { printf("dinput_selftest: %d failed\n", fails); return 1; }
    printf("dinput_selftest: ok\n");
    return 0;
}
