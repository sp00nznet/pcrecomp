/*
 * dinput.c - DirectInput (3 and 5): the system mouse and keyboard.
 *
 * Both devices read the input state the window manager keeps (user32.c:
 * the cursor, and the key and button bytes GetAsyncKeyState answers from),
 * which the host feeds from SDL or a script with hle_input_mouse and
 * hle_input_key. So a game that reads DirectInput and one that reads its
 * window's messages see the same mouse and keyboard.
 *
 * The mouse reports relative axes, each read the movement since the last,
 * unless the game sets DIPROP_AXISMODE to absolute; three buttons. The
 * keyboard reports DIK scan codes. Both answer GetDeviceState (immediate)
 * and GetDeviceData (buffered: each change as an event, recorded as input
 * arrives, with the device's notification event set then).
 *
 * HLE_DITRACE=1 prints the calls that set a device up.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "win32hle.h"

#define DI_OK                0u
#define DI_BUFFEROVERFLOW    1u
#define DI_NOEFFECT          1u
#define DIERR_UNSUPPORTED    0x80004001u
#define DIERR_NOINTERFACE    0x80004002u
#define DIERR_INVALIDPARAM   0x80070057u
#define DIERR_DEVICENOTREG   0x80040154u
#define DIERR_OBJECTNOTFOUND 0x80070002u

static int g_trace = -1;
static int trace(void) { if (g_trace < 0) g_trace = getenv("HLE_DITRACE") != NULL; return g_trace; }
#define T(...) do { if (trace()) fprintf(stderr, "[dinput] " __VA_ARGS__); } while (0)

enum { MOUSE = 1, KEYBOARD = 2 };
#define QUEUE 256
typedef struct { uint32_t ofs, data, time, seq; } ev_t;    /* DIDEVICEOBJECTDATA */
typedef struct {
    int kind, acquired, absolute;
    uint32_t data_size;                                  /* SetDataFormat's dwDataSize */
    uint32_t buffer;                                     /* DIPROP_BUFFERSIZE */
    int last_x, last_y;                                  /* GetDeviceState's: where the last read left the cursor */
    int buf_x, buf_y;                                    /* GetDeviceData's */
    uint8_t buf_buttons[3], buf_keys[256];               /* what the last buffered read saw */
    ev_t q[QUEUE];
    int qn;
    int overflow;
    uint32_t event;                                      /* SetEventNotification's */
} dev_t_;

static uint32_t g_vt_di, g_vt_dev, g_seq;
/* The devices made, so input arriving can reach them. */
#define MAX_DEV 16
static uint32_t g_devs[MAX_DEV];
#define DEV(o) ((dev_t_ *)hle_ptr(MEM32((o) + 8)))

/* ---- virtual keys to DirectInput's scan codes ---- */
static uint8_t g_dik[256];                                /* vk -> DIK */
static void dik_table(void) {
    if (g_dik[0x1B]) return;
    static const struct { uint8_t vk, dik; } t[] = {
        { 0x1B, 0x01 }, { 0x31, 0x02 }, { 0x32, 0x03 }, { 0x33, 0x04 }, { 0x34, 0x05 }, { 0x35, 0x06 }, { 0x36, 0x07 },
        { 0x37, 0x08 }, { 0x38, 0x09 }, { 0x39, 0x0A }, { 0x30, 0x0B }, { 0xBD, 0x0C }, { 0xBB, 0x0D }, { 0x08, 0x0E },
        { 0x09, 0x0F }, { 'Q', 0x10 }, { 'W', 0x11 }, { 'E', 0x12 }, { 'R', 0x13 }, { 'T', 0x14 }, { 'Y', 0x15 },
        { 'U', 0x16 }, { 'I', 0x17 }, { 'O', 0x18 }, { 'P', 0x19 }, { 0xDB, 0x1A }, { 0xDD, 0x1B }, { 0x0D, 0x1C },
        { 0xA2, 0x1D }, { 'A', 0x1E }, { 'S', 0x1F }, { 'D', 0x20 }, { 'F', 0x21 }, { 'G', 0x22 }, { 'H', 0x23 },
        { 'J', 0x24 }, { 'K', 0x25 }, { 'L', 0x26 }, { 0xBA, 0x27 }, { 0xDE, 0x28 }, { 0xC0, 0x29 }, { 0xA0, 0x2A },
        { 0xDC, 0x2B }, { 'Z', 0x2C }, { 'X', 0x2D }, { 'C', 0x2E }, { 'V', 0x2F }, { 'B', 0x30 }, { 'N', 0x31 },
        { 'M', 0x32 }, { 0xBC, 0x33 }, { 0xBE, 0x34 }, { 0xBF, 0x35 }, { 0xA1, 0x36 }, { 0x6A, 0x37 }, { 0xA4, 0x38 },
        { 0x20, 0x39 }, { 0x14, 0x3A }, { 0x70, 0x3B }, { 0x71, 0x3C }, { 0x72, 0x3D }, { 0x73, 0x3E }, { 0x74, 0x3F },
        { 0x75, 0x40 }, { 0x76, 0x41 }, { 0x77, 0x42 }, { 0x78, 0x43 }, { 0x79, 0x44 }, { 0x90, 0x45 }, { 0x91, 0x46 },
        { 0x67, 0x47 }, { 0x68, 0x48 }, { 0x69, 0x49 }, { 0x6D, 0x4A }, { 0x64, 0x4B }, { 0x65, 0x4C }, { 0x66, 0x4D },
        { 0x6B, 0x4E }, { 0x61, 0x4F }, { 0x62, 0x50 }, { 0x63, 0x51 }, { 0x60, 0x52 }, { 0x6E, 0x53 }, { 0x7A, 0x57 },
        { 0x7B, 0x58 }, { 0xA3, 0x9D }, { 0x6F, 0xB5 }, { 0xA5, 0xB8 }, { 0x13, 0xC5 }, { 0x24, 0xC7 }, { 0x26, 0xC8 },
        { 0x21, 0xC9 }, { 0x25, 0xCB }, { 0x27, 0xCD }, { 0x23, 0xCF }, { 0x28, 0xD0 }, { 0x22, 0xD1 }, { 0x2D, 0xD2 },
        { 0x2E, 0xD3 }, { 0x5B, 0xDB }, { 0x5C, 0xDC }, { 0x5D, 0xDD },
    };
    for (size_t i = 0; i < sizeof t / sizeof *t; i++) g_dik[t[i].vk] = t[i].dik;
}
/* The keyboard as DIK bytes: a key's byte 0x80 while it is down. The
 * generic Shift, Control and Alt count as the left ones. */
static void keyboard(uint8_t out[256]) {
    dik_table();
    memset(out, 0, 256);
    for (int vk = 1; vk < 256; vk++)
        if ((hle_input_vk((uint32_t)vk) & 0x80) && g_dik[vk]) out[g_dik[vk]] = 0x80;
    if (hle_input_vk(0x10) & 0x80 && !out[0x36]) out[0x2A] = 0x80;
    if (hle_input_vk(0x11) & 0x80 && !out[0x9D]) out[0x1D] = 0x80;
    if (hle_input_vk(0x12) & 0x80 && !out[0xB8]) out[0x38] = 0x80;
}
static void buttons(uint8_t out[3]) {
    out[0] = hle_input_vk(1) & 0x80, out[1] = hle_input_vk(2) & 0x80, out[2] = hle_input_vk(4) & 0x80;
}

static void push(dev_t_ *d, uint32_t ofs, uint32_t data) {
    if (d->qn >= QUEUE || (d->buffer && (uint32_t)d->qn >= d->buffer)) { d->overflow = 1; return; }
    ev_t *e = &d->q[d->qn++];
    e->ofs = ofs, e->data = data, e->time = hle_ticks_ms(), e->seq = ++g_seq;
}
/* What changed since the last buffered read, as events. */
static void gather(dev_t_ *d) {
    if (d->kind == MOUSE) {
        int x, y;
        uint8_t b[3];
        hle_input_position(&x, &y);
        if (x != d->buf_x) push(d, 0, d->absolute ? (uint32_t)x : (uint32_t)(x - d->buf_x));
        if (y != d->buf_y) push(d, 4, d->absolute ? (uint32_t)y : (uint32_t)(y - d->buf_y));
        d->buf_x = x, d->buf_y = y;
        buttons(b);
        for (int i = 0; i < 3; i++)
            if (b[i] != d->buf_buttons[i]) push(d, 12u + (uint32_t)i, b[i]), d->buf_buttons[i] = b[i];
    } else {
        uint8_t k[256];
        keyboard(k);
        for (int i = 0; i < 256; i++)
            if (k[i] != d->buf_keys[i]) push(d, (uint32_t)i, k[i]), d->buf_keys[i] = k[i];
    }
}
/* Input arrived (hle_input_hook, holding the machine): each acquired device
 * records what changed as events now, so a press and release between two
 * reads are both kept, and its notification event is set, as DirectInput
 * sets it when data arrives. */
static void arrived(void) {
    for (int i = 0; i < MAX_DEV; i++) {
        if (!g_devs[i]) continue;
        dev_t_ *d = (dev_t_ *)hle_ptr(MEM32(g_devs[i] + 8));
        if (!d->acquired) continue;
        int before = d->qn;
        gather(d);
        if (d->qn != before && d->event) hle_set_event(d->event);
    }
}
static void baseline(dev_t_ *d) {
    hle_input_position(&d->last_x, &d->last_y);
    d->buf_x = d->last_x, d->buf_y = d->last_y;
    buttons(d->buf_buttons);
    keyboard(d->buf_keys);
    d->qn = 0, d->overflow = 0;
}

/* ---- IDirectInputDevice(2)A ---- */
static void dv_QueryInterface(void) {
    uint32_t d1 = MEM32(A32(1));
    /* IUnknown, IDirectInputDeviceA, IDirectInputDevice2A: one object */
    if (d1 == 0 || d1 == 0x5944E680u || d1 == 0x5944E682u) { MEM32(A32(2)) = A32(0); MEM32(A32(0) + 4)++; RET(DI_OK, 3); }
    MEM32(A32(2)) = 0;
    RET(DIERR_NOINTERFACE, 3);
}
static void dv_Release(void) {
    uint32_t self = A32(0), n = --MEM32(self + 4);
    if (!n) {
        for (int i = 0; i < MAX_DEV; i++) if (g_devs[i] == self) g_devs[i] = 0;
        hle_free(DEV(self));
        hle_com_free(self);
    }
    RET(n, 1);
}
static void dv_GetCapabilities(void) {                   /* DIDEVCAPS */
    dev_t_ *d = DEV(A32(0));
    uint32_t c = A32(1), size = MEM32(c) ? MEM32(c) : 24;
    memset(hle_ptr(c + 4), 0, size - 4);
    MEM32(c + 4) = 1;                                    /* DIDC_ATTACHED */
    MEM32(c + 8) = d->kind == MOUSE ? 0x0102u : 0x0403u; /* a mouse, a keyboard: their DIDEVTYPEs */
    MEM32(c + 12) = d->kind == MOUSE ? 3 : 0;            /* axes */
    MEM32(c + 16) = d->kind == MOUSE ? 3 : 128;          /* buttons */
    RET(DI_OK, 2);
}
static void dv_GetProperty(void) {                       /* (this, guid or id, DIPROPHEADER*) */
    dev_t_ *d = DEV(A32(0));
    uint32_t id = A32(1), h = A32(2);
    if (id == 1) { MEM32(h + 16) = d->buffer; RET(DI_OK, 3); }          /* DIPROP_BUFFERSIZE */
    if (id == 2) { MEM32(h + 16) = (uint32_t)d->absolute; RET(DI_OK, 3); }   /* DIPROP_AXISMODE */
    RET(DIERR_UNSUPPORTED, 3);
}
static void dv_SetProperty(void) {
    dev_t_ *d = DEV(A32(0));
    uint32_t id = A32(1), h = A32(2);
    T("SetProperty %u = %u\n", id, h ? MEM32(h + 16) : 0);
    if (id == 1) d->buffer = MEM32(h + 16) > QUEUE ? QUEUE : MEM32(h + 16);
    else if (id == 2) d->absolute = MEM32(h + 16) == 1;  /* DIPROPAXISMODE_ABS */
    RET(DI_OK, 3);
}
static void dv_Acquire(void) {
    dev_t_ *d = DEV(A32(0));
    if (!d->acquired) baseline(d), d->acquired = 1;
    RET(DI_OK, 1);
}
static void dv_Unacquire(void) { DEV(A32(0))->acquired = 0; RET(DI_OK, 1); }
static void dv_GetDeviceState(void) {                    /* (this, size, data) */
    dev_t_ *d = DEV(A32(0));
    uint32_t n = A32(1), p = A32(2);
    if (!p || !n) RET(DIERR_INVALIDPARAM, 3);
    memset(hle_ptr(p), 0, n);
    if (d->kind == MOUSE) {                              /* DIMOUSESTATE: lX, lY, lZ, four buttons */
        int x, y;
        uint8_t b[3];
        hle_input_position(&x, &y);
        buttons(b);
        if (n >= 12) {
            MEM32(p) = (uint32_t)(d->absolute ? x : x - d->last_x);
            MEM32(p + 4) = (uint32_t)(d->absolute ? y : y - d->last_y);
        }
        d->last_x = x, d->last_y = y;
        for (uint32_t i = 0; i < 3 && 12 + i < n; i++) MEM8(p + 12 + i) = b[i];
    } else {
        uint8_t k[256];
        keyboard(k);
        memcpy(hle_ptr(p), k, n < 256 ? n : 256);
    }
    RET(DI_OK, 3);
}
static void dv_GetDeviceData(void) {                     /* (this, objsize, rgdod, &inout, flags) */
    dev_t_ *d = DEV(A32(0));
    uint32_t sz = A32(1), out = A32(2), io = A32(3), flags = A32(4);
    uint32_t want = io ? MEM32(io) : 0;
    gather(d);
    uint32_t hr = d->overflow ? DI_BUFFEROVERFLOW : DI_OK;
    if (!out) {                                          /* a count, or a flush */
        uint32_t n = (uint32_t)d->qn;
        if (!(flags & 1)) d->qn = 0, d->overflow = 0;    /* not DIGDD_PEEK: they are gone */
        if (io) MEM32(io) = want == 0xFFFFFFFFu || n < want ? n : want;
        RET(hr, 5);
    }
    uint32_t n = (uint32_t)d->qn < want ? (uint32_t)d->qn : want;
    if (sz < 16) sz = 16;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t e = out + i * sz;
        memset(hle_ptr(e), 0, sz);
        MEM32(e) = d->q[i].ofs, MEM32(e + 4) = d->q[i].data, MEM32(e + 8) = d->q[i].time, MEM32(e + 12) = d->q[i].seq;
    }
    if (!(flags & 1)) {
        memmove(d->q, d->q + n, sizeof *d->q * (size_t)(d->qn - (int)n));
        d->qn -= (int)n;
        d->overflow = 0;
    }
    if (trace() && n) {
        fprintf(stderr, "[dinput] GetDeviceData %s:", d->kind == MOUSE ? "mouse" : "keyboard");
        for (uint32_t i = 0; i < n; i++) fprintf(stderr, " %X=%X", MEM32(out + i * sz), MEM32(out + i * sz + 4));
        fprintf(stderr, "%s\n", flags & 1 ? " (peek)" : "");
    }
    MEM32(io) = n;
    RET(hr, 5);
}
static void dv_SetDataFormat(void) {                     /* DIDATAFORMAT: size, objsize, flags, datasize, nobjs, objs */
    dev_t_ *d = DEV(A32(0));
    uint32_t f = A32(1);
    d->data_size = MEM32(f + 12);
    if (MEM32(f + 8) & 1) d->absolute = 1;               /* DIDF_ABSAXIS */
    T("SetDataFormat on the %s: %u bytes, %u objects, flags %X\n", d->kind == MOUSE ? "mouse" : "keyboard",
      d->data_size, MEM32(f + 16), MEM32(f + 8));
    RET(DI_OK, 2);
}
static void dv_SetEventNotification(void) { DEV(A32(0))->event = A32(1); RET(DI_OK, 2); }
static void dv_SetCooperativeLevel(void) { T("SetCooperativeLevel %X\n", A32(2)); RET(DI_OK, 3); }
static void dv_GetObjectInfo(void) { RET(DIERR_OBJECTNOTFOUND, 4); }
static void put_instance(uint32_t p, int kind) {         /* DIDEVICEINSTANCEA */
    uint32_t size = MEM32(p) ? MEM32(p) : 0x234;
    memset(hle_ptr(p + 4), 0, size - 4);
    uint8_t g[16] = { 0x60, 0x2B, 0x1D, 0x6F, 0xA0, 0xD5, 0xCF, 0x11, 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 };
    if (kind == KEYBOARD) g[0] = 0x61;                   /* GUID_SysMouse, GUID_SysKeyboard */
    memcpy(hle_ptr(p + 4), g, 16);
    memcpy(hle_ptr(p + 20), g, 16);
    MEM32(p + 36) = kind == MOUSE ? 0x0102u : 0x0403u;
    strcpy((char *)hle_ptr(p + 40), kind == MOUSE ? "Mouse" : "Keyboard");
    strcpy((char *)hle_ptr(p + 300), kind == MOUSE ? "Mouse" : "Keyboard");
}
static void dv_GetDeviceInfo(void) { put_instance(A32(1), DEV(A32(0))->kind); RET(DI_OK, 2); }
static void dv_ok2(void) { RET(DI_OK, 2); }
static void dv_ok3(void) { RET(DI_OK, 3); }
static void dv_ok4(void) { RET(DI_OK, 4); }
static void dv_none1(void) { RET(DI_NOEFFECT, 1); }
static void dv_no2(void) { RET(DIERR_UNSUPPORTED, 2); }
static void dv_no3(void) { RET(DIERR_UNSUPPORTED, 3); }
static void dv_no5(void) { RET(DIERR_UNSUPPORTED, 5); }

/* ---- IDirectInput(2)A ---- */
static void di_QueryInterface(void) {
    uint32_t d1 = MEM32(A32(1));
    if (d1 == 0 || d1 == 0x89521360u || d1 == 0x5944E662u) { MEM32(A32(2)) = A32(0); MEM32(A32(0) + 4)++; RET(DI_OK, 3); }
    MEM32(A32(2)) = 0;
    RET(DIERR_NOINTERFACE, 3);
}
static void di_Release(void) {
    uint32_t self = A32(0), n = --MEM32(self + 4);
    if (!n) hle_com_free(self);
    RET(n, 1);
}
static void di_CreateDevice(void) {                      /* (this, guid, &device, outer) */
    uint32_t d1 = MEM32(A32(1));
    int kind = d1 == 0x6F1D2B60u ? MOUSE : d1 == 0x6F1D2B61u ? KEYBOARD : 0;
    if (!kind) { MEM32(A32(2)) = 0; RET(DIERR_DEVICENOTREG, 4); }
    dev_t_ *d = (dev_t_ *)hle_alloc(sizeof *d);
    d->kind = kind;
    baseline(d);
    uint32_t o = hle_com_new(g_vt_dev, 12);
    MEM32(o + 8) = hle_va(d);
    MEM32(A32(2)) = o;
    for (int i = 0; i < MAX_DEV; i++) if (!g_devs[i]) { g_devs[i] = o; break; }
    hle_input_hook = arrived;
    T("CreateDevice: the %s -> 0x%08X\n", kind == MOUSE ? "mouse" : "keyboard", o);
    RET(DI_OK, 4);
}
static void di_EnumDevices(void) {                       /* (this, type, callback, ctx, flags) */
    uint32_t type = A32(1) & 0xFF, mark = hle_scratch_mark(), p = hle_scratch(0x244);
    for (int kind = MOUSE; kind <= KEYBOARD; kind++) {
        if (type && type != (kind == MOUSE ? 2u : 3u)) continue;   /* DIDEVTYPE_MOUSE, DIDEVTYPE_KEYBOARD */
        MEM32(p) = 0x244;
        put_instance(p, kind);
        uint32_t a[2] = { p, A32(3) };
        if (!hle_call_guest(A32(2), 2, a)) break;        /* DIENUM_STOP */
    }
    hle_scratch_release(mark);
    RET(DI_OK, 5);
}
static void di_GetDeviceStatus(void) { RET(DI_OK, 2); }
static void di_FindDevice(void) { RET(DIERR_DEVICENOTREG, 4); }

static void vtables(void) {
    if (g_vt_di) return;
    static const win32hle_shim di[] = {
        { "IDirectInputA::QueryInterface", di_QueryInterface }, { "IDirectInputA::AddRef", hle_com_AddRef },
        { "IDirectInputA::Release", di_Release }, { "IDirectInputA::CreateDevice", di_CreateDevice },
        { "IDirectInputA::EnumDevices", di_EnumDevices }, { "IDirectInputA::GetDeviceStatus", di_GetDeviceStatus },
        { "IDirectInputA::RunControlPanel", dv_ok3 }, { "IDirectInputA::Initialize", dv_ok3 },
        { "IDirectInput2A::FindDevice", di_FindDevice }, { 0, 0 } };
    static const win32hle_shim dv[] = {
        { "IDirectInputDeviceA::QueryInterface", dv_QueryInterface }, { "IDirectInputDeviceA::AddRef", hle_com_AddRef },
        { "IDirectInputDeviceA::Release", dv_Release }, { "IDirectInputDeviceA::GetCapabilities", dv_GetCapabilities },
        { "IDirectInputDeviceA::EnumObjects", dv_ok4 }, { "IDirectInputDeviceA::GetProperty", dv_GetProperty },
        { "IDirectInputDeviceA::SetProperty", dv_SetProperty }, { "IDirectInputDeviceA::Acquire", dv_Acquire },
        { "IDirectInputDeviceA::Unacquire", dv_Unacquire }, { "IDirectInputDeviceA::GetDeviceState", dv_GetDeviceState },
        { "IDirectInputDeviceA::GetDeviceData", dv_GetDeviceData }, { "IDirectInputDeviceA::SetDataFormat", dv_SetDataFormat },
        { "IDirectInputDeviceA::SetEventNotification", dv_SetEventNotification },
        { "IDirectInputDeviceA::SetCooperativeLevel", dv_SetCooperativeLevel },
        { "IDirectInputDeviceA::GetObjectInfo", dv_GetObjectInfo }, { "IDirectInputDeviceA::GetDeviceInfo", dv_GetDeviceInfo },
        { "IDirectInputDeviceA::RunControlPanel", dv_ok3 }, { "IDirectInputDeviceA::Initialize", dv_ok4 },
        /* IDirectInputDevice2A: force feedback (none), Poll, SendDeviceData */
        { "IDirectInputDevice2A::CreateEffect", dv_no5 }, { "IDirectInputDevice2A::EnumEffects", dv_ok4 },
        { "IDirectInputDevice2A::GetEffectInfo", dv_no3 }, { "IDirectInputDevice2A::GetForceFeedbackState", dv_no2 },
        { "IDirectInputDevice2A::SendForceFeedbackCommand", dv_no2 },
        { "IDirectInputDevice2A::EnumCreatedEffectObjects", dv_ok4 }, { "IDirectInputDevice2A::Escape", dv_no2 },
        { "IDirectInputDevice2A::Poll", dv_none1 }, { "IDirectInputDevice2A::SendDeviceData", dv_no5 }, { 0, 0 } };
    g_vt_di = hle_com_vtable(di);
    g_vt_dev = hle_com_vtable(dv);
    (void)dv_ok2;
}

static void x_DirectInputCreateA(void) {                 /* (hinst, version, &out, outer) */
    vtables();
    T("DirectInputCreateA version %X\n", A32(1));
    MEM32(A32(2)) = hle_com_new(g_vt_di, 12);
    RET(DI_OK, 4);
}

const win32hle_shim win32hle_dinput[] = {
    { "DirectInputCreateA", x_DirectInputCreateA }, { "DirectInputCreate", x_DirectInputCreateA },
    { 0, 0 }
};
