/*
 * dinput32.c - synthetic DirectInput input for a host harness, included by
 * native32.c (native32_input_*).
 *
 * A game that reads the mouse and keyboard through DirectInput cannot be
 * driven by posted window messages, and under native32_headless its devices
 * do not work at all: the private desktop is never in the foreground, so
 * SetCooperativeLevel and Acquire fail and GetDeviceState answers
 * DIERR_NOTACQUIRED. Once synthetic input is on (native32_input_synthetic,
 * or by default under native32_headless), every system mouse and keyboard the
 * guest creates reads from here instead: the host moves the mouse, presses
 * its buttons and keys, and the device's next GetDeviceState sees it.
 *
 * Patched in dinput's own device vtable (shared by all of a version's
 * devices) from IDirectInput::CreateDevice, which di_wrap patches beside
 * EnumDevices. Buffered readers (GetDeviceData) get the same input as
 * events from a ring per device kind; each device keeps its own read cursor.
 * ponytail: 256 events per kind, older ones are dropped by a slow reader.
 */
typedef HRESULT (WINAPI *di_create_dev_t)(void*, const GUID*, void**, void*);
typedef HRESULT (WINAPI *di_dev1_t)(void*);
typedef HRESULT (WINAPI *di_state_t)(void*, DWORD, void*);
typedef HRESULT (WINAPI *di_data_t)(void*, DWORD, void*, DWORD*, DWORD);
typedef HRESULT (WINAPI *di_coop_t)(void*, HWND, DWORD);
static di_create_dev_t g_di_create_dev[2];
static di_dev1_t g_di_acquire, g_di_unacquire;
static di_state_t g_di_state;
static di_data_t g_di_data;
static di_coop_t g_di_coop;
static int g_di_synth = -1;                 /* -1: decide at first use (on under headless) */
static struct { void* dev; int kind; HANDLE ev; LONG seq; } g_di_devs[16];
typedef struct { DWORD ofs, data, time, seq; } di_evt_t;
static di_evt_t g_di_ring[3][256];
static volatile LONG g_di_seq[3];
static void di_push(int kind, DWORD ofs, DWORD data) {
    LONG s = InterlockedIncrement(&g_di_seq[kind]);
    di_evt_t* e = &g_di_ring[kind][s & 255];
    e->ofs = ofs; e->data = data; e->time = GetTickCount(); e->seq = (DWORD)s;
}   /* kind 1 mouse, 2 keyboard */
typedef HRESULT (WINAPI *di_event_t)(void*, HANDLE);
static di_event_t g_di_event;
static volatile LONG g_mouse_dx, g_mouse_dy, g_mouse_dz;
static volatile uint8_t g_mouse_btn[8], g_keys256[256];

void native32_input_synthetic(int on) { g_di_synth = on; }
/* A device the guest waits on (SetEventNotification) is told input arrived. */
static void di_signal(int kind) {
    for (int i = 0; i < 16; i++) if (g_di_devs[i].kind == kind && g_di_devs[i].ev) SetEvent(g_di_devs[i].ev);
}
void native32_input_mouse(int dx, int dy, int dz) {
    InterlockedExchangeAdd(&g_mouse_dx, dx);
    InterlockedExchangeAdd(&g_mouse_dy, dy);
    InterlockedExchangeAdd(&g_mouse_dz, dz);
    if (dx) di_push(1, 0, (DWORD)dx);
    if (dy) di_push(1, 4, (DWORD)dy);
    if (dz) di_push(1, 8, (DWORD)dz);
    di_signal(1);
}
void native32_input_button(int b, int down) {
    if (b < 0 || b >= 8) return;
    g_mouse_btn[b] = down ? 0x80 : 0;
    di_push(1, 12 + b, down ? 0x80 : 0);
    di_signal(1);
}
void native32_input_key(int dik, int down) {
    if (dik < 0 || dik >= 256) return;
    g_keys256[dik] = down ? 0x80 : 0;
    di_push(2, (DWORD)dik, down ? 0x80 : 0);
    di_signal(2);
}

static int di_synth(void) {
    if (g_di_synth < 0) g_di_synth = GetEnvironmentVariableA("NATIVE32_HEADLESS", NULL, 0) != 0;
    return g_di_synth;
}

static int di_kind(void* dev) {
    for (int i = 0; i < 16; i++) if (g_di_devs[i].dev == dev) return g_di_devs[i].kind;
    return 0;
}

static HRESULT WINAPI di_acquire(void* self) {
    HRESULT hr = g_di_acquire(self);
    return di_synth() && di_kind(self) ? 0 : hr;
}
static HRESULT WINAPI di_unacquire(void* self) {
    HRESULT hr = g_di_unacquire(self);
    return di_synth() && di_kind(self) ? 0 : hr;
}
static HRESULT WINAPI di_coop(void* self, HWND w, DWORD flags) {
    HRESULT hr = g_di_coop(self, w, flags);
    return di_synth() && di_kind(self) ? 0 : hr;
}
static HRESULT WINAPI di_state(void* self, DWORD cb, void* out) {
    int kind = di_synth() ? di_kind(self) : 0;
    if (!kind || !out) return g_di_state(self, cb, out);
    memset(out, 0, cb);
    if (kind == 2) {
        memcpy(out, (const void*)g_keys256, cb < 256 ? cb : 256);
    } else if (cb >= 16) {                  /* DIMOUSESTATE / DIMOUSESTATE2 */
        LONG* axes = (LONG*)out;
        axes[0] = InterlockedExchange(&g_mouse_dx, 0);
        axes[1] = InterlockedExchange(&g_mouse_dy, 0);
        axes[2] = InterlockedExchange(&g_mouse_dz, 0);
        memcpy((uint8_t*)out + 12, (const void*)g_mouse_btn, cb - 12 < 8 ? cb - 12 : 8);
    }
    return 0;
}
static HRESULT WINAPI di_event(void* self, HANDLE ev) {
    for (int i = 0; i < 16; i++) if (g_di_devs[i].dev == self) g_di_devs[i].ev = ev;
    return g_di_event(self, ev);
}
static HRESULT WINAPI di_data(void* self, DWORD cb, void* rg, DWORD* n, DWORD flags) {
    int kind = di_synth() ? di_kind(self) : 0, i;
    if (!kind) return g_di_data(self, cb, rg, n, flags);
    if (!n) return E_POINTER;
    for (i = 0; i < 16 && g_di_devs[i].dev != self; i++) ;
    LONG last = g_di_seq[kind], cur = g_di_devs[i].seq;
    if (last - cur > 256) cur = last - 256;
    DWORD want = *n, got = 0;
    for (; cur != last && got < want; got++) {          /* rg NULL: flush */
        const di_evt_t* e = &g_di_ring[kind][(cur + 1) & 255];
        if (rg) { memset((uint8_t*)rg + got * cb, 0, cb); memcpy((uint8_t*)rg + got * cb, e, cb < 16 ? cb : 16); }
        cur++;
    }
    if (!(flags & 1)) g_di_devs[i].seq = cur;           /* DIGDD_PEEK leaves them */
    *n = got;
    return 0;
}

static HRESULT di_create_dev(int w, void* self, const GUID* g, void** out, void* outer) {
    static const GUID mouse = { 0x6f1d2b60, 0xd5a0, 0x11cf, { 0xbf, 0xc7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };
    static const GUID kbd = { 0x6f1d2b61, 0xd5a0, 0x11cf, { 0xbf, 0xc7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };
    HRESULT hr = g_di_create_dev[w](self, g, out, outer);
    int kind = !memcmp(g, &mouse, sizeof mouse) ? 1 : !memcmp(g, &kbd, sizeof kbd) ? 2 : 0;
    if (hr < 0 || !out || !*out || !kind) return hr;
    for (int i = 0; i < 16; i++)
        if (!g_di_devs[i].dev) { g_di_devs[i].dev = *out; g_di_devs[i].kind = kind; g_di_devs[i].seq = g_di_seq[kind]; break; }
    void** vt = *(void***)*out;
    dd_patch(&vt[7], (void*)di_acquire, (void**)&g_di_acquire);
    dd_patch(&vt[8], (void*)di_unacquire, (void**)&g_di_unacquire);
    dd_patch(&vt[9], (void*)di_state, (void**)&g_di_state);
    dd_patch(&vt[10], (void*)di_data, (void**)&g_di_data);
    dd_patch(&vt[12], (void*)di_event, (void**)&g_di_event);
    dd_patch(&vt[13], (void*)di_coop, (void**)&g_di_coop);
    return hr;
}
static HRESULT WINAPI di_create_dev_a(void* s, const GUID* g, void** o, void* u) { return di_create_dev(0, s, g, o, u); }
static HRESULT WINAPI di_create_dev_w(void* s, const GUID* g, void** o, void* u) { return di_create_dev(1, s, g, o, u); }

static void di_wrap_devices(void*** di, int w) {
    dd_patch(&(*di)[3], w ? (void*)di_create_dev_w : (void*)di_create_dev_a, (void**)&g_di_create_dev[w]);
}
