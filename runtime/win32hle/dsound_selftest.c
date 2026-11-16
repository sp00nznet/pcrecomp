/*
 * dsound_selftest.c - DirectSound 3D's gains, through the shims as a guest
 * calls them:
 *
 *   - inverse distance past the minimum distance, held at the maximum,
 *     scaled by the listener's roll-off factor;
 *   - a sound on the listener's right is louder on the right (DirectSound is
 *     left-handed), and the listener's position counts in normal mode, not
 *     in head-relative mode; DS3DMODE_DISABLE plays the buffer as 2D;
 *   - SetPan does not move a 3D sound, and still pans a 2D one;
 *   - the listener survives the guest releasing it to zero;
 *   - a 3D interface keeps its buffer (and the buffer's slot) alive after the
 *     guest releases the buffer.
 */
#include <math.h>
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

#define DSBCAPS_PRIMARYBUFFER 0x01u
#define DSBCAPS_CTRL3D        0x10u
#define IID_3DBUFFER   0x279AFA86u                       /* first words of the IIDs */
#define IID_3DLISTENER 0x279AFA84u

static uint32_t f2u(float f) { uint32_t u; memcpy(&u, &f, 4); return u; }
static int near(float a, float b) { return fabsf(a - b) < 1e-3f; }

static uint32_t buffer(uint32_t ds, uint32_t flags) {
    uint16_t *wfx = (uint16_t *)hle_alloc(18);           /* WAVEFORMATEX: PCM, mono, 22050 Hz, 16 bits */
    memset(wfx, 0, 18);
    wfx[0] = 1, wfx[1] = 1, wfx[6] = 2, wfx[7] = 16;
    uint32_t rate = 22050, avg = 44100;
    memcpy(wfx + 2, &rate, 4), memcpy(wfx + 4, &avg, 4);
    uint32_t *desc = (uint32_t *)hle_alloc(20), *out = (uint32_t *)hle_alloc(4);
    desc[0] = 20, desc[1] = flags, desc[2] = flags & DSBCAPS_PRIMARYBUFFER ? 0 : 4096, desc[3] = 0;
    desc[4] = flags & DSBCAPS_PRIMARYBUFFER ? 0 : A(wfx);
    uint32_t a[4] = { ds, A(desc), A(out), 0 };
    ok("CreateSoundBuffer", call("IDirectSound::CreateSoundBuffer", 4, a) == 0 && *out);
    return *out;
}
static uint32_t query(uint32_t obj, uint32_t iid_d1) {
    uint32_t *iid = (uint32_t *)hle_alloc(16), *out = (uint32_t *)hle_alloc(4);
    memset(iid, 0, 16);
    iid[0] = iid_d1;
    uint32_t a[3] = { obj, A(iid), A(out) };
    ok("QueryInterface", call("IDirectSoundBuffer::QueryInterface", 3, a) == 0 && *out);
    return *out;
}
static void pos3d(const char *method, uint32_t obj, float x, float y, float z) {
    uint32_t a[5] = { obj, f2u(x), f2u(y), f2u(z), 0 };
    call(method, 5, a);
}
static void set1(const char *method, uint32_t obj, uint32_t v) { uint32_t a[3] = { obj, v, 0 }; call(method, 3, a); }
static uint32_t release(const char *method, uint32_t obj) { return call(method, 1, &obj); }
static void gains(uint32_t obj, float *l, float *r) { *l = *r = -1.0f; ok("gains", hle_dsound_buffer_gains(obj, l, r)); }

int main(void) {
    recomp_host_init();
    uint32_t *out = (uint32_t *)hle_alloc(4);
    uint32_t a0[3] = { 0, A(out), 0 };
    ok("DirectSoundCreate", call("DirectSoundCreate", 3, a0) == 0 && *out);
    uint32_t ds = *out;
    uint32_t prim = buffer(ds, DSBCAPS_PRIMARYBUFFER);
    uint32_t lis = query(prim, IID_3DLISTENER);
    uint32_t b = buffer(ds, DSBCAPS_CTRL3D), t = query(b, IID_3DBUFFER);
    float l, r;

    /* distance: the listener at the origin facing +z, minimum distance 1 */
    pos3d("IDirectSound3DBuffer::SetPosition", t, 0, 0, 1);
    gains(t, &l, &r);
    ok("at the minimum distance: full volume, centred", near(l, 1) && near(r, 1));
    pos3d("IDirectSound3DBuffer::SetPosition", t, 0, 0, 2);
    gains(t, &l, &r);
    ok("twice the minimum distance: half", near(l, 0.5f) && near(r, 0.5f));
    set1("IDirectSound3DBuffer::SetMaxDistance", t, f2u(10));
    pos3d("IDirectSound3DBuffer::SetPosition", t, 0, 0, 100);
    gains(t, &l, &r);
    ok("past the maximum distance: held there", near(l, 0.1f) && near(r, 0.1f));
    set1("IDirectSound3DListener::SetRolloffFactor", lis, f2u(0));
    gains(t, &l, &r);
    ok("roll-off 0: no attenuation", near(l, 1) && near(r, 1));
    set1("IDirectSound3DListener::SetRolloffFactor", lis, f2u(1));
    set1("IDirectSound3DBuffer::SetMaxDistance", t, f2u(1e9f));

    /* sides */
    pos3d("IDirectSound3DBuffer::SetPosition", t, 3, 0, 0);
    gains(t, &l, &r);
    ok("on the right: louder right", near(r, 1.0f / 3) && l < r * 0.5f);
    pos3d("IDirectSound3DBuffer::SetPosition", t, -3, 0, 0);
    gains(t, &l, &r);
    ok("on the left: louder left", near(l, 1.0f / 3) && r < l * 0.5f);
    uint32_t pan[2] = { b, 10000 };
    call("IDirectSoundBuffer::SetPan", 2, pan);
    float l2, r2;
    gains(t, &l2, &r2);
    ok("SetPan leaves a 3D sound where it is", near(l, l2) && near(r, r2));
    pan[1] = 0;
    call("IDirectSoundBuffer::SetPan", 2, pan);

    /* the listener's position: normal mode counts it, head-relative does not */
    pos3d("IDirectSound3DListener::SetPosition", lis, 5, 0, 0);
    pos3d("IDirectSound3DBuffer::SetPosition", t, 5, 0, 2);
    gains(t, &l, &r);
    ok("normal mode: relative to the listener", near(l, 0.5f) && near(r, 0.5f));
    set1("IDirectSound3DBuffer::SetMode", t, 1);
    gains(t, &l, &r);
    ok("head-relative: relative to the head", r < 0.5f && l < r);
    set1("IDirectSound3DBuffer::SetMode", t, 2);
    gains(t, &l, &r);
    ok("DS3DMODE_DISABLE: 2D", near(l, 1) && near(r, 1));
    set1("IDirectSound3DBuffer::SetMode", t, 0);
    pos3d("IDirectSound3DListener::SetPosition", lis, 0, 0, 0);

    /* a 2D buffer still pans */
    uint32_t flat = buffer(ds, 0);
    uint32_t pan2[2] = { flat, (uint32_t)-2000 };
    call("IDirectSoundBuffer::SetPan", 2, pan2);
    gains(flat, &l, &r);
    ok("SetPan pans a 2D buffer", near(l, 1) && near(r, 0.1f));

    /* the listener, released to zero (and once more), is still there */
    ok("listener Release to zero", release("IDirectSound3DListener::Release", lis) == 0);
    release("IDirectSound3DListener::Release", lis);
    ok("the same listener again", query(prim, IID_3DLISTENER) == lis);
    pos3d("IDirectSound3DListener::SetPosition", lis, 0, 0, 0);

    /* the buffer released while its 3D interface lives: it stays, with its slot */
    ok("buffer Release: the 3D interface holds it", release("IDirectSoundBuffer::Release", b) == 1);
    uint32_t c = buffer(ds, DSBCAPS_CTRL3D), tc = query(c, IID_3DBUFFER);
    pos3d("IDirectSound3DBuffer::SetPosition", tc, 0, 0, 1);
    pos3d("IDirectSound3DBuffer::SetPosition", t, 0, 0, 4);
    gains(t, &l, &r);
    ok("the 3D interface still moves its own buffer", near(l, 0.25f) && near(r, 0.25f));
    gains(tc, &l, &r);
    ok("...and not the next one", near(l, 1) && near(r, 1));
    ok("3D interface Release frees both", release("IDirectSound3DBuffer::Release", t) == 0);

    printf(fails ? "dsound_selftest: %d failed\n" : "dsound_selftest: ok\n", fails);
    return fails != 0;
}
