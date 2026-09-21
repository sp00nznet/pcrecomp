/*
 * eh64.c - see eh64.h.
 *
 * Two halves. The first is an ordinary x64 virtual unwind, run over GUEST
 * registers and the GUEST stack using the original image's .pdata/.xdata: the
 * lifter pushes real return addresses and executes the original prologues, so
 * the frames the unwind data describes are the frames that are really there.
 * The second reads the FuncInfo behind __CxxFrameHandler3 to decide which of
 * those frames catches.
 *
 * Everything is read out of the loaded guest image, so no table has to be
 * generated alongside the lifted code and none can go stale against it.
 */

#include "cpu64.h"

#include <stdio.h>
#include <string.h>

uint64_t es3_eh_image_base;     /* set by the loader */
int      g_eh_trace;

extern void dispatch(CPU *c, uint64_t target);
extern int  es3_cs_depth_get(void);
extern void es3_cs_depth_set(int d);

static __declspec(thread) es3_ehframe_t *eh_top;

void es3_eh_push(es3_ehframe_t *f, uint64_t func, jmp_buf *jb)
{
    f->prev = eh_top;
    f->jb = jb;
    f->func = func;
    f->resume = 0;
    f->cs_depth = es3_cs_depth_get();
    eh_top = f;
}

void es3_eh_pop(es3_ehframe_t *f) { eh_top = f->prev; }

/* ---- image access ---------------------------------------------------------
 * RVAs, because every pointer in unwind and EH data is one. */
static uint8_t *img(uint32_t rva)
{
    return (uint8_t *)(es3_eh_image_base + rva);
}

static uint32_t ru32(uint32_t rva)
{
    uint32_t v;
    memcpy(&v, img(rva), 4);
    return v;
}

static uint16_t ru16(uint32_t rva)
{
    uint16_t v;
    memcpy(&v, img(rva), 2);
    return v;
}

static int32_t ri32(uint32_t rva)
{
    int32_t v;
    memcpy(&v, img(rva), 4);
    return v;
}

typedef struct { uint32_t begin, end, unwind; } rfunc_t;

static rfunc_t *pdata;
static uint32_t pdata_n;

static void eh_init(void)
{
    uint32_t pe, dd;
    if (pdata || !es3_eh_image_base) return;
    pe = ru32(0x3c);
    /* OptionalHeader at pe+0x18, data directories 0x70 into it, exception is
     * entry 3. */
    dd = pe + 0x18 + 0x70 + 3 * 8;
    pdata = (rfunc_t *)img(ru32(dd));
    pdata_n = ru32(dd + 4) / 12;
}

static rfunc_t *pdata_find(uint32_t rva)
{
    int lo = 0, hi = (int)pdata_n - 1;
    while (lo <= hi) {
        int m = (lo + hi) / 2;
        if (rva < pdata[m].begin) hi = m - 1;
        else if (rva >= pdata[m].end) lo = m + 1;
        else return &pdata[m];
    }
    return 0;
}

/* ---- virtual unwind -------------------------------------------------------
 * Unwinds one guest frame: restores the non-volatile registers it saved, pops
 * the return address, and leaves *pc and c->rsp describing its caller.
 *
 * The non-volatiles matter as much as rsp does. The lifted body executed the
 * `push rbx` and never reached the matching `pop`, so a frame that catches
 * without this resumes with a callee's value in its own register - which does
 * not fault, and is wrong in a way nothing reports.
 */
static uint64_t *gpr(CPU *c, int n) { return &((uint64_t *)c)[n]; }

/* Where this frame's locals are measured from: rsp once the prologue has run,
 * which is what rsp already is at a call site in the body - unless the function
 * keeps a frame register, and then it is that. Every EH offset (the catch
 * object, the unwind help slot) is relative to this. */
static uint64_t frame_establisher(CPU *c, const rfunc_t *rf)
{
    uint32_t u;
    uint8_t fr, freg, foff, ncodes;

    if (!rf) return c->rsp;
    u = rf->unwind;
    for (;;) {
        uint8_t ver_flags = *img(u);
        ncodes = *img(u + 2);
        fr = *img(u + 3);
        freg = fr & 0xf;
        foff = fr >> 4;
        if (freg) return *gpr(c, freg) - (uint64_t)foff * 16;
        if (!(ver_flags & 0x20)) break;                 /* UNW_FLAG_CHAININFO */
        u = ru32(u + 4 + (((uint32_t)ncodes + 1) & ~1u) * 2 + 8);
    }
    return c->rsp;
}

static int unwind_one(CPU *c, uint64_t *pc, uint64_t *establisher)
{
    uint32_t rva = (uint32_t)(*pc - es3_eh_image_base);
    rfunc_t *rf = pdata_find(rva);
    uint32_t u, off;
    uint64_t frame_base;

    if (!rf) {                          /* leaf: only a return address */
        if (establisher) *establisher = c->rsp;
        *pc = rd64(c->rsp);
        c->rsp += 8;
        return *pc != 0;
    }
    u = rf->unwind;
    off = rva - rf->begin;
    frame_base = c->rsp;

    for (;;) {
        uint8_t ver_flags = *img(u);
        uint8_t ncodes = *img(u + 2);
        uint8_t fr = *img(u + 3);
        uint8_t freg = fr & 0xf, foff = fr >> 4;
        uint32_t codes = u + 4;
        int i;

        /* A frame register pins the establisher frame independently of how far
         * into the prologue we are, which is what the EH offsets are relative
         * to. */
        if (freg) frame_base = *gpr(c, freg) - (uint64_t)foff * 16;

        for (i = 0; i < ncodes; ) {
            uint8_t coff = *img(codes + i * 2);
            uint8_t opinfo = *img(codes + i * 2 + 1);
            uint8_t op = opinfo & 0xf, info = opinfo >> 4;
            int slots = 1;
            int apply = coff <= off;

            switch (op) {
            case 0:                                     /* PUSH_NONVOL */
                if (apply) {
                    *gpr(c, info) = rd64(c->rsp);
                    c->rsp += 8;
                }
                break;
            case 1:                                     /* ALLOC_LARGE */
                if (info == 0) {
                    slots = 2;
                    if (apply) c->rsp += (uint64_t)ru16(codes + (i + 1) * 2) * 8;
                } else {
                    slots = 3;
                    if (apply) c->rsp += ru32(codes + (i + 1) * 2);
                }
                break;
            case 2:                                     /* ALLOC_SMALL */
                if (apply) c->rsp += (uint64_t)info * 8 + 8;
                break;
            case 3:                                     /* SET_FPREG */
                if (apply) c->rsp = *gpr(c, freg) - (uint64_t)foff * 16;
                break;
            case 4:                                     /* SAVE_NONVOL */
                slots = 2;
                if (apply)
                    *gpr(c, info) =
                        rd64(frame_base + (uint64_t)ru16(codes + (i + 1) * 2) * 8);
                break;
            case 5:                                     /* SAVE_NONVOL_FAR */
                slots = 3;
                if (apply)
                    *gpr(c, info) = rd64(frame_base + ru32(codes + (i + 1) * 2));
                break;
            case 8: slots = 2; break;                   /* SAVE_XMM128 */
            case 9: slots = 3; break;                   /* SAVE_XMM128_FAR */
            default: break;                             /* PUSH_MACHFRAME */
            }
            i += slots;
        }
        if (ver_flags & 0x20) {                         /* UNW_FLAG_CHAININFO */
            uint32_t chain = u + 4 + (((uint32_t)ncodes + 1) & ~1u) * 2;
            u = ru32(chain + 8);
            off = 0xffffffffu;                          /* parent codes all apply */
            continue;
        }
        break;
    }
    if (establisher) *establisher = c->rsp;
    *pc = rd64(c->rsp);
    c->rsp += 8;
    return *pc != 0;
}

/* ---- __CxxFrameHandler3 data ---------------------------------------------- */
typedef struct {
    uint32_t magic;
    int32_t  max_state;
    int32_t  unwind_map;
    int32_t  n_try;
    int32_t  try_map;
    int32_t  n_ip;
    int32_t  ip_map;
    int32_t  unwind_help;
} funcinfo_t;

static int funcinfo_at(uint32_t unwind, funcinfo_t *fi)
{
    uint8_t ver_flags, ncodes;
    uint32_t hd, rva;

    if (!unwind) return 0;
    ver_flags = *img(unwind);
    if (!(ver_flags & 0x08)) return 0;                  /* no UNW_FLAG_EHANDLER */
    ncodes = *img(unwind + 2);
    hd = unwind + 4 + (((uint32_t)ncodes + 1) & ~1u) * 2;
    rva = ru32(hd + 4);                                 /* language-specific data */
    if (!rva) return 0;
    memcpy(fi, img(rva), sizeof *fi);
    /* 0x1993052x are the MSVC revisions. Anything else is a different
     * personality routine - __C_specific_handler's scope table, say - and is
     * not ours to interpret. */
    if ((fi->magic & 0xfffffff0u) != 0x19930520u) return 0;
    return 1;
}

static int state_at(const funcinfo_t *fi, uint32_t rva)
{
    int i, st = -1;
    for (i = 0; i < fi->n_ip; i++) {
        if ((uint32_t)ri32(fi->ip_map + 8 * i) > rva) break;
        st = ri32(fi->ip_map + 8 * i + 4);
    }
    return st;
}

static const char *td_name(uint32_t td)
{
    return td ? (const char *)img(td + 16) : 0;
}

/* Does this catch accept the thrown type? ti is the ThrowInfo the guest handed
 * to _CxxThrowException. */
static int catch_matches(uint32_t catch_td, uint32_t ti, uint32_t *size)
{
    uint32_t cta, n, i;
    const char *want;

    if (!catch_td) { *size = 8; return 1; }             /* catch(...) */
    want = td_name(catch_td);
    cta = (uint32_t)ri32(ti + 0x0c);
    if (!cta || !want) return 0;
    n = ru32(cta);
    for (i = 0; i < n && i < 64; i++) {
        uint32_t ct = ru32(cta + 4 + 4 * i);
        const char *have = td_name((uint32_t)ri32(ct + 4));
        if (have && !strcmp(have, want)) {
            *size = ru32(ct + 0x14);
            return 1;
        }
    }
    return 0;
}

/* ---- the throw ------------------------------------------------------------ */
int es3_eh_throw(CPU *c, uint64_t ret_pc, uint64_t obj, uint64_t throw_info)
{
    uint64_t pc = ret_pc, establisher = 0;
    uint32_t ti;
    int depth;

    if (!obj || !throw_info || !ret_pc) return 0;
    eh_init();
    if (!pdata) return 0;
    ti = (uint32_t)(throw_info - es3_eh_image_base);
    if (g_eh_trace)
        fprintf(stderr, "[eh] throw obj %#llx ti %#llx from %#llx, rsp %#llx\n",
                (unsigned long long)obj, (unsigned long long)throw_info,
                (unsigned long long)ret_pc, (unsigned long long)c->rsp);

    for (depth = 0; depth < 512 && pc; depth++) {
        uint32_t rva = (uint32_t)(pc - es3_eh_image_base);
        rfunc_t *rf = pdata_find(rva);
        funcinfo_t fi;

        if (g_eh_trace)
            fprintf(stderr, "[eh]   frame %2d pc %#llx fn %#llx %s\n", depth,
                    (unsigned long long)pc,
                    (unsigned long long)(rf ? es3_eh_image_base + rf->begin : 0),
                    rf ? (funcinfo_at(rf->unwind, &fi) ? "C++ EH" : "-")
                       : "no pdata");

        if (rf && funcinfo_at(rf->unwind, &fi)) {
            uint64_t fn = es3_eh_image_base + rf->begin;
            establisher = frame_establisher(c, rf);
            /* Every pc here is a RETURN address, and a return address can fall
             * into the next state's range. */
            int st = state_at(&fi, rva - 1);
            int t, best_low = -1, found = 0;
            uint32_t handler = 0, obj_off = 0, obj_size = 8;

            for (t = 0; t < fi.n_try; t++) {
                int32_t lo = ri32(fi.try_map + 20 * t);
                int32_t hi = ri32(fi.try_map + 20 * t + 4);
                int32_t nc = ri32(fi.try_map + 20 * t + 12);
                uint32_t ha = (uint32_t)ri32(fi.try_map + 20 * t + 16);
                int k;
                if (st < lo || st > hi || lo <= best_low) continue;
                for (k = 0; k < nc; k++) {
                    uint32_t td = (uint32_t)ri32(ha + 20 * k + 4);
                    uint32_t sz = 8;
                    if (!catch_matches(td, ti, &sz)) continue;
                    best_low = lo;
                    handler = (uint32_t)ri32(ha + 20 * k + 12);
                    obj_off = (uint32_t)ri32(ha + 20 * k + 8);
                    obj_size = sz;
                    found = 1;
                    break;
                }
            }
            if (found) {
                es3_ehframe_t *f;
                uint64_t cont;

                for (f = eh_top; f; f = f->prev)
                    if (f->func == fn) break;
                if (!f) {
                    fprintf(stderr, "[eh] %#llx catches at state %d but has no "
                            "landing pad - not lifted with EH?\n",
                            (unsigned long long)fn, st);
                    return 0;
                }
                if (g_eh_trace)
                    fprintf(stderr, "[eh] entering funclet %#llx frame %#llx "
                            "catchobj +%#x size %u\n",
                            (unsigned long long)(es3_eh_image_base + handler),
                            (unsigned long long)establisher, obj_off, obj_size);
                /* The catch parameter is a local of the catching frame. */
                if (obj_off)
                    memcpy((void *)(establisher + obj_off), (void *)obj,
                           obj_size < 64 ? obj_size : 64);
                /* The catch funclet is guest code: it reaches the parent's
                 * locals through rdx and returns where to continue in rax. */
                c->rdx = establisher;
                c->rcx = 0;
                c->rsp = (establisher - 0x200) & ~(uint64_t)15;
                push64(c, 0);
                dispatch(c, es3_eh_image_base + handler);
                cont = c->rax;
                c->rsp = establisher;
                if (g_eh_trace)
                    fprintf(stderr, "[eh] caught in %#llx (state %d, funclet "
                            "%#llx, frame %#llx), resuming at %#llx\n",
                            (unsigned long long)fn, st,
                            (unsigned long long)(es3_eh_image_base + handler),
                            (unsigned long long)establisher,
                            (unsigned long long)cont);
                f->resume = cont;
                c->rip = cont;
                es3_cs_depth_set(f->cs_depth);
                eh_top = f;
                longjmp(*f->jb, 1);
            }
        }
        if (!unwind_one(c, &pc, &establisher)) break;
    }
    if (g_eh_trace)
        fprintf(stderr, "[eh] no guest frame caught the throw\n");
    return 0;
}
