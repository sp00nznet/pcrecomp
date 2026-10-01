/*
 * ns_objc.c - the NeXTSTEP 3.x Objective-C runtime, over guest memory.
 *
 * Classes are the images' own __OBJC data -- the app's and every shlib's -- so
 * AppKit's hierarchy, instance sizes and ivar layout are the real ones. What
 * _objcInit did at launch is done here once: superclass names become class
 * pointers, metaclasses are linked, categories are attached, class refs are
 * resolved and every selector is uniqued to one canonical string VA.
 *
 * objc_msgSend finds the IMP and jumps to it with the caller's frame intact:
 * a lifted IMP runs from the dispatch table, a shlib IMP binds by its symbol
 * ("-[Window display]") through recomp_lookup_import like any other import.
 *
 * struct objc_class (40 bytes): isa, super_class, name, version, info,
 *   instance_size, ivars, methods, cache, protocols.
 * struct objc_method_list: next, count, {SEL name; char *types; IMP imp}[].
 * struct objc_category (20 bytes): name, class_name, instance_methods,
 *   class_methods, protocols.
 * Part of the pcrecomp toolbox.
 */
#include "ns_runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CLS_ISA(c)     MEM32((c) + 0)
#define CLS_SUPER(c)   MEM32((c) + 4)
#define CLS_NAME(c)    MEM32((c) + 8)
#define CLS_INFO(c)    MEM32((c) + 16)
#define CLS_SIZE(c)    MEM32((c) + 20)
#define CLS_METHODS(c) MEM32((c) + 28)
#define CLS_META        0x2
#define CLS_INITIALIZED 0x4

/* ---- selectors: name -> canonical VA ------------------------------------- */
#define SEL_SLOTS 16384
static struct { const char *name; uint32_t va; } g_sels[SEL_SLOTS];

static uint32_t hash_str(const char *s) {
    uint32_t h = 2166136261u;
    while (*s) h = (h ^ (uint8_t)*s++) * 16777619u;
    return h;
}

/* Canonical SEL for the string at `va`; the first VA seen for a name wins. */
static uint32_t sel_unique(uint32_t va) {
    const char *name = GSTR(va);
    uint32_t h = hash_str(name) & (SEL_SLOTS - 1);
    while (g_sels[h].name && strcmp(g_sels[h].name, name)) h = (h + 1) & (SEL_SLOTS - 1);
    if (!g_sels[h].name) { g_sels[h].name = name; g_sels[h].va = va; }
    return g_sels[h].va;
}

uint32_t ns_sel(const char *name) {
    uint32_t h = hash_str(name) & (SEL_SLOTS - 1);
    while (g_sels[h].name && strcmp(g_sels[h].name, name)) h = (h + 1) & (SEL_SLOTS - 1);
    if (g_sels[h].name) return g_sels[h].va;
    return sel_unique(ns_strdup(name));
}

/* ---- classes -------------------------------------------------------------- */
#define MAX_CLASSES 4096
static uint32_t g_classes[MAX_CLASSES];
static int g_nclasses;

uint32_t ns_class(const char *name) {
    for (int i = 0; i < g_nclasses; i++)
        if (!strcmp(GSTR(CLS_NAME(g_classes[i])), name)) return g_classes[i];
    return 0;
}

static void unique_list(uint32_t ml) {
    for (; ml; ml = MEM32(ml)) {
        uint32_t n = MEM32(ml + 4);
        for (uint32_t i = 0; i < n; i++) {
            uint32_t m = ml + 8 + 12 * i;
            if (MEM32(m)) MEM32(m) = sel_unique(MEM32(m));
        }
    }
}

/* ---- method lookup, with a (class, sel) cache ----------------------------- */
#define CACHE_SLOTS 16384
static struct { uint32_t cls, sel, imp; } g_cache[CACHE_SLOTS];

static uint32_t lookup(uint32_t cls, uint32_t sel) {
    uint32_t h = ((cls >> 3) ^ (sel * 2654435761u)) & (CACHE_SLOTS - 1);
    if (g_cache[h].cls == cls && g_cache[h].sel == sel) return g_cache[h].imp;
    for (uint32_t c = cls; c; c = CLS_SUPER(c))
        for (uint32_t ml = CLS_METHODS(c); ml; ml = MEM32(ml)) {
            uint32_t n = MEM32(ml + 4);
            for (uint32_t i = 0; i < n; i++)
                if (MEM32(ml + 8 + 12 * i) == sel) {
                    uint32_t imp = MEM32(ml + 8 + 12 * i + 8);
                    g_cache[h].cls = cls; g_cache[h].sel = sel; g_cache[h].imp = imp;
                    return imp;
                }
        }
    return 0;
}

static void dispatch(uint32_t imp) {
    recomp_func_t fn = recomp_lookup(imp);
    if (!fn) fn = recomp_lookup_import(imp);
    if (!fn) { fprintf(stderr, "objc: IMP 0x%08X is neither lifted nor a shlib symbol\n", imp); exit(1); }
    uint32_t caller = g_cur_func;
    fn();                                                /* the IMP's ret pops RETADDR */
    g_cur_func = caller;
}

static void send_initialize(uint32_t cls);

/* Stack on entry: RETADDR, self, _cmd, args -- exactly what the IMP expects. */
static void msg_send_from(uint32_t start_cls) {
    uint32_t self = ARG(0), sel = ARG(1);
    if (CLS_INFO(CLS_ISA(self)) & CLS_META && !(CLS_INFO(self) & CLS_INITIALIZED))
        send_initialize(self);
    uint32_t imp = lookup(start_cls, sel);
    if (g_ns_trace) fprintf(stderr, "objc: [%s %s] -> 0x%08X\n",
                            GSTR(CLS_NAME(CLS_INFO(start_cls) & CLS_META ? self : start_cls)), GSTR(sel), imp);
    if (!imp) {
        fprintf(stderr, "objc: %s does not respond to '%s'\n", GSTR(CLS_NAME(start_cls)), GSTR(sel));
        g_edx = 0;
        NS_RET(0);
        return;
    }
    dispatch(imp);
}

static void sh_msgSend(void) {
    uint32_t self = ARG(0);
    if (!self) { g_edx = 0; NS_RET(0); return; }        /* message to nil */
    msg_send_from(CLS_ISA(self));
}

/* objc_msgSendSuper(struct objc_super {receiver, class} *, sel, ...): the
 * search starts at super->class, and the method sees the receiver as self. */
static void sh_msgSendSuper(void) {
    uint32_t sup = ARG(0);
    ARG(0) = MEM32(sup);
    if (!ARG(0)) { g_edx = 0; NS_RET(0); return; }
    msg_send_from(MEM32(sup + 4));
}

uint32_t ns_send(uint32_t self, const char *sel, int n, const uint32_t *args) {
    for (int i = n - 1; i >= 0; i--) PUSH32(g_esp, args[i]);
    PUSH32(g_esp, ns_sel(sel));
    PUSH32(g_esp, self);
    PUSH32(g_esp, RECOMP_RETADDR);
    sh_msgSend();                                        /* pops RETADDR on every path */
    g_esp += 4 * (n + 2);
    return g_eax;
}

static void send_initialize(uint32_t cls) {
    CLS_INFO(cls) |= CLS_INITIALIZED;
    if (CLS_SUPER(cls) && !(CLS_INFO(CLS_SUPER(cls)) & CLS_INITIALIZED))
        send_initialize(CLS_SUPER(cls));
    /* Only an app's own +initialize matters; the shlibs' set up state the
     * host shims own. */
    uint32_t imp = lookup(CLS_ISA(cls), ns_sel("initialize"));
    if (imp && recomp_lookup(imp)) ns_send(cls, "initialize", 0, NULL);
}

uint32_t ns_alloc_instance(uint32_t cls) {
    uint32_t obj = ns_calloc(CLS_SIZE(cls) < 4 ? 4 : CLS_SIZE(cls));
    MEM32(obj) = cls;
    return obj;
}

/* ---- Object (libsys) ------------------------------------------------------ */
static void o_alloc(void)   { NS_RET(ns_alloc_instance(ARG(0))); }
static void o_new(void)     { uint32_t o = ns_alloc_instance(ARG(0));
                              NS_RET(ns_send(o, "init", 0, NULL)); }
static void o_self(void)    { NS_RET(ARG(0)); }
static void o_class(void)   { NS_RET(CLS_INFO(CLS_ISA(ARG(0))) & CLS_META ? ARG(0) : CLS_ISA(ARG(0))); }
static void o_super(void)   { uint32_t c = CLS_INFO(CLS_ISA(ARG(0))) & CLS_META ? ARG(0) : CLS_ISA(ARG(0));
                              NS_RET(CLS_SUPER(c)); }
static void o_name(void)    { uint32_t c = CLS_INFO(CLS_ISA(ARG(0))) & CLS_META ? ARG(0) : CLS_ISA(ARG(0));
                              NS_RET(CLS_NAME(c)); }
static void o_free(void)    { NS_RET(0); }
static void o_isKindOf(void) {
    for (uint32_t c = CLS_ISA(ARG(0)); c; c = CLS_SUPER(c))
        if (c == ARG(2)) { NS_RET(1); return; }
    NS_RET(0);
}
static void o_respondsTo(void) { NS_RET(lookup(CLS_ISA(ARG(0)), ARG(2)) != 0); }
static void o_perform(void)  { uint32_t a[2] = { ARG(3), ARG(4) };
                               NS_RET(ns_send(ARG(0), GSTR(ARG(2)), 2, a)); }
static void sh_objcInit(void) { NS_RET(0); }            /* done in ns_objc_init */
static void sh_getClass(void) { NS_RET(ns_class(GSTR(ARG(0)))); }

static const ns_shim_t objc_shims[] = {
    { "_objc_msgSend", sh_msgSend },        { "_objc_msgSendSuper", sh_msgSendSuper },
    { "__objcInit", sh_objcInit },          { "_objc_getClass", sh_getClass },
    { "+[Object alloc]", o_alloc },         { "+[Object allocFromZone:]", o_alloc },
    { "+[Object new]", o_new },             { "+[Object initialize]", o_self },
    { "-[Object init]", o_self },           { "-[Object self]", o_self },
    { "+[Object class]", o_class },         { "-[Object class]", o_class },
    { "+[Object superclass]", o_super },    { "-[Object superclass]", o_super },
    { "+[Object name]", o_name },           { "-[Object name]", o_name },
    { "-[Object free]", o_free },           { "-[Object isKindOf:]", o_isKindOf },
    { "-[Object respondsTo:]", o_respondsTo },
    { "-[Object perform:]", o_perform },    { "-[Object perform:with:]", o_perform },
    { "-[Object perform:with:with:]", o_perform },
    { NULL, NULL }
};

void ns_objc_init(void) {
    uint32_t addr[64], size[64];
    int n;

    /* classes */
    n = ns_sections("__OBJC", "__class", addr, size, 64);
    for (int s = 0; s < n; s++)
        for (uint32_t c = addr[s]; c + 40 <= addr[s] + size[s] && g_nclasses < MAX_CLASSES; c += 40)
            g_classes[g_nclasses++] = c;

    /* superclass and metaclass links; super_class holds the NAME until now */
    uint32_t root_meta = 0;
    for (int i = 0; i < g_nclasses; i++)
        if (!CLS_SUPER(g_classes[i])) root_meta = CLS_ISA(g_classes[i]);   /* Object */
    for (int i = 0; i < g_nclasses; i++) {
        uint32_t c = g_classes[i], meta = CLS_ISA(c);
        uint32_t sup = CLS_SUPER(c) ? ns_class(GSTR(CLS_SUPER(c))) : 0;
        if (CLS_SUPER(c) && !sup)
            fprintf(stderr, "objc: %s: no superclass %s\n", GSTR(CLS_NAME(c)), GSTR(CLS_SUPER(c)));
        CLS_SUPER(c) = sup;
        CLS_SUPER(meta) = sup ? CLS_ISA(sup) : c;         /* root meta's super is the root class */
        CLS_ISA(meta) = root_meta;
    }

    /* categories: their lists go in front of the class's */
    n = ns_sections("__OBJC", "__category", addr, size, 64);
    for (int s = 0; s < n; s++)
        for (uint32_t cat = addr[s]; cat + 20 <= addr[s] + size[s]; cat += 20) {
            uint32_t cls = ns_class(GSTR(MEM32(cat + 4)));
            if (!cls) continue;
            for (int k = 0; k < 2; k++) {
                uint32_t ml = MEM32(cat + 8 + 4 * k), target = k ? CLS_ISA(cls) : cls;
                if (!ml) continue;
                MEM32(ml) = CLS_METHODS(target);
                CLS_METHODS(target) = ml;
            }
        }

    /* selectors: method lists, then every message ref */
    for (int i = 0; i < g_nclasses; i++) {
        unique_list(CLS_METHODS(g_classes[i]));
        unique_list(CLS_METHODS(CLS_ISA(g_classes[i])));
    }
    n = ns_sections("__OBJC", "__message_refs", addr, size, 64);
    for (int s = 0; s < n; s++)
        for (uint32_t r = addr[s]; r < addr[s] + size[s]; r += 4)
            if (MEM32(r)) MEM32(r) = sel_unique(MEM32(r));

    /* class refs: name -> class */
    n = ns_sections("__OBJC", "__cls_refs", addr, size, 64);
    for (int s = 0; s < n; s++)
        for (uint32_t r = addr[s]; r < addr[s] + size[s]; r += 4) {
            uint32_t c = MEM32(r) ? ns_class(GSTR(MEM32(r))) : 0;
            if (MEM32(r) && !c) fprintf(stderr, "objc: class ref %s unresolved\n", GSTR(MEM32(r)));
            MEM32(r) = c;
        }

    ns_register(objc_shims);
    fprintf(stderr, "objc: %d classes linked\n", g_nclasses);
}
