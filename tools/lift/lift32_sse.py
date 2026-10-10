"""SSE and SSE2 for lift32: the xmm instructions, on lift32's global registers.

lift32 had none. The VC6-era titles never needed it; anything built with
/arch:SSE (VC 2005 and later, for float code) is full of it, and a scalar
`mulss` that lifts as a no-op leaves every float in the game wrong without a
single crash. Tiberium Wars has 212,000 of them, 120,000 of those movss.

The register file is `_xmm[8]` (xmm_t, runtime/recomp32/recomp_types.h),
global beside `_mm` and saved per guest thread by native32. Lanes are
read through the union, so bits pass through untouched and a float lane
never visits the x87. Memory goes through MEM32/MEM64 and xmm_ld/xmm_st.

lift_sse() returns the C for one instruction, or None when it is not an SSE
instruction it knows; lift32 then carries on, and an unknown xmm instruction
still lifts as a counted UNIMPLEMENTED line.

Covered: the scalar and packed float arithmetic, moves, compares (comiss
and friends set EFLAGS the way sahf does, as a FK_EFLAGS word), shuffles and
unpacks, the conversions, ldmxcsr/stmxcsr, and the integer SSE2 forms that
MSVC's own code uses (pxor/pand/por/pandn, psrldq/pslldq, punpck*qdq,
pshufd, paddd/psubd, movd/movq). Not the rest of packed integer SSE2.
Checked against hardware by tools/lift/difftest.py (the sse.* cases).
"""

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_XMM0

XMM_REGS = {X86_REG_XMM0 + i: i for i in range(8)}

# cmpXXps and friends: capstone names the predicate in the mnemonic.
CMP_PRED = {'eq': 0, 'lt': 1, 'le': 2, 'unord': 3, 'neq': 4, 'nlt': 5, 'nle': 6, 'ord': 7}

ARITH = {'add': '({a} + {b})', 'sub': '({a} - {b})', 'mul': '({a} * {b})', 'div': '({a} / {b})',
         'min': 'sse_min{t}({a}, {b})', 'max': 'sse_max{t}({a}, {b})',
         'sqrt': 'sqrt{f}({b})', 'rcp': '(1.0{F} / {b})', 'rsqrt': '(1.0{F} / sqrt{f}({b}))'}
BITWISE = {'and': '{a} & {b}', 'andn': '~{a} & {b}', 'or': '{a} | {b}', 'xor': '{a} ^ {b}'}


def _xi(op):
    return XMM_REGS.get(op.reg) if op.type == X86_OP_REG else None


def is_sse(m, ops):
    """Whether lift_sse should see this instruction at all."""
    return (any(_xi(o) is not None for o in ops) or m.startswith('cvt')
            or m in ('ldmxcsr', 'stmxcsr'))


def lift_sse(L, m, ops, comment):
    """C lines for one SSE instruction; None if it is not one this handles."""
    if not is_sse(m, ops):
        return None

    def addr(op):
        return L._fmt_mem_addr(op.mem)

    def X(op):                     # the whole register (an xmm_t rvalue)
        i = _xi(op)
        return f"_xmm[{i}]" if i is not None else f"xmm_ld({addr(op)})"

    def lane(op, k, kind):         # lane k of a register or memory operand, as kind
        i = _xi(op)
        if i is not None:
            return f"_xmm[{i}].{kind}[{k}]"
        size = 8 if kind in ('f64', 'u64') else 4
        a = addr(op) + (f" + {k * size}" if k else '')
        if kind == 'f32':
            return f"sse_f32(MEM32({a}))"
        if kind == 'f64':
            return f"sse_f64(MEM64({a}))"
        return f"MEM{size * 8}({a})"

    def one(c):
        return [f"{c} {comment}"]

    d = ops[0] if ops else None
    s = ops[1] if len(ops) > 1 else None
    di = _xi(d) if d is not None else None

    # ---- MXCSR -------------------------------------------------------------
    if m == 'ldmxcsr':
        return one(f"g_mxcsr = MEM32({addr(d)});")
    if m == 'stmxcsr':
        return one(f"MEM32({addr(d)}) = g_mxcsr;")

    # ---- moves -------------------------------------------------------------
    # movss/movsd: a load from memory zeroes the rest of the register; between
    # registers only the low lane moves.
    if m in ('movss', 'movsd') and len(ops) == 2:
        k = 'u32' if m == 'movss' else 'u64'
        mem = 'MEM32' if m == 'movss' else 'MEM64'
        if di is not None and _xi(s) is not None:
            return one(f"_xmm[{di}].{k}[0] = _xmm[{_xi(s)}].{k}[0];")
        if di is not None:
            return one(f"_xmm[{di}].u64[0] = {mem}({addr(s)}); _xmm[{di}].u64[1] = 0;")
        return one(f"{mem}({addr(d)}) = _xmm[{_xi(s)}].{k}[0];")
    if m in ('movaps', 'movups', 'movapd', 'movupd', 'movdqa', 'movdqu', 'lddqu',
             'movntps', 'movntpd', 'movntdq'):
        if di is not None:
            return one(f"_xmm[{di}] = {X(s)};")
        return one(f"xmm_st({addr(d)}, _xmm[{_xi(s)}]);")
    if m in ('movlps', 'movlpd', 'movhps', 'movhpd'):
        h = 1 if m.startswith('movh') else 0
        if di is not None:
            return one(f"_xmm[{di}].u64[{h}] = MEM64({addr(s)});")
        return one(f"MEM64({addr(d)}) = _xmm[{_xi(s)}].u64[{h}];")
    if m == 'movlhps':
        return one(f"_xmm[{di}].u64[1] = _xmm[{_xi(s)}].u64[0];")
    if m == 'movhlps':
        return one(f"_xmm[{di}].u64[0] = _xmm[{_xi(s)}].u64[1];")
    if m == 'movd':
        if di is not None:
            return one(f"_xmm[{di}].u64[0] = (uint32_t)({L._fmt_read(s)}); _xmm[{di}].u64[1] = 0;")
        return one(f"{L._fmt_write(d, f'_xmm[{_xi(s)}].u32[0]')};")
    if m == 'movq':
        if di is not None:
            src = L._mm_read(s) if _xi(s) is None else f"_xmm[{_xi(s)}].u64[0]"
            return one(f"_xmm[{di}].u64[0] = {src}; _xmm[{di}].u64[1] = 0;")
        return one(f"{L._mm_write(d, f'_xmm[{_xi(s)}].u64[0]')};")
    if m == 'movdq2q':
        return one(f"{L._mm_write(d, f'_xmm[{_xi(s)}].u64[0]')};")
    if m == 'movq2dq':
        return one(f"_xmm[{di}].u64[0] = {L._mm_read(s)}; _xmm[{di}].u64[1] = 0;")
    if m in ('movmskps', 'movmskpd'):
        n = 4 if m == 'movmskps' else 2
        k = 'u32' if n == 4 else 'u64'
        sh = 31 if n == 4 else 63
        bits = ' | '.join(f"(uint32_t)((_xmm[{_xi(s)}].{k}[{j}] >> {sh}) << {j})" for j in range(n))
        return one(f"{L._fmt_write(d, f'({bits})')};")

    # ---- compares into EFLAGS ------------------------------------------------
    if m in ('comiss', 'ucomiss', 'comisd', 'ucomisd'):
        k = 'f32' if m.endswith('ss') else 'f64'
        L._flag_state = ('eflags', '_flag_a, _flag_b')
        L._flag_seq += 1
        return one(f"_flag_a = SSE_COMI(_xmm[{di}].{k}[0], {lane(s, 0, k)}); _flag_b = 0; "
                   f"_cf = _flag_a & 1u;")

    # ---- arithmetic ----------------------------------------------------------
    for suffix, kind, n in (('ss', 'f32', 1), ('ps', 'f32', 4), ('sd', 'f64', 1), ('pd', 'f64', 2)):
        if not m.endswith(suffix):
            continue
        op = m[:-2]
        if op in ARITH:
            t, f, F = ('f', 'f', 'f') if kind == 'f32' else ('d', '', '')
            ct = 'float' if kind == 'f32' else 'double'
            if n == 1:     # scalar: lane 0 only, the rest of the register stays
                expr = ARITH[op].format(a=f"_xmm[{di}].{kind}[0]", b="_s", t=t, f=f, F=F)
                return one(f"{{ {ct} _s = {lane(s, 0, kind)}; _xmm[{di}].{kind}[0] = ({ct}){expr}; }}")
            out = []
            for j in range(n):
                expr = ARITH[op].format(a=f"_d.{kind}[{j}]", b=f"_s{j}", t=t, f=f, F=F)
                out.append(f"_d.{kind}[{j}] = ({'float' if kind == 'f32' else 'double'}){expr};")
            srcs = ' '.join(f"{'float' if kind == 'f32' else 'double'} _s{j} = {lane(s, j, kind)};"
                            for j in range(n))
            return one(f"{{ {srcs} xmm_t _d = _xmm[{di}]; {' '.join(out)} _xmm[{di}] = _d; }}")
        if op in BITWISE and suffix in ('ps', 'pd'):
            return _bitwise(BITWISE[op], di, X(s), comment)
        if op.startswith('cmp') and op[3:] in CMP_PRED or op == 'cmp':
            p = CMP_PRED[op[3:]] if op != 'cmp' else ops[2].imm & 7
            k = 'u32' if kind == 'f32' else 'u64'
            mask = '' if kind == 'f32' else '(uint64_t)(int64_t)(int32_t)'
            out = ' '.join(f"_xmm[{di}].{k}[{j}] = {mask}sse_cmp_pred(_xmm[{di}].{kind}[{j}], _s{j}, {p});"
                           for j in range(n))
            srcs = ' '.join(f"double _s{j} = {lane(s, j, kind)};" for j in range(n))
            return one(f"{{ {srcs} {out} }}")

    # ---- shuffles and unpacks --------------------------------------------------
    if m == 'shufps':
        i = ops[2].imm
        sel = [f"_d.u32[{i & 3}]", f"_d.u32[{(i >> 2) & 3}]", f"_s.u32[{(i >> 4) & 3}]", f"_s.u32[{(i >> 6) & 3}]"]
        return one(f"{{ xmm_t _s = {X(s)}, _d = _xmm[{di}]; "
                   + ' '.join(f"_xmm[{di}].u32[{j}] = {v};" for j, v in enumerate(sel)) + " }")
    if m == 'shufpd':
        i = ops[2].imm
        return one(f"{{ xmm_t _s = {X(s)}, _d = _xmm[{di}]; _xmm[{di}].u64[0] = _d.u64[{i & 1}]; "
                   f"_xmm[{di}].u64[1] = _s.u64[{(i >> 1) & 1}]; }}")
    if m == 'pshufd':
        i = ops[2].imm
        return one(f"{{ xmm_t _s = {X(s)}; "
                   + ' '.join(f"_xmm[{di}].u32[{j}] = _s.u32[{(i >> (2 * j)) & 3}];" for j in range(4)) + " }")
    if m in ('unpcklps', 'unpckhps'):
        a, b = (0, 1) if m == 'unpcklps' else (2, 3)
        return one(f"{{ xmm_t _s = {X(s)}, _d = _xmm[{di}]; _xmm[{di}].u32[0] = _d.u32[{a}]; "
                   f"_xmm[{di}].u32[1] = _s.u32[{a}]; _xmm[{di}].u32[2] = _d.u32[{b}]; "
                   f"_xmm[{di}].u32[3] = _s.u32[{b}]; }}")
    if m in ('unpcklpd', 'unpckhpd', 'punpcklqdq', 'punpckhqdq'):
        h = 1 if 'h' in m[5:7] or m == 'punpckhqdq' else 0
        return one(f"{{ xmm_t _s = {X(s)}, _d = _xmm[{di}]; _xmm[{di}].u64[0] = _d.u64[{h}]; "
                   f"_xmm[{di}].u64[1] = _s.u64[{h}]; }}")

    # ---- integer SSE2 on xmm ---------------------------------------------------
    if m in ('pxor', 'pand', 'por', 'pandn') and di is not None:
        return _bitwise(BITWISE[{'pxor': 'xor', 'pand': 'and', 'por': 'or', 'pandn': 'andn'}[m]],
                        di, X(s), comment)
    if m in ('psrldq', 'pslldq'):
        n = ops[1].imm
        if n > 15:
            return one(f"_xmm[{di}].u64[0] = _xmm[{di}].u64[1] = 0;")
        idx = f"_k + {n}" if m == 'psrldq' else f"_k - {n}"
        return one(f"{{ xmm_t _s = _xmm[{di}]; for (int _k = 0; _k < 16; _k++) "
                   f"_xmm[{di}].u8[_k] = ({idx} >= 0 && {idx} < 16) ? _s.u8[{idx}] : 0; }}")
    if m in ('paddd', 'psubd', 'paddq', 'psubq') and di is not None:
        k, n = ('u32', 4) if m.endswith('d') else ('u64', 2)
        o = '+' if m.startswith('padd') else '-'
        return one(f"{{ xmm_t _s = {X(s)}; for (int _k = 0; _k < {n}; _k++) "
                   f"_xmm[{di}].{k}[_k] {o}= _s.{k}[_k]; }}")

    # ---- conversions ------------------------------------------------------------
    if m in ('cvtsi2ss', 'cvtsi2sd'):
        k, t = ('f32', 'float') if m == 'cvtsi2ss' else ('f64', 'double')
        return one(f"_xmm[{di}].{k}[0] = ({t})(int32_t)({L._fmt_read(s)});")
    if m in ('cvtss2si', 'cvttss2si', 'cvtsd2si', 'cvttsd2si'):
        k = 'f32' if 'ss' in m else 'f64'
        trunc = 1 if m.startswith('cvtt') else 0
        return one(f"{L._fmt_write(d, f'(uint32_t)sse_cvt_i32((double){lane(s, 0, k)}, {trunc})')};")
    if m == 'cvtss2sd':
        return one(f"_xmm[{di}].f64[0] = (double){lane(s, 0, 'f32')};")
    if m == 'cvtsd2ss':
        return one(f"_xmm[{di}].f32[0] = (float){lane(s, 0, 'f64')};")
    if m in ('cvtps2pi', 'cvttps2pi'):
        trunc = 1 if m.startswith('cvtt') else 0
        lo = f"(uint32_t)sse_cvt_i32((double){lane(s, 0, 'f32')}, {trunc})"
        hi = f"(uint32_t)sse_cvt_i32((double){lane(s, 1, 'f32')}, {trunc})"
        return one(f"{L._mm_write(d, f'((uint64_t){hi} << 32 | {lo})')};")
    if m == 'cvtpi2ps':
        return one(f"{{ uint64_t _v = {L._mm_read(s)}; _xmm[{di}].f32[0] = (float)(int32_t)_v; "
                   f"_xmm[{di}].f32[1] = (float)(int32_t)(_v >> 32); }}")
    if m == 'cvtdq2ps':
        return one(f"{{ xmm_t _s = {X(s)}; for (int _k = 0; _k < 4; _k++) _xmm[{di}].f32[_k] = (float)_s.i32[_k]; }}")
    if m in ('cvtps2dq', 'cvttps2dq'):
        trunc = 1 if m.startswith('cvtt') else 0
        return one(f"{{ xmm_t _s = {X(s)}; for (int _k = 0; _k < 4; _k++) "
                   f"_xmm[{di}].i32[_k] = sse_cvt_i32((double)_s.f32[_k], {trunc}); }}")
    if m == 'cvtps2pd':
        return one(f"{{ float _a = {lane(s, 0, 'f32')}, _b = {lane(s, 1, 'f32')}; "
                   f"_xmm[{di}].f64[0] = _a; _xmm[{di}].f64[1] = _b; }}")
    if m == 'cvtpd2ps':
        return one(f"{{ xmm_t _s = {X(s)}; _xmm[{di}].f32[0] = (float)_s.f64[0]; "
                   f"_xmm[{di}].f32[1] = (float)_s.f64[1]; _xmm[{di}].u64[1] = 0; }}")
    return None


def _bitwise(fmt, di, src, comment):
    expr = fmt.format(a=f"_xmm[{di}].u32[_k]", b="_s.u32[_k]")
    return [f"{{ xmm_t _s = {src}; for (int _k = 0; _k < 4; _k++) _xmm[{di}].u32[_k] = {expr}; }} {comment}"]
