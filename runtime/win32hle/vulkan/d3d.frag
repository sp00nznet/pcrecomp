#version 450
// d3d_raster.c's shade(), as d3d_metal.m's fs: stage 0's colour and alpha
// operations, colour key, alpha test, specular and fog, the texture read
// texel by texel as the software renderer reads it.
layout(location = 0) in vec4 dif;
layout(location = 1) in vec4 spec;
layout(location = 2) in vec2 uv;
layout(location = 0) out vec4 col;
// a: tex, colorkey, bilinear, wrap_u; b: wrap_v, colorop, colorarg1, colorarg2;
// c: alphaop, alphaarg1, alphaarg2, alphatest; d: alphafunc, specular, fog, 0;
// fogc.w: alpharef
layout(push_constant) uniform U { layout(offset = 16) ivec4 a; ivec4 b; ivec4 c; ivec4 d; vec4 tf; vec4 fogc; } u;
layout(set = 0, binding = 0) uniform sampler2D tx;
layout(set = 0, binding = 1) uniform usampler2D kt;
bool cmp(int f, float a, float b) {
    switch (f) { case 1: return false; case 2: return a < b; case 3: return a == b; case 4: return a <= b;
    case 5: return a > b; case 6: return a != b; case 7: return a >= b; default: return true; }
}
vec4 arg(int a, vec4 tex, vec4 dif, vec4 tf) {
    vec4 o = (a & 0xF) == 2 ? tex : (a & 0xF) == 3 ? tf : dif;
    if ((a & 0x20) != 0) o = vec4(o.w);
    if ((a & 0x10) != 0) o = 1.0 - o;
    return o;
}
vec4 op(int op, vec4 a, vec4 b) {
    switch (op) {
    case 2: return a; case 3: return b; case 4: return a * b;
    case 5: return min(a * b * 2.0, vec4(1)); case 6: return min(a * b * 4.0, vec4(1));
    case 7: return min(a + b, vec4(1)); case 8: return clamp(a + b - 0.5, vec4(0), vec4(1));
    case 10: return max(a - b, vec4(0)); case 11: return min(a + b - a * b, vec4(1));
    default: return b;
    }
}
int wrap(int i, int n, bool w) { if (w) { i %= n; return i < 0 ? i + n : i; } return clamp(i, 0, n - 1); }
void main() {
    vec4 tex = vec4(1);
    bool has = u.a.x != 0, ck = u.a.y != 0;
    if (has) {
        ivec2 sz = textureSize(tx, 0);
        int w = sz.x, h = sz.y;
        bool wu = u.a.w != 0, wv = u.b.x != 0;
        if (u.a.z == 0) {
            ivec2 p = ivec2(wrap(int(floor(uv.x * w)), w, wu), wrap(int(floor(uv.y * h)), h, wv));
            tex = texelFetch(tx, p, 0);
            if (ck && texelFetch(kt, p, 0).x != 0u) discard;
        } else {
            float x = uv.x * w - 0.5, y = uv.y * h - 0.5;
            float x0 = floor(x), y0 = floor(y), fx = x - x0, fy = y - y0;
            int xs[2] = int[2](wrap(int(x0), w, wu), wrap(int(x0) + 1, w, wu));
            int ys[2] = int[2](wrap(int(y0), h, wv), wrap(int(y0) + 1, h, wv));
            float wt[4] = float[4]((1.0 - fx) * (1.0 - fy), fx * (1.0 - fy), (1.0 - fx) * fy, fx * fy);
            // A keyed texel counts as transparent black, so edges fade instead of fringing.
            vec4 acc = vec4(0); float kw = 0.0;
            for (int k = 0; k < 4; k++) {
                ivec2 p = ivec2(xs[k & 1], ys[k >> 1]);
                if (ck && texelFetch(kt, p, 0).x != 0u) { kw += wt[k]; continue; }
                acc += texelFetch(tx, p, 0) * wt[k];
            }
            if (ck && kw > 0.5) discard;
            tex = acc;
        }
    }
    col.xyz = has && u.b.y != 1 ? op(u.b.y, arg(u.b.z, tex, dif, u.tf), arg(u.b.w, tex, dif, u.tf)).xyz : dif.xyz;
    col.w = has && u.c.x != 1 ? op(u.c.x, arg(u.c.y, tex, dif, u.tf), arg(u.c.z, tex, dif, u.tf)).w : dif.w;
    if (u.c.w != 0 && !cmp(u.d.x, col.w * 255.0, u.fogc.w)) discard;
    if (u.d.y != 0) col.xyz = min(col.xyz + spec.xyz, vec3(1));
    if (u.d.z != 0) { float f = clamp(spec.w, 0.0, 1.0); col.xyz = col.xyz * f + u.fogc.xyz * (1.0 - f); }
}
