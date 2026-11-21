#version 450
// DirectDraw's blit (ddraw.c's blit()), as d3d_metal.m's fs_blit: each pixel
// of the destination rectangle from source pixel (sl + x * sw / dw,
// st + y * sh / dh), none outside the source, none whose value in the
// source's own format is in the colour key's range.
layout(location = 0) out vec4 col;
layout(push_constant) uniform BU { layout(offset = 16) ivec4 d; ivec4 s; uvec4 key; uvec4 sh; uvec4 bits; } u;
layout(set = 0, binding = 0) uniform sampler2D src;
void main() {
    int x = int(gl_FragCoord.x) - u.d.x, y = int(gl_FragCoord.y) - u.d.y;
    if (x < 0 || y < 0 || x >= u.d.z || y >= u.d.w) discard;
    int sx = u.s.x + x * u.s.z / u.d.z, sy = u.s.y + y * u.s.w / u.d.w;
    ivec2 sz = textureSize(src, 0);
    if (sx < 0 || sy < 0 || sx >= sz.x || sy >= sz.y) discard;
    vec4 c = texelFetch(src, ivec2(sx, sy), 0);
    if (u.key.x != 0u) {
        uint v = 0u;
        for (int i = 0; i < 4; i++)
            if (u.bits[i] != 0u) v |= uint(clamp(c[i], 0.0, 1.0) * float((1u << u.bits[i]) - 1u) + 0.5) << u.sh[i];
        if (v >= u.key.y && v <= u.key.z) discard;
    }
    col = c;
}
