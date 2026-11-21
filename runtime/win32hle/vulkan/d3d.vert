#version 450
// d3d_vulkan.c's vertex stage: a screen-space vertex (x, y in pixels, z,
// 1/w) to clip space, as d3d_metal.m's vs. Vulkan's y runs down, as the
// screen's does.
layout(location = 0) in vec4 p;
layout(location = 1) in vec4 dif;
layout(location = 2) in vec4 spec;
layout(location = 3) in vec2 uv;
layout(push_constant) uniform PC { vec2 size; } pc;
layout(location = 0) out vec4 o_dif;
layout(location = 1) out vec4 o_spec;
layout(location = 2) out vec2 o_uv;
void main() {
    float rhw = p.w;
    float w = rhw > 0.0 && !isinf(rhw) && !isnan(rhw) ? 1.0 / rhw : 1.0;
    float nx = p.x / pc.size.x * 2.0 - 1.0, ny = p.y / pc.size.y * 2.0 - 1.0;
    gl_Position = vec4(nx * w, ny * w, p.z * w, w);
    o_dif = dif, o_spec = spec, o_uv = uv;
    gl_PointSize = 1.0;
}
