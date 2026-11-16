# Contributors

Thank you to everyone who has contributed code, fixes, testing, or a hard-won
debugging insight. This file is the canonical record of who did what; the
CHANGELOG tells the story change by change, but credit lives here. The tools
and published work pcrecomp builds on are credited in the README's
[Credits](README.md#credits).

If you've contributed and aren't listed (or a line is wrong), open a PR against
this file. We want every name right.

---

## Maintainer

### Ned Heller ([@sp00nznet](https://github.com/sp00nznet))
Project creator and maintainer. The disassemblers and lifters (x86-16, -32 and
-64), the PE, NE and Mach-O tooling, the native32 and win32hle runtimes, the DRM
unwrappers, and the game projects that built them.

---

## Contributors

### Chris Pressland ([@cpressland](https://github.com/cpressland))
**native32 under Wine** (#55): found why lifted programs could not take a
callback under Wine. Wine leaves DEP off unless a process asks for it, so the
first fetch from the guest's code made the page executable and ran the original
machine code, silently; and under Rosetta (CrossOver on an Apple Silicon Mac)
Wine reports an instruction fetch as a read. `native32_init` now turns DEP on,
and the fault handler takes a read of the faulting instruction's own address as
a fetch. This is what lets native32 games run on macOS and Linux under Wine; it
was found and proved with Red Alert 2 on a Mac (sp00nznet/redalert2-recomp#1).

**win32hle on a 64-bit host** (#100): win32hle runs on macOS and 64-bit Linux,
with the guest's 4 GB as one block of host memory (`guest_mem.c`): pointer
conversions throughout, COM objects and their data kept in guest memory, guest
varargs read from guest memory, macOS's 16 KB pages, and selftests that build
64-bit.

**DirectX 6** (#154, #158): DirectDraw 4 and Direct3D 3 in software
(IDirectDraw4 and its surfaces, IDirect3D3 and Device3, a multithreaded
perspective-correct, z-buffered, bilinear, alpha-blending rasteriser) and a
focused first window; then the review follow-ups: the texture cache resized
with its surface, the z-buffer released, a uniqueness value per surface, and
`ddraw_selftest.c`.

**Theme Park World's input, text and sound** (#159, #160, #161, #164):
DirectInput 3 and 5 on the system mouse and keyboard; `lfWidth` stretching and
squeezing text (the park's sign-fitting loop hung without it); the mouse held
in the picture, with a HiDPI fix to the cursor warp; and DirectSound's play
cursor moving between mixes (the movie audio ran a lap ahead). All found and
proved with Theme Park World on a Mac (cpressland/tpw-recomp).

**Direct3D on the GPU through Metal** (#163): `d3d_metal.m` behind a new
`d3d_gpu.h` seam, shading as the software rasterizer does, with the flip handed
to the presenter without the game waiting, and the frame pacing split out of it
into its own change. Theme Park World on an M1 Pro went from 7 to 80 frames a
second.

### Haukur Rósinkranz ([@hauxir](https://github.com/hauxir))
**win32hle in the browser** (#148): an Emscripten/WebAssembly host for the
win32hle layer, so a lifted game runs in a web page. The guest image sits in
linear memory, DirectSound plays through a shared-memory ring drained by an
AudioWorklet, frames go to the page's WebGL presenter, and Bink movies are
played by the page. Fixes the web port turned up apply to every host: a Bink
stub that reads the real `.bik` header instead of failing (Yuri's Revenge
crashed without it), INI, `_lcreat` and docfile writes routed to the mod
overlay, and kept directory listings for the case-insensitive path match
(on the browser's storage, listing on every miss took minutes). Built and proved
with Red Alert 2 (sp00nznet/redalert2-recomp).

### Daniel Nylander ([@yeager](https://github.com/yeager))
**Malformed input, and free disk space** (#145, #146, #147): `unlzexe.py`
bounds-checks the header, the relocation tables and every back-reference
(before, a bad stream could read bytes from the end of the output through
Python's negative indexing); the 16-bit MZ analyzer validates the header
against the file before using it; and win32hle gained
`GetDiskFreeSpaceExA`, with lexical `..` now stopping at a mapped drive's
root, as it does on Windows. Each came with tests.

### neurocontrarian ([@neurocontrarian](https://github.com/neurocontrarian))
**Operation Flashpoint on win32hle** (#168, #169, #170, #171, #172, #173,
#174, #175): a run of fixes and speed-ups found by bringing Operation
Flashpoint: Cold War Assault up as a native Linux build. `VirtualFree
(MEM_RELEASE)` fails as on Windows for an address inside a reservation (it
was freeing the game's whole memory pool), and a handle closed during a wait
counts as signalled. A based host can give the guest the 4 GB a
large-address-aware program gets (`hle_vm_any_hi`), draw the game with its own
OpenGL or Vulkan renderer (`hle_screen_gl`), and time each import on the main
thread for a profiler. Winsock gained `select` and a hook after a UDP
broadcast, which is how OFP's server list fills from Internet servers. In the
lifter's runtime: opt-in caches for indirect calls (loading stalls 3.8 s to
3.0 s) and the x87 stack as a moving pointer with a function's own pushes in
locals (+47 % frames in x87-heavy code).

**DirectSound 3D and DirectSound 8** (#176): 3D buffers and the listener
(distance attenuation and panning, normal and head-relative), `DirectSoundCreate8`
and the `IDirectSoundBuffer8` methods, with a selftest. Operation Flashpoint
places its sounds with it.

### Peter Jorgensen ([@pete-jorgensen](https://github.com/pete-jorgensen))
**loop and jecxz leaving the function** (#166): `loop`, `loope`, `loopne`,
`jecxz` and `jcxz` whose target was not a block of the function being lifted
became a `goto` to a label that did not exist, and the generated C failed to
compile. They now dispatch with `RECOMP_ITAIL` and return, as `jmp` and `jcc`
do, through one helper (`_branch_to`), with a test
(`tools/lift/test_loop_exits.py`). Found on Operation Neptune's `ONWIN32.EXE`.
A follow-up test covers `jcxz` with the address-size prefix (#191).
