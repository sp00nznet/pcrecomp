# Ports: consoles, Android and the browser

Two titles already run far from the PC they were made for:
[SkiFree](https://github.com/sp00nznet/skifree) (13 targets, a decompile) and
[Link's Awakening DX portable](https://github.com/sp00nznet/linksawakening-portable)
(13 targets, a Game Boy lift). Both build every target from the user's own copy,
inside Docker, from one table. `ports/` is that machinery, taken out so a
pcrecomp title can use it:

| Path | What |
|---|---|
| `ports/setup-consoles.sh` | The Docker driver both repos had, with the game taken out. Run from a title's repo; it reads that title's `ports/ports.conf` and `ports/targets.tsv` (format in the script's header). |
| `ports/sdl2lite/` | A software slice of SDL2 for toolchains with none (PS3, Dreamcast, Xbox 360): one framebuffer, a backend per console. It has what SkiFree calls; a title that calls more adds it here. `backend_ppm.c` is a headless desktop backend for testing. |
| `ports/recipes/` | SkiFree's build script for each target and both repos' `targets.tsv`: the image, compiler flags, libraries and packaging each toolchain wants. Copy the ones a title needs. They source SkiFree's `env.sh` (here as `env.skifree.sh`). |

## Targets

| Target | CPU | Bytes | RAM | SDL2 | Image |
|---|---|---|---|---|---|
| Browser (wasm) | wasm32 | LE | grows | Emscripten's | `emscripten/emsdk` |
| Android | arm64, x86_64 | LE | plenty | build it (recipe) | `recipes/android.Dockerfile` |
| PS Vita | ARM | LE | 512 MB | yes | `vitasdk/vitasdk` |
| 3DS | ARM | LE | 64 MB (128 New) | yes | `devkitpro/devkitarm` |
| PSP | MIPS | LE | 32 MB (64 slim) | yes | `pspdev/pspdev` |
| PS2 | MIPS | LE | 32 MB | yes | `ps2dev/ps2dev` |
| Original Xbox | x86 | LE | 64 MB | nxdk's | `ghcr.io/xboxdev/nxdk` |
| PS4 | x86-64 | LE | plenty | OpenOrbis | `openorbisofficial/toolchain` |
| Dreamcast | SH-4 | LE | 16 MB | sdl2lite | `kazade/dreamcast-sdk` |
| Wii / GameCube | PowerPC | **BE** | 88 / 24 MB | yes | `devkitpro/devkitppc` |
| PS3 | PowerPC | **BE** | 256 MB | sdl2lite | `ps3dev/ps3dev:submodules` |
| Xbox 360 | PowerPC | **BE** | 512 MB | sdl2lite | `free60/libxenon` |

## What a lift needs that a decompile doesn't

- **Address space.** dos32 reserves 4 GB so every guest address is valid. No
  32-bit host can. Build with `-DDOS32_SMALL_HOST` (and `-DDOS32_MEM=` to size
  it, default 64 MB) for one block with the frame buffer moved to its top.
  Theme Park passes its conformance script this way.
- **Byte order.** Lifted x86 reads guest memory with plain host loads
  (`MEM32` in `recomp_types.h`). On the PowerPC targets every one needs a
  byte swap. Not done yet: the little-endian targets come first.
- **Threads.** dos32 delivers IRQs at points the lifted code calls in, so the
  guest needs no signals. A title's host may still use threads (Theme Park's
  game thread, its audio feeder); the browser needs `-pthread` and a page
  served cross-origin isolated, or the game loop moved onto `ASYNCIFY`.
- **Tail calls.** A loop the lift splits across functions jumps from one to
  the next with `RECOMP_ITAIL`. Native compilers make those jumps; wasm grows
  the stack on each and overflows it within seconds. `RECOMP_ITAIL` now uses
  clang's `musttail`, so build wasm with `-mtail-call`.
- **Code size.** A lift is tens of MB of C. LA's notes: split it across
  files, and expect slow PowerPC and wasm compiles.

[LA's PORTING.md](https://github.com/sp00nznet/linksawakening-portable/blob/main/docs/PORTING.md)
has the per-console gotchas (PSP VRAM aliasing, PS2 IRX sets, Vita colour
order, Dreamcast RAM).

## Titles

| Title | Runtime | Status |
|---|---|---|
| Theme Park | dos32 | Plays in Chrome: intro, menus, a new park with its clock running (themepark's `wasm` branch). No music yet. |
