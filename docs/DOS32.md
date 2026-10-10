# dos32: running a lifted DOS-extender program

`runtime/dos32/` is the host for 32-bit DOS programs that ran under a DOS
extender (DOS/4GW and its kin). The front end is `tools/le/le_parse.py`; the
lifter runs with `Lifter(dos=True)`. Theme Park (Bullfrog, 1994) is the first
title through it.

## The pipeline

```
MAIN.EXE (MZ + LE)
  le_parse.py --base 0x400000 --pe out.exe --seeds seeds.json
  disasm32.py out.exe --full --seed-functions seeds.json
  lift32 Lifter(dos=True, call_pop=...)    # the game's run_lift.py drives this
  link with runtime/dos32/dos32.c + the image as a C array
```

The relocated image goes into the build as data (the game's `run_lift.py`
writes it next to the lifted C), and `dos32_run` copies it into guest memory.

## What the lifter does in DOS mode

`Lifter(dos=True)` turns the instructions Win32 code never uses into host
calls (`recomp_types.h`, "DOS-extender hooks"):

| Instruction | Emitted | Why |
|---|---|---|
| `int n` | `recomp_int(n)` with registers and flags published | All of DOS, DPMI and the BIOS. The handler returns EFLAGS, because DOS reports failure in CF |
| `in`/`out`, `ins*`/`outs*` | `recomp_in8/16/32`, `recomp_out*`, `recomp_ins/outs` | VGA DAC and status, PIT, PIC, keyboard |
| `cli`/`sti`/`hlt` | `recomp_cli/sti/hlt` | When an IRQ may be delivered |
| `iretd` | pop 12 bytes and return | Interrupt handlers are lifted functions |
| `mov es/fs/gs`, `pop`, `les/lfs/lgs` | `recomp_set_seg` | The host keeps each selector's base |
| `es:` override | `ES_BASE + addr` | Under DOS/4GW es is a real selector (the PSP) |
| `ret` to an address the caller did not push | dispatch there | `push x; ret` is a jump; Watcom's `int386x` jumps into a table of `int n; ret` stubs that way |

`call_pop` (any mode): a call whose target starts with `pop r32` is a jump
that hands over its return address (get-EIP, or code that patches its caller),
so the real address is pushed and control tail-jumps.

ds and ss are flat (base 0), as a Watcom flat-model program keeps them, and the
lifter does not track them. That is the main limit; see "Ceilings".

## Guest memory

One 4 GB reservation; guest linear address = offset into it (`g_mem_base`).
The host may be 64-bit, and no host pointer ever appears in guest memory.

| Guest address | What |
|---|---|
| `0x00000000` | environment block (base-0 selector) |
| `0x00000080` | copy of the command tail |
| `0x00000100` | PSP (selector `0x24`) |
| `0x00000400` | BIOS data area: tick count at `0x46C`, shift flags at `0x417` |
| `0x00001000`..`0x9F000` | conventional memory, DPMI `0100h` |
| `0x000A0000` | VGA window |
| image base | the LE objects (Theme Park: `0x400000`) |
| `0x01000000`..`0x05000000` | DPMI `0501h` / int 21h `48h` heap, 64 MB |
| `0xE0000000` | VESA linear frame buffer |
| `0xFFF00000` | default interrupt handlers (dispatch addresses only) |

Why the odd low-memory layout: Watcom's startup reads the command tail with
`repe scasb` and walks the environment through ds, both of which the lifter
treats as flat, while it reads the PSP's own fields through `es:` with a real
base. Putting the environment at 0 and a copy of the tail at 0x80 makes the
flat reads land on the right bytes, and the PSP proper sits at 0x100.

The heap is capped at 64 MB: Theme Park allocates every 16 MB block DPMI will
give it at start, and a DOS-era program has no use for more.

## Interrupts

The guest runs on one host thread. An IRQ is delivered only where lifted code
calls into the host: every loop back-edge (`RECOMP_BACKEDGE`, every 256th with
`RECOMP_YIELD_EVERY=256u`), every `int`, every port read, `sti`, `hlt`. The
host saves every register, flag, segment base and the x87 stack, pushes EFLAGS,
CS and a dummy return address as the CPU would, calls the handler, and restores.
That grain is coarser than hardware's and is what makes it safe.

- Timer: the PIT rate the program programs (port 43h/40h); IRQ 0 goes to
  vector 8 if hooked, else 1Ch. Falling behind drops ticks rather than
  delivering a storm.
- Keyboard: scancodes go to the program's IRQ 1 handler if it hooked vector 9,
  else into the BIOS buffer for int 16h and DOS input.
- Mouse: int 33h, including the `0Ch` event handler. The pointer is absolute:
  the window position maps onto the range the program set with `07h`/`08h`.

## Video

Mode 13h reads the window at `0xA0000`. VESA 640x400 to 1024x768 at 8 bpp,
banked (the 64 KB window swaps with a host copy on a bank switch) or linear.
`dos32_frame` renders the current screen through the DAC for the host.

## Time

Guest time drives the PIT, the BIOS tick, the 70 Hz frame clock and the DOS
clock (int 21h `2Ah`/`2Ch` return start time plus guest time).

- `dos32_speed` scales guest time against real time.
- `dos32_virtual_clock`: guest time moves only by `dos32_advance`, plus a fixed
  sliver per read so a program spinning on the tick count still sees it move.
  A headless run is then the same run every time, and runs as fast as the host
  can. `dos32_idle` waits real time (or advances virtual time) while still
  delivering interrupts: how a host paces a program that ran flat out.

DOS-era programs often have no frame limiter at all. Theme Park counts every
timeout in frames and paces nothing, so natively its name prompt timed out in
a fraction of a second. The host has to choose where to pace; Theme Park does it
on its per-frame input poll.

## Debugging

- `cfg.log`: every `int` (except the noisy mouse and keyboard ones), file opens,
  vector installs, DPMI allocations, and port read counts at exit.
- Anything unhandled is reported once, always: `dos32: unhandled int 21h 0x44 ...`.
- A guest fault prints the guest address, the lifted function, the registers,
  the last indirect calls and the top of the guest stack.
- `DOS32_BREAK=addr`: a hardware write watchpoint on a guest word. Each write
  logs the lifted function and the value. This found Theme Park's attract-mode
  timeout in one run:

  ```
  dos32: write 004C6652 = 0050 in sub_0040A836 (esp 004D2258, ret 00003D80)
  dos32: write 004C6652 = 0000 in sub_0044B55A (esp 004D2230, ret 004D2244)
  ```

## Ceilings

Deliberate shortcuts, each with what would lift it:

- ds is assumed flat. A program that loads ds with a non-zero-based selector
  and reads through it needs ds tracked in the lifter.
- The environment must fit in 128 bytes (the low-memory trick above).
- Implicit es (`stos`, `movs` destination) is flat; only explicit `es:` has a base.
- No unchained VGA (mode X) and no planar EGA: reported once if a program
  turns chain-4 off.
- No sound hardware on the bus: Sound Blaster, MPU-401 and AdLib ports read
  0xFF. Sound belongs at the program's sound-library API (HMI SOS, MSS), in
  the game's host.
- No real-mode code: DPMI `0300h` runs the host's own int handlers in real-mode
  form; `0301h`/`0302h` far calls are reported, not run.
