# SafeDisc 1.x: unwrapping by emulating the loader

This is the mechanism of SafeDisc 1.x copy protection as measured on Microsoft
Flight Simulator 2000 (`FS2000.EXE` + `FS2000.ICD`, SafeDisc `BoG_ *90.0`,
secdrv.sys dated 1999), and how `tools/drm/safedisc1.py` unwraps it without a
disc, a driver, or launching anything. **Status: work in progress** — the loader
runs headless through the anti-debug gauntlet, the secdrv challenge and into the
`.txt` reconstruction, but the per-page reconstruction does not yet match the
oracle (see "Where it actually diverges"), so no decrypted ICD is produced yet.
It is the reference for finishing that tool, and it applies to every SafeDisc 1
title (Crimson Skies, X-Wing Alliance, the many others on the usual-suspects
list — see "Which SafeDisc 1 titles this covers"), because the pieces are shared.

The goal is a decrypted, importable PE for the lifter — not a working disc
check. We measure the game; we do not help anyone skip buying it.

## The two files

A SafeDisc 1 title ships as:

- **`GAME.EXE`** — a normal MSVC program. Its `.text` is cleartext (a standard
  CRT start-up and `WinMain`), but it carries extra `.txt`/`.txt2` sections at
  ~8 bits/byte: the obfuscated SafeDisc shell, reached from `WinMain` as a
  `jmp`-maze (overlapping instructions, jumps into mid-instruction — junk that
  defeats a linear or recursive disassembler but runs fine under emulation).
- **`GAME.ICD`** — the real program. A valid PE whose `.text` is encrypted
  (~7.98 bits/byte) and whose `kernel32`/`user32` imports are stripped; its
  entry point sits *inside* the encrypted `.text`, so it cannot self-decrypt.
  The loader decrypts it.

Both are linked at `0x400000`, which is the first hint that the ICD runs in a
*separate* process, not inside the loader.

## What the loader does (measured, in order)

Driven from `GAME.EXE`'s clean entry point under Unicorn, the loader:

1. Runs the MSVC CRT start-up (heap, TLS, `_setenvp`, `_cinit`).
2. Creates a 0x30-byte named section, `ladybird` / `SAFEDISC_ERROR_%08x` (the
   pid) — the shell↔child IPC control block.
3. `GetProfileIntA("C-DILLA", "INTERACTIVE"/"TESTMESSAGES")` — C-DILLA config.
4. Opens `CLCD32.DLL`, `CLCD16.DLL`, `SECDRV.SYS` from the CD drive and calls
   `drvmgt.dll!Setup`, which installs the `secdrv` kernel driver.
5. Opens `GAME.ICD`.
6. **Anti-debug gauntlet.** All of these must answer "no debugger":
   - `CreateFileA("\\.\SICE")`, `"\\.\NTICE")`, … → must fail (`INVALID_HANDLE_VALUE`).
     Succeeding tells SafeDisc SoftICE is loaded.
   - `NtQueryInformationProcess(ProcessDebugPort)` → port 0, `STATUS_SUCCESS`.
   - `IsDebuggerPresent` → 0; reads `KUSER_SHARED_DATA` at `0x7FFE0000`.
7. **Driver authentication.** `DeviceIoControl(\\.\Secdrv, 0xEF002407,
   in=1300, out=1552)` — a challenge/response with secdrv. The loader retries
   256 times and then traps if the 1552-byte response is wrong.
8. Only once authentication passes: it decrypts the ICD and **process-hollows**
   it into a child — `CreateProcess` (suspended), `WriteProcessMemory` the
   decrypted sections, `SetThreadContext` with `Eip` = the ICD's real OEP,
   `ResumeThread`.

The decryption is **gated on step 7**: with the secdrv response stubbed, step 8
never happens (no `CreateProcess`, no `WriteProcessMemory`). So the decryption
key is derived from the secdrv response, and there is no shortcut around it.

## The emulator

`tools/drm/safedisc1.py` maps the loader and answers its imports in Python, the
same shape as `drm/emu_unpack.py`: a GDT/TEB/PEB, a thunk per IAT entry, a
`UC_HOOK_CODE` over the thunk page that dispatches to `api_*` handlers, and
`ArgcResolver` (tools/pe/stdcall_argc.py) for the stdcall purge of any import
without a hand-written handler, so the stack never silently desynchronises.

### Done so far

- **Steps 1–6** (CRT, C-DILLA set-up, the full anti-debug gauntlet).
- **Step 7, the secdrv authentication — `tools/drm/secdrv.py`.** This was the
  documented crux and it is solved. `SECDRV.SYS` (14 KB, imports only `Io*`/`Rtl*`
  from `ntoskrnl`, no disk I/O) runs headless under its own Unicorn instance with
  a fake `DRIVER_OBJECT` and stubbed ntoskrnl imports. `DriverEntry` (`0x12466`)
  is emulated once to capture `MajorFunction[IRP_MJ_DEVICE_CONTROL]` (`0x10676`);
  each call builds an IRP + `IO_STACK_LOCATION` and runs the dispatch, stopping at
  `IofCompleteRequest` (fastcall) to read `IoStatus` + the response. Two things
  mattered: `0xEF002407 & 3 == 3` is **METHOD_NEITHER** (input is
  `Type3InputBuffer`, output is `Irp->UserBuffer` — *not* `SystemBuffer`); and
  `KeTickCount` is a 3-dword `KSYSTEM_TIME` the driver reads with a stable-read
  spin (`High1Time==High2Time`), so its variable needs its own zeroed region
  clear of `NtBuildNumber`. The crypto worker (`0x10cbc` → `0x10da6`) reads `DR1`
  as an anti-debug check; `0` is the correct clean-machine value. The loader now
  **accepts the response and proceeds** (verification: before, it trapped at the
  gate after ~10M insns; after, it runs ~132M insns deep into the shell). secdrv
  is byte-identical across SafeDisc 1 titles, so this is reusable as-is.
- **Software interrupts (`safedisc1.py` `_intr`/`_seh`).** The shell sprinkles
  `int 1`/`int 3`/`icebp`; on a clean machine the fault reaches SafeDisc's own
  SEH handler, which resumes after the trap (a debugger would consume it — that
  is the check). We dispatch as the no-debugger case: resume past the trap.
- **A real file model (`safedisc1.py`).** `GetModuleFileNameA(NULL)` returns the
  loader; `CreateFileA`/`SetFilePointer`/`ReadFile`/`GetFileSize` are backed by
  the real loader and ICD bytes, so the shell's self-reopen (it `SetFilePointer`s
  to `EXE+0x44200`, the appended `"custom data"` block, and reads it) and the ICD
  reads deliver true bytes instead of zeros.

### The frontier: `.txt` reconstruction

With all of the above, the loader reaches the shell's **code-reconstruction
engine** and stops cleanly at `0x0040AAE2` (a `.txt` byte that reconstructed to
junk). The engine is now fully mapped:

- A command interpreter walks records keyed off the `"custom data"` payload and
  calls a dispatcher (`0x415d10`): command `0x64` = nop, `0x65` → `0x415960`,
  `0x66`/`0x67` → the patch engine `0x415a80`.
- `0x415a80` wraps a `rep movsd` copy in `VirtualProtect` (`[0x435958]`, for
  `0x67` = patch self) or routes through `WriteProcessMemory` (`[0x43595c]`, for
  `0x66` = write the hollowed child). On this title it issues 13 `0x67` calls
  rebuilding `.txt` page-by-page (`0x401000`…`0x40d800`).
- Each page's plaintext is produced by a **per-page decrypt routine** (in the
  interpreter above `0x415d10`) into a stack buffer, which `0x67` then copies in.
  That decryptor is the one remaining gap: it currently yields junk, so the
  rebuilt `.txt` is wrong and a later `call` into it faults. Finding its key
  derivation from the `"custom data"` block is the next concrete step.

### A reference oracle, from the VM (2026-10-19)

The headless `.txt` decryptor was "unverifiable without a reference dump." We now
have one, and it needed no disc check: the SafeDisc shell (`FS2000.EXE`)
self-decrypts its own `.txt` **before** any ICD hollow or CD check, so running the
game on the Win2000 box (see the `win2kdev` memory) and grabbing `FS2000.EXE`'s
memory yields the correct plaintext. `tools/drm/safedisc1_dump.c grab FS2000.EXE
shell.bin` does exactly that; the capture is in `work/safedisc1/`.

Measured against that oracle (`work/safedisc1/cmp_pages.py`):

- Every `.txt` page is encrypted in the file (entropy ~7.95) and real code in the
  shell dump (~6.3–7.0). The emulator's final `.txt` is still ~7.97 — it
  reconstructs only the first page (0x401000, already-cleartext bootstrap) and then
  the per-page decryptor emits **garbage** for the rest.
- The cipher is **not** a simple keystream: `file_txt XOR shell_txt` is ~7.95
  (high) per page, so it is a real stream/block cipher, not a repeating XOR.

#### The per-page decrypt primitive, pinned down (2026-11-22)

The inner decrypt loop was traced byte-by-byte (`FS2000.EXE` `0x426728..0x4267eb`,
reached from the patch engine `0x415a80`). It is, per byte `i`:

    out[i] = cipher[i] ^ foldbyte(K) ^ mask[i]
    K      = (K + out[i]) & 0xFFFFFFFF

with `foldbyte(K) = (K ^ (K>>8) ^ (K>>16) ^ (K>>24)) & 0xFF`, `K` a 32-bit
running accumulator held at `[0x435A70]`, `cipher` the page transformed in place
(ptr `[ebp+0x14]`) and `mask` a second byte stream (ptr `[ebp+0x1c]`); both
pointers advance one byte per step. A **second pass** (`0x426d85`) shares the same
`K`, so `K` is stateful across passes *and* pages — not reseeded per page.
`tools/drm/safedisc1_cipher.py` is this primitive plus a self-test: it reproduces
the first bytes of `shell.bin` page 0 exactly from the captured `cipher`/`mask`/`K=0`
inputs, so the **arithmetic is confirmed correct**. (The `rep movsd` at `0x415AC8`
is only the copy-in of the finished page.)

Also required a fix: `wsprintfA` was stubbed as a no-op, so the shell built an
**empty** `\\.\Secdrv` device name (it formats `"\\.\%s"`). `safedisc1.py` now
implements a minimal `wsprintfA`, and the device name resolves.

#### Where it actually diverges

With the primitive confirmed, the divergence was localised:

- Page 0 (`0x401000`) is the already-cleartext **bootstrap** and reconstructs
  byte-for-byte; it is a passthrough, so it never exercised the real cipher. Pages
  `0x402000`+ are genuinely encrypted and the emulator produces garbage for them.
  Only **5 pages** are copied before the shell faults on executing a junk page.
- **The decrypt inputs are entirely internal and deterministic.** Perturbing the
  secdrv IOCTL response (`0xEF002407`) and perturbing the `"custom data"` block
  (`0x44200`) each leave the page-1 decrypted output **bit-identical** (measured by
  comparing the `esi` source at the copy, not the pre-copy destination — the earlier
  "key comes from custom data" note was based on a read *before* the copy and is
  withdrawn). So the key/mask are **not** fed by secdrv or custom data; they are
  built from the mapped image and the shell's own `.data` by earlier reconstruction
  steps that run inside the emulator.
- Therefore the remaining bug is **not a missing external input**; everything is
  internal and deterministic.

#### Narrowed to stage 1 (2026-11-22, backward-bisect)

The reconstruction is **two stages** per `.txt` page, confirmed by capturing full
buffers and whole-page outputs:

- **Stage 2** is the byte loop above (`out = in ^ foldbyte(K) ^ mask[i]`). Its three
  inputs are now each pinned:
  - `mask` is the mapped **`.txt2`** section, one page per `.txt` page (page 0's
    mask = `.txt2` VA `0x423000`, page 1 = `0x424000`, …). `.txt2` is cleartext in
    the file and loads straight into the image, so the mask is **correct by
    construction**.
  - `K` carries between pages. **Page 0 reconstructs all 4096 bytes correctly**
    (verified against `shell.bin`, not just the first 16), so every `K` update
    through page 0 is correct and the value entering page 1 (`0xEF189825`) is
    correct.
  - `cipher` is the `P` intermediate (stack buffer `0x5F1FDDFC`), *not* the raw
    `.txt`. It is produced by stage 1.
- So for page 1, stage 2's only wrong input is **`P` (the stage-1 output)**. Direct
  check at byte 0: oracle wants `0x30`; with the correct `K` (`foldbyte=0x4A`) and
  correct mask (`0xA2`), `P[0]` would have to be `0x30^0x4A^0xA2 = 0xD8`, but the
  emulator's `P[0]` is `0x27`. Page 1's output is wrong **from byte 0**, which (since
  `K` is still correct at byte 0) can only be a wrong `cipher`/`P` byte.
- **Stage 1** fills `P` from the raw mapped `.txt` ciphertext (`0x402000…`, correct
  in the image) and transforms it in **8-byte blocks** — a helper whose tail at
  `0x426490..0x4264A7` stores two dwords (`[ebp-8]`,`[ebp-0xC]`) per call and is
  called **512 times per page** (512×8 = 4096). Its arguments are
  `(P_dest, 0x435A60, 0x400000, 0x70000024)`. `0x435A60` is a 256-byte stage-1
  **context/state table** (sparse — ~26 distinct bytes, a `00 01 02 … 0F` prefix;
  *not* a full RC4 permutation), sitting `0x10` below the stage-2 accumulator `K` at
  `0x435A70`. So stage 1 is a keyed block transform whose state is this table plus the
  surrounding `.data`; the exact round function is still to be reversed.

Why this is a **hard wall** for black-box work, with the evidence:

- Stage 1 runs for **every** page including page 0 (in the loop-window *before*
  page 0's stage-2 pass), and page 0's `P` is both produced by stage 1 and consumed
  by stage 2 to give the byte-perfect page 0. **So stage 1 demonstrably works on
  page 0.**
- Its S-box state therefore evolves correctly through page 0 and should enter page 1
  correct; its raw `.txt` input for page 1 is correct in the image; secdrv and custom
  data are ruled out. Every input stage 1 has on page 1 is one we can show is correct,
  yet its output `P` is wrong from byte 0.
- When a fully deterministic computation with all-correct inputs produces a correct
  result on page 0 and a wrong one on page 1, the remaining cause is that the
  **emulator executes some instruction on page 1's data path differently from a real
  CPU** — a Unicorn semantics edge (an obfuscated `aad`/`aam`/BCD, a flag or
  segment or `rep` corner), or S-box state silently clobbered between pages. The only
  oracle available headless is the final `shell.bin`, which cannot by itself localise
  a single wrong instruction deep inside 512 blocks of obfuscated stage-1 code.

Two ways past the wall, for whoever picks it up:

1. **Reverse stage 1 fully** (the per-block round function at/above
   `0x426490`) into a standalone reference, run it over page 1's known-correct inputs,
   and compare to the emulator's per-instruction state to find the first divergence.
2. **A known-good x86 reference** to diff instruction semantics against the emulator
   on the stage-1 path. We cannot run the original natively (project rule), but the
   decrypt routines can be executed in isolation under a second, independent x86
   engine (or a Unicorn vs. a software x86 model) on the captured input buffers —
   neither runs the game — and the first instruction whose two engines disagree is
   the bug.

Fixing stage 1 makes `P` correct, stage 2 is already proven, and the shell runs to
completion and decrypts the ICD (secdrv is already answered headless).

### Then

1. **Finish the page decryptor** so `.txt` reconstructs to real code; the shell
   then runs its own reconstruction to completion.
2. **Model the child.** `CreateProcess(ICD)` initialises a second memory image
   from the ICD's file layout; `WriteProcessMemory`/`ReadProcessMemory`/
   `VirtualProtect` act on it (the `0x66` path already targets it);
   `GetThreadContext`/`SetThreadContext` carry the OEP. After `ResumeThread` the
   child image holds the decrypted program.
3. **Rebuild the PE.** Reuse `emu_unpack.py`'s `find_iat`/`layout`/`write`: the
   stripped imports come back as the runs of thunk addresses the decrypted code
   calls through, and a fresh import directory is appended. Output is an ordinary
   PE that `pe_analyze` and the lifters read like any other.

## Which SafeDisc 1 titles this covers

The loader, `secdrv.sys` (byte-identical across the family), the anti-debug
gauntlet and this per-page cipher primitive are shared across SafeDisc 1.x
(`BoG_ *90.0`-era, secdrv dated 1998–1999). Once the headless unwrapper finishes
one title it should cover the others unchanged apart from per-title offsets. The
usual-suspects list this unblocks — all `GAME.EXE` + `GAME.ICD` pairs with a
`secdrv.sys`:

- **Microsoft Flight Simulator 2000** (this reference; also `FSEDIT.EXE`/`FSEDIT.ICD`
  in the same install).
- **Crimson Skies** (Microsoft/Zipper, 2000).
- **X-Wing Alliance** retail SafeDisc pressing (the Steam build is SteamStub, handled
  elsewhere) and other LucasArts SafeDisc 1 discs.
- Other Microsoft-published SafeDisc 1 titles of the era (e.g. Motocross Madness 2,
  Midtown Madness) and the broad SafeDisc 1 catalogue — any title whose ICD carries
  the same `BoG_` marker and ships the 1999 `secdrv.sys`.

Confirm a candidate by checking the ICD's `.text` entropy (~7.99, stripped
kernel32/user32 imports) and that `secdrv.sys` matches the known hash before
pointing the unwrapper at it.

## Verifying

A decrypted ICD is correct when `pe/pe_analyze.py` reads a clean import table,
`disasm/disasm32.py` recovers a sane function count (not a sea of invented
functions from decoding data as code), and the lifted program runs. Until then,
`drm/safedisc_dump.py` (run the game on a Windows VM with the disc, dump `.text`
from memory) is the fallback that unblocks lifting — slower and not headless,
but it produces the same decrypted bytes to check the emulator against.
