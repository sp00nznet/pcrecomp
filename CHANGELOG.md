# Changelog

All notable changes to pcrecomp. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [SemVer](https://semver.org/).

## [Unreleased]

### Added
- dos32: `dos32_heap_alloc` / `dos32_heap_free`, the DPMI heap for the host,
  so a host can hold memory back from a program that grabs everything it can.
  Theme Park's memory manager takes every block down to 16 bytes and leaves its
  C library nothing for `fopen`. (#PR)
- `runtime/dos32/` and `Lifter(dos=True)`: lifted DOS-extender programs run.
  The lifter turns `int`, port I/O, cli/sti/hlt, `iretd` and segment loads into
  host calls, gives `es:` a real base, and dispatches a `ret` to an address the
  caller never pushed (`push x; ret`); `call_pop=` makes a call into a function
  that pops its own return address a jump. dos32 provides what DOS/4GW, DOS and
  the BIOS did: a 4 GB guest address space (64-bit hosts work), DPMI, DOS files,
  VGA and VESA video, int 16h and IRQ 1 keyboard, int 33h mouse with event
  handlers, the PIT and IRQ 0, a virtual clock for reproducible headless runs,
  crash reports and a hardware write watchpoint (`DOS32_BREAK`). Theme Park
  boots, plays its menus and runs a park. See docs/DOS32.md. (#69)
- `tools/le/le_parse.py`: the LE front end, for 32-bit DOS-extender programs
  (DOS/4GW, PMODE/W, DOS/32A: most Watcom-built DOS games of 1993-97). It lays
  the objects out at a chosen base with every fixup applied, as the extender
  would have, and re-wraps the result as a PE32 (`--pe`, one section per
  object, the fixups as `.reloc`) so disasm32 and lift32 run on it unchanged.
  `--seeds` lists the code addresses the fixup tables name, minus data kept in
  code. Theme Park's MAIN.EXE: 3 objects, 19,728 fixups. (#68)
- native32 eh32: guest C++ exceptions for lifted x86-32 code. `_CxxThrowException` is a
  built-in that dispatches over the guest's own `fs:[0]` chain and FuncInfo tables, runs the
  unwind and catch funclets as guest code, and longjmps into a landing pad the lifter gives
  every function with catch blocks (`tools/lift/eh32.py`, `generate.lift_function_linear`
  `eh_resume=`). Found on Unreal Tournament, whose `StaticLoadObject` catches its own throws.
- `tools/lift/name_lift.py`: readable names for a finished lift, and a header on
  every function saying what it is, from what the binary itself says. Virtual
  methods are named by their class and slot from RTTI (COM's own slots by name:
  `UnitClass__QueryInterface`, `OverlayClass__Load`); MSVC's scalar deleting
  destructors and `operator delete` by their shape; constructors and destructors
  by the vtables they store; functions that print `Class::Method` in a debug
  message by it. The header lists the strings a function uses, the Windows calls
  it makes, its source file where a message names one, its `this` class and how
  many places call it; a constant that is a string's or a vtable's address gets
  a comment. Nothing comes from outside the binary. 7,167 of Red Alert 2: Yuri's
  Revenge's 24,954 functions are named and 5,602 of Tiberian Sun's 18,559; both
  build and play as before. `--demo` checks it on a synthetic lift.
- `runtime/win32hle/`: enough of Win32 for a DirectDraw game to run on Linux,
  driven by Tiberian Sun (tiberiansun-recomp `src/linux`), which now boots,
  plays its movies and music, runs its menus and dialogs, and plays a
  skirmish with no Windows and no Wine:
  - `ddraw.c`: DirectDraw in software (`IDirectDraw`/`2`, surfaces 1–3,
    palettes, clippers; blits with colour fill, colour key and stretch, flips),
    with a 64 KB tail behind every surface for blitters that run past the end;
    `screen.c` shows the primary in an SDL2 window and turns SDL input into
    window messages.
  - `dsound.c`: DirectSound on SDL2 audio, a software mixer with real-time
    play cursors.
  - `user32.c`: a window manager — windows, classes, the queue with `WM_PAINT`
    and `WM_TIMER` generated, focus/capture/activation, dialogs from their
    templates, and the standard controls with owner-draw (combo boxes sized
    from `WM_MEASUREITEM` as Windows does, which the game's layout depends on).
  - `gdidc.c`: device contexts on surfaces, fonts on SDL2_ttf, `TextOutA`.
  - `module.c`, `hle_path.c`: `LoadLibraryA` and resources (`LoadStringA`,
    dialog templates in a resource DLL), Windows paths on a case-sensitive
    disk.
  - `kernel32*.c`: files on descriptors and the directory search, sized heap
    blocks, virtual memory, critical sections, events, mutexes, waits, TLS,
    codepage 1252 and an English locale for the CRT.
  - `ole32.c` (COM class factories, the host's and the guest's own),
    `advapi32.c` (an in-memory registry, COMCTL32, VERSION, SHELL32),
    `wsock32.c` (Winsock 1.1 on BSD sockets, and IPX as IPXEmu puts it on
    UDP, so a native player and a Windows one share a LAN), `winmm.c` timers
    on threads.
  - `storage.c`: structured storage (`StgCreateDocfile`, `IStorage`,
    `IStream`, `OleSaveToStream`/`OleLoadFromStream`) on compound files in
    Windows' own format (MS-CFB v3), so saves move between the two; a
    selftest round-trips one.
  - `screen.c` scales as a Windows presenter does: sharp-bilinear, smooth,
    CRT, nearest, integer (F12), blurred bars, fullscreen (F11); an optional
    2x picture from the host (an HD layer).
  - The machine lock is handed over with the registers saved, at every import
    and loop back-edge when another thread waits; ordinal imports bind as
    `dll#N`; `build_selftests.sh` runs the selftests.
  - `bink.c`: `binkw32.dll` on ffmpeg, built with `HLE_WITH_FFMPEG`: a movie
    opened by name or from the game's own file handle at its offset
    (`BINKFILEHANDLE`), frames converted to 565, 555 or 32-bit into the
    game's buffer, the audio played through a host stream that `dsound.c`
    mixes. Red Alert 2 and Yuri's Revenge (redalert2-recomp `src/linux`) run
    on the layer with it, with the calls they added (`MulDiv`,
    `FormatMessageA`, `OpenEventA`, `GetLogicalDriveStringsA`,
    `GetTempFileNameA`, `ChildWindowFromPointEx`, `GetSysColor`, IMM32's
    no-ops, `EnumProtocolsA`); invalidating a window without
    `WS_CLIPCHILDREN` repaints its children as Windows does.
- `tools/drm/steamstub.py`: removes SteamStub 2.x (x86) without running anything and
  without Steam. The stub's header and payload are running-XOR decoded. The embedded
  `steamdrm.dll` is XTEA-CBC decrypted, and the payload offsets it uses (AES key, first
  block, OEP, code range) are read from its own code. The code section is then
  AES-256-CBC decrypted, with the IV taken from an ECB-decrypted first block. The
  dead `.bind` section is dropped. Needs `cryptography`. Found on KotOR (Steam, app 32370).
- `tools/drm/steamstub.py`: the older SteamStub 2.0 layout too. It has no `steamdrm.dll`:
  the stub copies a header whose first dword seeds the running XOR over the rest, and the
  code section is the same running XOR keyed by a header field. Found on Unreal
  Tournament (Steam, app 13240).
- `runtime/win32hle/` WinMain bring-up, driven by running a lifted Fury³ under
  the permissive host and implementing each import it reached:
  - `user32.c`: the window-setup and RECT surface a GUI WinMain needs —
    `FindWindowA` (single-instance), `LoadIcon/Cursor/Image/Bitmap/Accelerators/
    Menu` (non-NULL handles; a NULL accelerator table is fatal to some games),
    `TranslateAcceleratorA`, `GetSystemMetrics` (a 1600×960 desktop),
    `GetClientRect`/`GetWindowRect`/`Adjust*`, `BeginPaint`/`EndPaint`,
    `MessageBoxA` (to stderr), the focus/z-order setters, and the `*Rect`
    helpers (`CopyRect`/`OffsetRect`/`SetRect*`/`InflateRect`).
  - `winmm.c` (new): WINMM — multimedia timers, no-joystick, and a silent
    waveOut device that retires every buffer immediately (so a mixer thread
    keeps cycling without a sound card), MCI stubbed.
  - `kernel32_crt.c`: `CreateThread` runs the lifted start routine on a pthread
    via `hle_call_guest` (each guest thread already gets its own stack+TIB);
    guest threads interleave cooperatively, yielding the machine lock in the
    blocking shims (`Sleep` now yields, `WaitForSingleObject`).
  - `kernel32_ext.c` `CreateFileA` translates Windows `\\` to `/`, and
    `GetModuleFileNameA`/`GetCurrentDirectoryA` return the real image location
    (`hle_set_module_path`) so a title finds its data relative to the exe.
  With these a lifted Fury³ runs its whole CRT **and WinMain** on Linux —
  through window creation, its worker thread, and timing — into its own asset
  loader (it then wants its `.POD` data manifest, which is game packaging, not a
  runtime gap). `HLE_FILETRACE=1` logs the data files a title opens. (#45)

### Fixed
- disasm32: data kept in a code section no longer becomes a function start.
  The body probe (`probes_as_function_body`) now fails a candidate whose decode
  meets an instruction no 32-bit compiler emits (`arpl`, `bound`, BCD, `sldt`,
  `lsl`, ...): a string or a byte table decodes that way, and used to pass as
  long as a `ret` turned up first. The code-immediate harvest runs that probe,
  and ignores an immediate that points into a hole inside the very function
  loading it (a table it jumps over). Watcom keeps both in its code object:
  Theme Park's startup `mov edx, offset "con"` straddled the real entry, and a
  `mov edi, offset keys; repne scasw` switch split its function in two. SimCity
  2000 against IDA: precision 87.40% -> 87.43%, recall unchanged. (#67)
- generate: `loop`, `loope` and `loopne` are block leaders. They were missing from
  `COND_JUMPS`, so a loop's target got no label, its `goto` fell to the
  missing-label fallback, and that tail-jumped to an address nothing lifted: the
  loop body ran once and the function carried on. Hand-written asm uses `loop`
  in every inner loop; Theme Park's sprite blitter drew its runs off the end of
  the screen. MSVC rarely emits it, which is why no Win32 title showed it. (#66)
- lift32: MMX's byte and unsigned-saturating ops (`paddusb`, `psubusb`, `paddusw`, `psubusw`,
  `paddb`, `psubb`, `paddsb`, `psubsb`, `pcmpeqb`, `pcmpgtb`, `pcmpeqd`, `pcmpgtd`,
  `packsswb`) are lifted. They were emitted as an `UNIMPLEMENTED` comment and the lift
  still counted 0 errors. Unreal Tournament's software renderer blends every translucent
  pixel with one `paddusb`, so its HUD panels were drawn opaque, solid black when faded
  out. `mmx_selftest.c` covers each one.
- native32 under Wine (macOS with CrossOver, Linux): `native32_init` turns DEP on,
  since Wine otherwise answers the first fetch from the guest's code by making it
  executable and running the original machine code; and the fault handler takes a
  read of the faulting instruction's own address as a fetch, as Wine under Rosetta
  reports one. Callbacks into lifted code now arrive under Wine. (#55, by
  [@cpressland](https://github.com/cpressland))
- lift32: a signed or unsigned ordering jcc/setcc after `or` or `xor` (`jge`, `jl`, `jg`,
  `jle`, `ja`, `jbe`, `jb`, `jae`) tests the result's sign and zero, as after `test`. It
  compared the result with itself (`xor eax, [b]; jge` was always taken). Unreal
  Tournament's clipper asks whether an edge crosses a plane that way; its renderer drew
  stretched, overlapping shards. Four difftest cases.
- disasm32: a data pointer to an instruction start inside another body is a function entry
  when it is 16-aligned right after `nop`/`int3` padding: that body ran past a call that
  never returns, through the padding, into the next function, and the data scan had skipped
  the pointer as already covered. Unreal Tournament's UWeb.dll lost a static constructor
  named only by its `_initterm` table that way, and loading the DLL faulted on it.
- `recomp_types.h`: gcc and clang get `__rdtsc` from `<x86intrin.h>`, as MSVC
  gets it from `<intrin.h>`, so generated code that reads the timestamp
  counter compiles off Windows.
- disasm32: straight-line code longer than one scan window (8 KB, 4 KB per block) is decoded
  to its end. The rest of the function used to be dropped. KotOR registers its script commands in
  ~7 KB of `mov [reg+disp], offset`, so 142 functions named only there were never catalogued;
  a script command's unresolved dispatch skipped its `ret 8` and corrupted the VM's esi. (#50)
- native32: the guest's last error survives the bridge in both directions. mach_enter and
  mach_leave's TlsGetValue reset it to 0, so `GetLastError()` after a native call saw 0.
  KotOR's resource scan looped forever waiting for ERROR_NO_MORE_FILES. (#49)
- native32: the bridge's inline asm no longer touches esi or ebp. clang-cl addresses this
  frame's locals off esi (its base pointer), and the bridge's `mov esi, src` sent the first
  native call to 0. Inputs go to registers before esp moves, and arguments are copied by a
  push loop. Found on KotOR built with clang-cl. (#48)
- `pe/analyze_sections.py` called a `.bind` section a SafeDisc wrapper. `.bind` is
  Steam's SteamStub.

- generate: a gap in the middle of a lifted body falls through to the right
  address. An instruction that can fall through, followed in the emitted list
  by one that is not at its end (the extent walk stops after a `call` that is
  followed by a catalog entry), ran on into the next emitted block. Now it gets
  a goto, or a tail transfer when the address is outside the body, the same as
  the end of a body. Yuri's Revenge lost an inline strcat after `call sprintf`
  and showed its insert-disc box; 73 such gaps in its lift, 1 in The Movies'
  3,000-function closure. (#41)

- `tools/lift/translator.py` (`python -m tools … --all`) now seeds the PE entry
  point and every export into function discovery. disasm32's `find_functions`
  already took a `seeds` list — "the PE entry point above all" — but the default
  pipeline never passed it, so when a CRT entry opened with `mov eax, fs:[0]`
  (the SEH prologue) the prologue scan seeded the inner `push ebp` six bytes in
  and the real entry VA was never lifted: a host calling the entry found no
  function there. Fury³'s entry `0x00452BE1` was recovered only as `0x00452BE7`
  until this; now the entry and exports are always in the catalog. (#34)

### Added
- `runtime/win32hle/`: a permissive bind for bringing up a new title. `host.c`
  gains `recomp_host_boot_permissive`, and `hle_resolve_or_stub` binds an
  unresolved import to a self-naming stub instead of failing the boot. A stdcall
  import can't be a silent no-op (it wouldn't pop its args and the stack would
  drift), so the stub names itself from the last-dispatched VA and stops when
  first *called* — giving the exact import the running program reached and its
  caller. The bring-up loop: run, see the import, implement it, rerun. (#34)
- `runtime/win32hle/kernel32_crt.c`: the KERNEL32 imports an MSVC C runtime
  calls between the PE entry and WinMain — `GetStdHandle`/`GetFileType`, the ANSI
  codepage/locale queries (`GetACP`/`GetCPInfo`/`GetStringType*`), the
  environment block, `GetModuleFileNameA`/`GetCurrentDirectoryA`,
  `MultiByteToWideChar`/`WideCharToMultiByte`, `GlobalMemoryStatus`, and the
  SEH/error hooks (`SetUnhandledExceptionFilter`, `RtlUnwind` as a no-op). With
  these plus `kernel32_ext`, a lifted Fury³ runs its whole CRT startup on Linux
  and reaches its own WinMain (first unmet call there: `FindWindowA`). (#34)

### Added
- lift16: self-modifying code. `Lifter.smc_imm` is the set of linear addresses
  the program writes into its own code; an immediate overlapping one is read
  from guest memory at run time instead of becoming a C constant, and a
  conditional jump whose opcode byte is in it takes its condition from the byte
  in memory (`cc_dyn` in `recomp16/cpu.h`). Blake Stone's wall scaler patches
  its step into `add edx, 12345678h`, and its raycaster flips `jge`/`jle` per
  view quadrant; lifted as constants the walls were noise and actors were
  corrupted by a raycaster running off its tables. Opt-in: nothing changes for
  a project that does not set `smc_imm`. (#39)

### Changed
- lift32_cpu: `fs:` operands emit `FS_RD*`/`FS_WR*` macros (cpu.h) instead of
  the MSVC `__readfsdword`/`__writefsdword` intrinsics directly. The macros
  resolve at compile time: MSVC still reads the real segment (unchanged), while
  gcc/clang (or any build with `RECOMP_FS_SIMULATED`) reads a host-provided
  simulated TIB at `c->fs_base`, a new `CPU` field. This lets SEH prologues lift
  once and build for either host, which the CPU-struct (reentrant) model needs
  for a non-Windows host; it mirrors the global-register model's existing
  `FS_BASE`/`g_fs_base` simulated-TIB design (`recomp_types.h`), extended to the
  per-thread CPU struct. `cpu_selftest.c` round-trips fs:[0]/[4]/[6]/[0x18] on
  the simulated path. (#27)

- `tools/drm/unlzexe.py`: LZEXE 0.90/0.91 unpacking for DOS MZ executables, by
  decoding the format rather than running the stub. `test_unlzexe.py` builds a
  packed file with a small encoder (literals, short and long matches, an
  extended length, a delta-coded relocation table) and checks the round trip.
  Blake Stone's two executables both ship packed. (#35)

- decode16/lift16: Borland's 8087-emulator `INT 3Eh` shortcuts. `CD 3E xx 90`
  is the emulator's own transcendental call -- a function byte and a pad -- not
  an interrupt followed by `repnz nop`; decoded as `emu3e` and lifted to
  `x87_emu3e(cpu, fn)`, the runtime owning the table (Blake Stone uses EC sin,
  F0 tan, F2 atan, each beside the 387 path it replaces). lift16 also lifts
  the 387 `fsin`, `fcos` and `fsincos` that Borland's math library takes when
  a 387 is present; they were `x87_unhandled`. (#36)

### Fixed
- lift32/recomp32: `jp`/`jnp` (and `setp`/`setnp`) evaluated at runtime read
  parity. A jcc at a join point (a branch target, or any instruction of a
  function with an unresolved indirect jump, which labels them all) reads the
  flag kind at runtime, and `recomp_cond` had no PF: the lifter emitted
  `/* no flag state for jp */ _cf`. MSVC's float compares are
  `fnstsw ax; test ah, N; jp`, so every one of them in such a function took
  one fixed branch. The Movies has 274; its cursor clamp read `x < 0.0` as
  true for every x, pinning the mouse to the top-left corner. A narrow flag
  setter now records its left-align shift in the kind
  (`FK_NARROW(kind, shift)`), which also gives `recomp_eflags` the right PF and
  AF for 8- and 16-bit results: difftest's `WIDTH` divergences (11 cases) and
  both x87 parity ones now match, 202/202 with two new join-point cases.


- disasm32: a catalog good enough to lift from without IDA. Scored against
  IDA on SimCity 2000 (Win95, MSVC 2.x + static MFC): precision 54.5% ->
  87.4% at the same recall (88.2%), exact ends 80% -> 84%. The game lifts
  from this catalog alone with no lift errors; see the PR for the city runs.
  - The interior walk of `drop_mid_instruction_entries` follows a switch's
    table: a scan hit on the last byte of an instruction in an arm survived,
    clamped CRT `__output` to 164 bytes and stalled the game before its first
    frame. `table_entries` is now shared with recursive descent.
  - `interior_starts`: a linear-scan candidate that another body falls into,
    branches to conditionally, or reaches through its own switch table is a
    label, and becomes an alias instead of cutting that body short. A target
    reached only by `jmp` (a tail call, a thunk) or after a `call` stays a start.
  - `eh_entries`: MSVC C++ handler stubs (`mov eax, FuncInfo; jmp`) and the
    unwind funclets and catch handlers their FuncInfo names are aliases of the
    function that installs them -- 1,933 of the 2,220 remaining splits.
  - Entries on int3 padding that only a pointer-shaped constant named are
    dropped (330).
  - The CLI now runs `close_dispatch_targets` after clamping, extended to
    switch arms and told which addresses are inside a known instruction, so
    every branch target in the catalog has a body.
  - `drop_mid_instruction_entries` counts only bodies that survive the round
    as evidence: a bogus entry inside one jump thunk decoded over the next,
    real thunk (named by `push offset` to the vector-constructor iterator),
    both went, and the game called a function nothing had lifted.
  - A branch out of the image no longer crashes the interior walk
    (`read_bytes` returns None there).

- lift/generate: a jump-table entry never points into its own table. The
  negative-index read below `jmp [reg*4 + table]` (#11, CRT memcpy) took the
  dword just under an inline table, which for MSVC 2's table-after-the-jmp
  layout is the jmp's own displacement: the table's address. The table was
  walked as code and the body lifted two interleaved decodes, so a `call`
  returned into the middle of its own bytes. Hover! faulted as level 1
  started; SimCity 2000's CRT memcpy lifted the same garbage. Bunghole in
  One, Civilization III and The Movies are unchanged, function for function.
  (#24)

- disasm32: a candidate in the `nop`/`int3` padding before a 16-byte boundary
  is moved to the function at the boundary. A raw-scan candidate (an `E8` byte
  inside another instruction, a pointer-shaped dword) landing in the padding
  decoded as a function that walked into the real one and owned its
  instructions, so the real start was `covered` and even a data table naming it
  exactly could not make it an entry. Yuri's Revenge: 516 entries started in
  padding and 66 real functions were missing, among them a static constructor
  `_initterm` calls and a method only a data table names; after, 2 and 0, and
  the catalog run is 15 min instead of 17. (#32)


- decode16: `mov sreg, r/m` and `mov r/m, sreg` with reg 4/5 are FS/GS. The
  field was masked with `& 3`, so `mov gs, ax` decoded as `mov cs, ax`; Blake
  Stone's wall scaler loads its texture segment into GS and every texel was
  read from the wrong segment. (#37)

- recomp16 `cpu.h`: SI, DI, BP and SP are unions with ESI, EDI, EBP and ESP. A
  386 running 16-bit code uses the 32-bit forms with an operand-size prefix
  (the Wolfenstein-family raycasters step EBP/EDX through their column loops);
  lift16 already emitted them and the struct had no such members. Writing the
  16-bit half leaves the top half alone, as on the hardware. (#38)


- `runtime/win32hle/kernel32_ext.c`: the KERNEL32 file-I/O (`CreateFileA`/
  `ReadFile`/`WriteFile`/`SetFilePointer`/`GetFileSize`/`SetEndOfFile`/
  `FlushFileBuffers`/`CloseHandle` over a HANDLE→`FILE*` table), `Global*`
  (fixed-memory: `HGLOBAL` is the pointer), and `.ini` profile
  (`GetPrivateProfileStringA`/`IntA`, `WritePrivateProfileStringA`) shims every
  Win32 title needs at startup and for load/save — on libc/POSIX. `gdi32.c`
  gains `GetDeviceCaps` (reports a plain 32bpp desktop the size of the
  framebuffer, so a software renderer takes the truecolour path) and
  `GetStockObject`. Chosen by the first real title's import census (Fury³: 157
  imports / 5 DLLs; this lifts win32hle's coverage of it from 31 to 46).
  `kernel32_ext_selftest.c` round-trips a file, a `Global` block and an `.ini`
  key from a synthetic lifted guest, headless under gcc `-m32`. (#32)

### Added
- `runtime/win32hle/` SDL2 present + input (`present.c`): shows the gdi32
  framebuffer in a window (via the window surface, so the same path works under
  the SDL "dummy" driver and over RDP) and turns SDL input into `WM_*` messages
  posted to the user32 queue. It wires itself as user32's pump hook
  (`hle_present_enable`), so a guest's own `GetMessage`/`PeekMessage` loop shows
  frames and receives input with no change to the guest; user32 stays SDL-free
  (the hook is a function pointer, NULL when headless). `pump_selftest.c` proves
  the hook drives a guest message loop (SDL-free); `present_selftest.c` drives
  the SDL layer headless under the dummy driver, checking a key, a mouse move
  and a quit translate to the right `WM_*`. With this the host maps, binds,
  runs, draws and takes input for a lifted 32-bit Windows GUI program on Linux.
  Needs 32-bit SDL2 (`libsdl2-dev:i386`); the rest of win32hle stays
  display-free. (#31)

- `runtime/win32hle/` full host + user32 message core: `host.c`
  (`recomp_host_init`/`_boot`/`_run`/`_main`) registers the shim modules, maps a
  PE and binds its IAT, then calls the lifted entry point, so a lifted 32-bit
  Windows GUI program boots and runs its own message loop off Windows. `user32.c`
  is that loop, SDL-free: class/window registries, a message queue, and
  `RegisterClass`/`CreateWindowEx`/`GetMessage`/`PeekMessage`/`TranslateMessage`/
  `DispatchMessage`/`PostMessage`/`PostQuitMessage` — `DispatchMessage` calls the
  window's `WndProc` back as lifted code through `hle_call_guest` (the explicit
  native→guest path, no exec-fault trampoline). `host_selftest.c` drives a
  synthetic lifted GUI app — entry → register class → create window → message
  loop → `WndProc` paints a DIB through gdi32 → quit — all headless under gcc
  `-m32 -no-pie`, no game binary and no display. Presenting the framebuffer in a
  real window (SDL2) is the one piece left for a real windowed title. (#30)

- `runtime/win32hle/` PE loader: `recomp_pe_map` maps a 32-bit PE at its
  ImageBase with `mmap` (sections to their VAs, `.bss` zero-filled),
  `recomp_pe_bind` walks the import directory and writes each IAT slot's shim VA
  (resolved by name through `hle_resolve`), and `recomp_pe_relocate` applies
  HIGHLOW base relocations. The portable counterpart of what native32 did
  through the Windows loader and windows.h — `pe_format.h` defines the PE
  structures so no windows.h is needed, which is what kept native32 on Windows.
  `pe_loader_selftest.c` builds a minimal PE (two KERNEL32 imports and a reloc)
  and maps/binds/relocates it, checked headless under gcc `-m32 -no-pie`. (#29)

- `runtime/win32hle/`: an *implemented* Win32-subset host for recomp32
  (global-register) lifted code, on libc/POSIX/SDL2, so a lifted 32-bit Windows
  program can run off Windows (Linux first). Where `native32` forwards a guest's
  imports to the real Win32 API — and so is Windows-only — win32hle answers them
  itself. It reuses native32's shim ABI (an import is a `recomp_func_t` that
  reads its stdcall args from `g_esp` and pops them), so there is no inline asm;
  native→guest calls go through an explicit `hle_call_guest`, so there is no
  exec-fault trampoline either. The spine (`host_lite.c`) owns the register
  file, a pthread machine lock, each thread's simulated TIB (`g_fs_base`), and
  the shim registry. `kernel32.c` covers process/module/heap/VirtualAlloc/time/
  error/`lstr*`; `gdi32.c` the software-renderer seam (`CreateDIBSection` +
  `StretchDIBits` into a host framebuffer, 32bpp). `win32hle_selftest.c` drives
  a synthetic lifted guest through all of it headless under gcc `-m32` (guest→
  shim, pointer args, the TIB, a native→guest callback, and a DIB blit).
  user32+SDL2 present and a PE loader are the next pieces (see README). The
  counterpart of `runtime/nextstep/`, which already hosts recomp32 off Windows. (#28)

### Fixed
- recomp32_cpu `cpu.h`: `wrf80` (store x87 register as 80-bit `tbyte`) dropped
  the sign bit of negative zero. The branch chain fell through to the implicit
  zero case for `-0.0` (since `-0.0 == 0.0` in C) and wrote a sign+exponent
  word of 0, where the hardware writes `0x8000`. Now the sign is taken with
  `signbit()`, which distinguishes `-0.0`, in both the normal and zero paths.
  A real correctness bug, not compiler-specific; it survived because the
  CPU-struct `wrf80` tested `v < 0` while the global-register model's `wrf80`
  (`recomp_types.h`) already set the sign first and was right.
  `runtime/recomp32_cpu/cpu_selftest.c` covers it (the `-0.0` row). (#26)

- recomp32 `recomp_types.h`: include `<stddef.h>` for `ptrdiff_t` (`g_mem_base`).
  MSVC pulls `ptrdiff_t` in transitively through other headers, so the omission
  never showed; gcc and clang do not, so the header failed to compile outside
  MSVC. Found building the runtime under gcc `-m32` toward an OS-agnostic
  (Linux) host. (#26)

- disasm32: a call target is kept only while a body that calls it is still an
  entry, re-derived each round of the drop. #14 took its `keep` set from every
  decoded body, garbage included, before any were dropped: in Bunghole in
  One's game DLL a mid-instruction body's `call` kept a garbage entry inside a
  real function's `call [..]` and clamped that function short (it is a
  handler the engine calls; its lift ended mid-instruction). The Movies' 0x00C10170
  (#14's case) is still kept; POD unchanged, Hellbender one fewer split.  (#21)

- recomp32: flags cross calls and tail jumps between lifted functions, as they
  do on the CPU. A call or tail transfer exports the caller's flags and every
  function entry imports them (`ret` already exported the callee's). A function
  reached by a tail jump started from `FK_NONE`, so one whose first conditional
  tests flags its predecessor set took an arbitrary branch: the MSVC CRT's
  `cos` falls from its load helper into `_CIcos`, whose first `je` reads the
  helper's ZF, and Bunghole in One's golf ball never moved.
  `runtime/recomp32/flags_selftest.c` checks both transfers, both ways. (#20)

### Fixed
- disasm32: a pointer-shaped guess (the data scan, the code-immediate harvest)
  whose decode straddles a directly called entry is dropped. #14 keeps the
  called entry; this removes the false body it leaves beside it. Bunghole in
  One: a DIDATAFORMAT in `.text`, taken for code from its `push offset`, over
  the `jmp [DirectInputCreateA]` thunk. Against IDA on top of #14: POD invented
  starts 108 -> 62 (F1 62.76% -> 63.09%), Hellbender 66.62% -> 66.64%. (#19)

### Fixed
- disasm32 seeds the exports, as the README always said it did, not only the
  entry point. Bunghole in One's game DLL is entered only through
  `GetProcAddress`, and both its exports were missing; the engine EXE was
  missing 57 of its 244. (#18)

- native32: guest modules that import from each other.
  `native32_module(name)` finds a mapped guest image by file name and
  `native32_export(base, name_or_ordinal)` reads its export table, and
  `native32_bind` uses them: an import from a module that is itself mapped
  as a guest binds to that module's export VA, which is in the dispatch
  table, instead of going to `LoadLibrary`. A game DLL that calls back into
  its engine EXE (Bunghole in One: 93 imports from `Golf.exe`) now binds with
  no host code; the host uses the same two calls to shim `LoadLibraryA` and
  `GetProcAddress` for its guest DLLs. The selftest maps a system DLL as a
  guest and checks both lookups. Every shim gets its VA on every bind (the
  bind rebuilds the table with #7's built-ins, so a VA set for one module
  was lost to the next); the selftest binds two modules with one array. (#17)

### Fixed
- native32: a guest thread's stack starts `BRIDGE_SLOTS * 4 + 64` bytes below
  its top, not 64. The bridge copies 24 argument slots up from `esp` whatever
  the callee takes, so a native call from a nearly empty guest stack read past
  the end of the allocation and faulted whenever the next page was unmapped:
  `native32_selftest` crashed on 9 of 20 runs, and passes 20 of 20 now. (#16)

### Added
- `runtime/native32/`: a 32-bit host for lifted recomp32 code, extracted from
  gunman. The native bridge copies the guest's argument slots to the real
  stack and measures the callee's purge from esp, so every import,
  GetProcAddress result and COM method is called with no argc table and no
  shim; x87 results cross in st(0) both ways. Windows -> guest callbacks enter
  through an exec-fault trampoline on the non-executable guest code, and one
  machine lock gives each guest thread its own stack and TIB.
  `native32_selftest.c` checks stdcall/cdecl/thiscall purges and a double
  return. Guest threads get at least 16 MB of stack (a lifted frame is several
  times the original's) and a 64 KB guarantee, so an overflow can still be
  reported. The Movies runs on it. (#7)

### Fixed
- `lift32`: `fucompp` was unimplemented, so the compare never ran and its two
  pops never happened, leaking two x87 slots per call. The Movies has 3,244;
  its audio code read every position/length ratio as 1.0 and asserted.
  difftest cases for equal, less and NaN (177/190 match, 0 failures). (#15)

### Added
- `recomp_types.h`: `g_cpuid_edx1` / `g_cpuid_ecx1` / `g_cpuid_edx_ext`, the
  CPUID feature bits the guest sees (all ones by default), so a host can hide
  SSE/3DNow! and CPU-dispatching libraries take their x87 paths. `CPUID` also
  honours the sub-leaf in ecx now (`__cpuidex`). (#15)

### Fixed
- `disasm32.py` never drops the target of a decoded `call` as a
  mid-instruction entry. The only evidence against such an entry is that
  another body's decode straddles it, and that body can be the false one: a
  data-scan hit inside a jump table decoded over a directly called function
  in The Movies (0x00C10170) and the real function went. Against IDA:
  POD F1 62.01% -> 62.76%, Hellbender 66.57% -> 66.62%. (#14)

### Fixed
- `disasm32.py`'s callback harvest (`push offset` / `mov r, offset` into code)
  no longer skips a target that an earlier body already covers: that body fell
  into it after a call it did not know was noreturn, and the target becomes an
  alias entry, as a jump into a body already does. The Movies: CRT
  `__endthreadex` ends in `ExitThread` and runs on into `__threadstartex`,
  whose only reference is the `push offset` ahead of `CreateThread`; the
  game's first worker thread faulted. POD and Hellbender catalogs unchanged.
  (#13)

### Fixed
- `disasm32.py`'s prologue scan starts a hot-patchable function at its
  `mov edi, edi` (8B FF), not two bytes in at `push ebp`. MSVC /hotpatch code
  (D3DX, the CRT, most Microsoft libraries) was split two bytes into every
  such function. The Movies: 2,048 of 3,083 framed functions; split entries
  6,582 -> 4,536, exact function ends 87.7% -> 91.2%. (#12)

### Added
- `generate.py`: `true_extent()` and `closure()`, the lift-driver helpers that
  forcecommander, prey and The Movies each carried a copy of. `true_extent`
  walks a body's branches for its real end, capped by reach instead of the
  catalog's clamp: MSVC calls a function's own __finally block mid-body, so
  the clamp cut CRT calloc off before its epilogue. On The Movies' startup
  closure, undefined-label ITAIL fallbacks 76 -> 44 and bodies with no
  terminator 7 -> 0. Selftest models the calloc shape.
- `true_extent` follows `jmp [reg*4 + table]` switches through their tables
  and can hand back the exact instruction set it reached;
  `linear_disassemble_function(reached=...)` then lifts only those, so the
  table bytes between a switch and its arms are never lifted as `pushal`
  (The Movies: CRT memcpy's tail copies were unresolved ITAILs). The sweep
  also decodes through `disasm32.decode`.
- `find_splits()`: entries that are really the middle of the entry before
  them (a walk from them branches backward into it). Dropping them from
  `true_extent`'s `entries` stops the parent being cut at a loop head. 366 on
  The Movies. (#11)

### Changed
- `disasm32.py` is 7-18x faster with byte-identical output. capstone's Python
  `disasm()` is a generator over one `cs_disasm(count=0)` call, so it decodes
  its whole buffer, with detail, before yielding the first instruction; every
  early-exit caller paid for a full window. `decode()` decodes in doubling
  batches instead. Fury3 3:35 -> 0:18, Hellbender 5:19 -> 0:42; The Movies'
  whole catalog went from 143 minutes to 8. (#10)

From #9. Found bringing Nocturne (Terminal Reality, Watcom C/C++32) in game.

### Fixed
- `lift32`: `push`/`pop` of a segment register moves esp by 4 in 32-bit code
  (2 only with a 66h prefix); `add` publishes CF, so `add`/`adc` chains carry
  right; `fild`/`fistp qword` are exact, the x87 stack shadowing an int64 per
  slot (`g_st_i64`).
- `generate`: static flag state no longer crosses a branch target.
- `recomp_types.h`: an unresolved `RECOMP_ICALL` no longer pops a return
  address it never pushed (Nocturne's CRT init lost its saved registers and
  skipped ~90 static constructors).
  difftest: 186/197 match, 11 known divergences, 0 failures.

### Added
- `drm/emu_unpack.py`: unpack a compressed PE32 by running its stub under
  Unicorn to the OEP, then rebuild the import directory around the IAT the code
  calls through. Handles PECompact 2.x and Valve's Steam2 wrapper on top of it
  (`SteamStartup`/`SteamIsAppSubscribed` answered). Headless, deterministic,
  `--selftest` for the IAT picker. Found on The Movies (2005), whose Steam
  build packs all three executables this way. (#5)

From #6. Found running SimCity 2000
(Windows 95, MSVC 2.x) recompiled: its simulation faulted after `div cl`.

### Fixed
- `lift32`: one-operand `mul`, `imul`, `div` and `idiv` at 8 and 16 bits use AX
  and DX:AX. Every width was lifted as the 32-bit EDX:EAX form, so `div cl`
  overwrote EDX. One-operand `mul`/`imul` now set CF and OF; signed
  `INT_MIN / -1` takes the divide-by-zero path instead of C undefined behaviour.
  (`lift32_cpu` already had this right.) Eight difftest cases: 183/195 match,
  12 known divergences, 0 failures.

From #8. Found running SimCity 2000
recompiled: its simulation hung in the CRT's `strstr`.

### Fixed
- `lift32`: a `rep`/`repe`/`repne` `cmps` or `scas` with ECX = 0 leaves the flags
  as they were. It set them to "equal", so `strstr` never saw the end of its
  haystack and looped forever. The jcc after a rep compare now reads the lazy
  flag state instead of assuming a compare wrote it. Two difftest cases:
  177/189 match, 12 known divergences, 0 failures.

From #4. Found running Gunman Chronicles (MSVC 6 CRT, Quake-lineage software renderer)
fully recompiled; each is generic x86 semantics or code generation. Each fix
has a difftest case against Unicorn: 175/187 match, 12 known divergences,
0 failures.

### Fixed
- `sahf` loads SF ZF AF PF CF from `ah` (it was a comment), and `fprem` reports
  C2 clear: the CRT `fmod` loop `fprem; fnstsw ax; sahf; jp` spun forever.
- `fxam` and `xlatb` lifted; the CRT math functions classify with them.
- `frndint` rounds by the control word (it truncated, so `floor`/`ceil` did).
- `fld`/`fstp` of 80-bit operands convert for real (they pushed 0.0 / dropped
  the value); `fsin`/`fcos`/`fsincos`/`fptan` clear C2.
- Flags survive `ret`: every `ret` publishes the lazy flag state and every call
  reloads it (`RECOMP_FLAGS_OUT/IN`), so a caller's `je` after a helper that
  returns ZF reads the helper's flags. Weak globals in `recomp_types.h`, so no
  project runtime needs a change.
- `inc`/`dec` keep CF; `bt; jae` no longer inverted; memory `bt*` address the
  bit string; `lock`-prefixed forms lift; `fist`/`fistp` round by the control
  word; patched immediates/displacements apply on every read.
- x87 compares report unordered (NaN) as C3=C2=C0; `repe cmps; sbb` reads the
  real CF; PF of narrow results is taken from the low byte.
- `generate.py`: a body can hold code below its entry (a `goto` to the entry
  comes first); `push label; jmp func` lifts as a call returning to `label`;
  a body that runs off its end falls through as a tail call.

### Added
- `Lifter(precise_carry=True)`: `adc`/`sbb` take CF from the `add`/`sub`/`cmp`
  before them instead of the `_cf` variable. Opt-in: Fury3 depends on the old
  behaviour.
- `Lifter(reloc=fn)`: rewrite every absolute displacement and immediate that
  points into a moved block of static data (growing fixed-size tables).
- `RECOMP_LOCAL_REGS` (opt-in): lifted bodies keep the eight registers in
  locals, written back around calls and returns, so the optimiser can hold
  them in host registers. `RECOMP_FLAT_MEMORY` (opt-in): no base added per
  guest access. Together about 2x on Gunman's renderer.
- `lift_function_linear(indirect_targets=...)`: when the caller knows every
  local target of a body's indirect jumps, only those get labels and switch
  cases, so a function with a `switch` optimises (default unchanged).
