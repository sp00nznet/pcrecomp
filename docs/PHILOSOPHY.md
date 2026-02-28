# The Philosophy of Static Recompilation

## The Core Thesis

**Any application that was ever compiled for a PC can be taken apart and rebuilt to run on modern hardware.**

Not "some applications." Not "simple ones." *Any.* DOS games from 1991. MFC desktop apps from 1996. Triple-A shooters from 2000. Multimedia encyclopedias with proprietary fractal codecs. It doesn't matter how old, how complex, or how proprietary -- if it ran on x86, we can make it run again.

This isn't a theoretical claim. We've done it. Across nine projects spanning 16-bit DOS, Win32, Quake II, GoldSrc, id Tech 3, and completely custom engines, the same fundamental approach works every time.

---

## Why Static Recompilation?

There are a lot of ways to run old software:

| Approach | Pros | Cons |
|----------|------|------|
| **Emulation** (DOSBox, QEMU) | Easy, broad compatibility | Performance overhead, can't extend or fix |
| **Compatibility layers** (Wine, compat shims) | Drop-in, no modification | Fragile, breaks on edge cases, DRM issues |
| **Source ports** (ioquake3, OpenMW) | Full control, modern features | Requires leaked/released source code |
| **Static recompilation** | Full control, works on *any* binary | Labor-intensive up front |

Static recompilation is the nuclear option. You don't need source code. You don't need the original developers. You don't need permission from a publisher that no longer exists. You just need the binary and the will to understand it.

The output is **native code** -- not emulated, not interpreted, not shimmed. It runs at full speed, can be debugged with modern tools, and can be extended with modern features (widescreen, modern input, networking, new renderers).

---

## The Universal Pipeline

Every project we've done follows the same pipeline. The specifics change, but the shape is always this:

```
 PHASE 0: RECONNAISSANCE
    What are we looking at? PE headers, sections, imports, exports.
    How was it compiled? What DLLs does it load? Is there DRM?

 PHASE 1: DISASSEMBLY
    Turn bytes into instructions. Find function boundaries.
    Build a call graph. Identify basic blocks.

 PHASE 2: CLASSIFICATION
    What's SDK code vs custom code? What's CRT vs game logic?
    What can we get from public sources (SDKs, leaked headers)?
    What do we actually need to reverse-engineer?

 PHASE 3: LIFTING
    Turn assembly into C. Not pretty C -- correct C.
    Global register model. Memory address translation.
    Pattern-matched condition codes. FPU stack simulation.

 PHASE 4: SHIMMING
    Bridge the gap between then and now.
    Win32 API -> SDL2. DirectDraw -> D3D11. Winsock -> modern sockets.
    DOS INTs -> C runtime. VGA Mode 13h -> SDL2 framebuffer.

 PHASE 5: BUILD & DEBUG
    Compile the lifted code. Fix the crashes.
    VEH crash handlers. ICALL trace buffers. Binary-search dispatch tables.
    This is where most of the time goes. And that's fine.

 PHASE 6: SHIP
    Native binary. Modern OS. No emulation required.
```

---

## Key Principles

### 1. Start With the Binary, Not the Problem

Don't guess what's inside. Don't assume. Run `pe_analyze.py` and read the output. The binary will tell you:

- **When it was compiled** (timestamp in PE header)
- **What compiler** (linker version, CRT imports, calling conventions)
- **What it depends on** (import table = your shim TODO list)
- **How it's structured** (sections, base address, relocations)
- **Whether it's protected** (SafeDisc, SecuROM, packed sections)

This takes 5 minutes and saves weeks of wrong assumptions.

### 2. Classification Before Lifting

The single biggest time-saver in any recompilation project is figuring out **what you don't need to reverse-engineer**.

Gunman Chronicles has 3,990 functions. Sounds terrifying. But 3,131 of those (78%) are straight from the Half-Life SDK -- publicly available C++ source code. The actual custom work is 499 functions (12.5%). That's the difference between "impossible" and "a few weeks."

This applies to every project:
- **Quake-family games**: Huge chunks are public engine code
- **MFC applications**: Most UI code follows known patterns
- **DOS games**: MSC runtime is well-documented
- **Any game with a modding SDK**: Compare against SDK headers

Our classifiers (`combined_classify.py`) use four passes: name matching, string references, call graph propagation, and address clustering. They're not perfect, but they get you to 80%+ accuracy automatically.

### 3. Correctness Over Readability

Lifted C code is ugly. That's fine. The goal of the lifter is **functional equivalence**, not pretty code. A function that looks like this:

```c
void sub_00401000(void) {
    g_eax = MEM32(g_esp + 4);
    if (CMP_EQ(g_eax, 0)) goto label_1;
    g_ecx = MEM32(g_eax + 0x1C);
    RECOMP_ICALL(g_ecx);
    goto label_2;
label_1:
    g_eax = 0xFFFFFFFF;
label_2:
    return;
}
```

...is correct, compilable, and debuggable. That's all that matters for Phase 3. You can clean it up later once you know what it does. Or don't -- some functions will run for decades in their ugly lifted form and nobody will care.

### 4. The Global Register Model Works

Every 32-bit project uses the same trick: x86 registers become C global variables.

```c
uint32_t g_eax, g_ecx, g_edx, g_ebx, g_esi, g_edi, g_esp;
```

This sounds cursed, and it kind of is, but it solves the hardest problem in static recompilation: **you don't need to recover calling conventions**. The original code passes parameters in registers and on the stack in whatever way the compiler felt like. By keeping registers global, every lifted function automatically preserves the original ABI.

For 16-bit code, we use a CPU state struct instead (segment registers, flags, etc.), but the idea is the same: don't fight the original code's assumptions.

### 5. Three-Tier Dispatch for Indirect Calls

The trickiest part of any recomp is indirect calls (`call [eax]`, vtable dispatches, function pointers). You can't statically resolve them. Our solution:

1. **Manual overrides** -- hand-written replacements for known hot paths
2. **Auto dispatch table** -- binary search over all lifted functions by address
3. **Import bridges** -- API wrappers for external DLL calls

The dispatch table is generated automatically. Manual overrides accumulate as you debug. Import bridges are your shim layer. Together, they handle every indirect call we've ever encountered.

### 6. The Shim Layer is the Product

For many projects, the most valuable output isn't the lifted code -- it's the **shim layer** that bridges old APIs to new ones.

`win32_compat.h` from the SoF project catalogs 275 Win32 API calls and maps each one to: KEEP (still works), SHIM (needs a wrapper), SDL2 (replaced), STUB (dead code), or CRT (modern compiler handles it). That header is reusable across any Win32-era game.

The same principle applies at every level:
- **DOS INT handlers** -> C runtime calls
- **VGA Mode 13h** -> SDL2 framebuffer
- **DirectDraw** -> D3D11 or Vulkan
- **Winsock ordinal imports** -> modern socket API
- **SafeDisc/SecuROM** -> just don't (dump the decrypted code and move on)

### 7. DRM is a Speed Bump, Not a Wall

SafeDisc, SecuROM, and similar schemes encrypt the `.text` section and decrypt it at runtime. This sounds scary, but the solution is simple: **let the DRM do its job, then dump the result**.

`safedisc_dump.py` launches the game via Steam, waits for SafeDisc v1 to finish decrypting, reads the process memory, and writes a clean PE. 320 lines of Python. The "unbreakable" DRM becomes a 30-second preprocessing step.

### 8. Format Reverse Engineering is Unavoidable (and Fun)

Every project hits proprietary file formats. Encarta 97 uses FIF (Fractal Image Format), M20 (Multimedia Viewer 2.0 containers), and SPAM (whatever that stands for). SoF uses GHOUL model bundles, MIP32 textures, and ROFF motion files. Civ 1 uses custom overlay loading via INT 3Fh.

You can't skip this work, but you can make it systematic:
1. Hex dump the file. Look for magic numbers and repeating structures.
2. Find the loader code in the binary (cross-reference file extension strings).
3. Write a standalone parser/dumper tool.
4. Validate by round-tripping: parse -> reconstruct -> compare.

Every format tool you write becomes reusable. The M20 parser works on any Microsoft Multimedia Viewer file, not just Encarta.

### 9. Automate the Boring Parts, Hand-Craft the Hard Parts

The pipeline has a clear automation boundary:

**Automate**: PE analysis, function discovery, basic block identification, instruction lifting, dispatch table generation, import stub templates, function classification.

**Hand-craft**: Complex control flow (computed gotos, longjmp), self-modifying code, inline assembly, hardware-specific behavior (timing, DMA), and the final 20% of functions where the lifter gets confused.

The automation handles 80% of the code. The remaining 20% is where the actual reverse engineering happens. But even there, the automated output gives you a starting point -- ugly C is easier to understand than raw assembly.

### 10. Every Project Makes the Next One Easier

This is the whole point of this repo. The tools compound:

- `pe_analyze.py` has been refined across 7 projects. It handles edge cases (UPX packing, ordinal imports, non-standard image bases) that we only discovered by hitting them.
- The 32-bit lifter started in XWA and now handles every x86 instruction we've encountered across all projects.
- The Win32 compat header from SoF applies to every Win32-era game.
- The DOS compat layer from Civ applies to every 16-bit DOS game.
- The SafeDisc dumper from XWA works on any SafeDisc v1 game.
- The Ghidra scripts from Gunman work on any binary.

**We're building a universal toolkit, one project at a time.**

---

## When to Use Which Approach

Not every binary needs the full pipeline. Here's a decision tree:

```
Is source code available (leaked, released, SDK)?
  YES -> Source port. Use classification tools to map SDK code.
  NO  -> Continue...

Is it a 16-bit DOS executable?
  YES -> decode16 -> analyze -> lift16 -> DOS compat runtime
  NO  -> Continue...

Is it a 32-bit PE (Win32)?
  YES -> Is it DRM protected?
         YES -> safedisc_dump.py first, then continue
         NO  -> pe_analyze -> disasm32 -> lift32 -> translator
  NO  -> Different toolchain needed (see sibling repos for N64/360/PS2)

Is it SDK/engine-based (Quake, GoldSrc, id Tech, Unreal)?
  YES -> Ghidra decompile -> classify against SDK -> reconstruct custom code only
  NO  -> Full lift pipeline

Is it C++ heavy (vtables, RTTI, templates)?
  YES -> GhidraStats + msvc_mangler + parse_vtables for structure recovery
  NO  -> Standard pipeline
```

---

## The Proof

Nine projects. Spanning 1991 to 2001. DOS to Win32. 16-bit to 32-bit. Assembly to C++ with virtual inheritance. Single executables to multi-DLL architectures. Custom engines to licensed middleware.

**Every single one follows the same pipeline.** The tools are different at the edges, but the core approach -- analyze, disassemble, classify, lift, shim, build, debug -- is universal.

That's not a coincidence. It's a consequence of how compilers work. Every compiler turns structured source code into sequential machine instructions. Static recompilation reverses that process. The specifics vary, but the principle is as old as computing itself.

If it compiled once, it can compile again.

---

*"We're not reverse engineers. We're software archaeologists. And the dig site is every hard drive from the 90s."*
