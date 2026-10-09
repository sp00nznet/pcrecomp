#!/usr/bin/env python3
"""Give a finished lift readable names, and say at each function what it is.

A lift names every function by its address (`sub_0058C1B0`) and leaves its
constants as numbers (`0x007E920Cu`). That is enough for a compiler and for an
agent with the binary open beside it, but a person reading one function cannot
tell what it does. This pass rewrites the generated C in place, after the lift,
with what the binary itself says about each function:

    named from          becomes                         evidence
    ------------------  ------------------------------  ---------------------------------
    a debug message     MapClass__Init_Clear            "MapClass::Init_Clear entry"
    a COM slot          UnitClass__QueryInterface       slot 0 of a class RTTI says is IUnknown
    a virtual slot      UnitClass__virtual_42           slot 42 of UnitClass's vtable (RTTI)
    a vtable store      UnitClass__constructor          stores UnitClass's vtable into `this` last
                        UnitClass__destructor           stores it first, then its bases'
    the host            Debug_Log                       a name the game repo passes (--known)

and puts a short header above every function:

    /* MapClass__Init_Clear (0x0058C1B0)
     *   named from its debug message "MapClass::Init_Clear entry"
     *   this (ecx) is a MapClass
     *   strings: "MapClass::Init_Clear entry\\n", "MapClass::Init_Clear done\\n"
     *   calls Windows: GetTickCount
     *   source file: Map.CPP (an assert message)
     *   called from 3 places
     */

and a comment after any constant that is the address of a string or a
vtable (`= 0x007E920Cu; /* "Can't open %s" */`).

Nothing is guessed from outside the binary: no names from other projects, no
heuristic "this looks like strcpy". A function with no evidence keeps its
address name and still gets the header (its strings and Windows calls are
often enough to tell what it does). Names stay unique: a second claim on a
name gets the address appended. The address is in the header and in the
function's RECOMP_ENTER, so crash reports and logs still lead here.

It only renames the lift's own identifiers (`sub_XXXXXXXX`) across the
generated directory, so the dispatch table and declarations follow. Run it on
a fresh lift; it refuses a directory it has already named.

    python tools/lift/name_lift.py game.exe --gen src/recomp/gen --rtti work/rtti.json \\
                                   [--known 0x004068E0=Debug_Log ...] [--report names.json]
"""
import argparse
import json
import os
import re
import struct
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'pe'))
from merge_names import sanitize  # noqa: E402

MARK = '/* Functions named by name_lift.py */'
FUNC_DEF = re.compile(r'^void (sub_[0-9A-F]{8})\(void\) \{', re.M)
CONST = re.compile(r'\b0x([0-9A-F]{8})u\b')
VTABLE_STORE = re.compile(r'MEM32\((?:e[abcd]x|e[sd]i|ebp)\) = 0x([0-9A-F]{8})u;')
CALL = re.compile(r'RECOMP_CALL\((sub_[0-9A-F]{8})\)')
WINDOWS_CALL = re.compile(r'/\* call \[[^\]]+\]([A-Za-z_][A-Za-z0-9_@]*) \*/')
# MSVC's scalar deleting destructor: tests bit 0 of its one argument (free the
# memory too?) and returns with `ret 4`.
DELETE_FLAG_TEST = re.compile(r': test (?:[abcd]l|byte ptr \[esp \+ (?:4|8|0xc)\]), 1 \*/')
RET_4 = re.compile(r': ret 4 \*/')
METHOD_STRING = re.compile(r'^([A-Z][A-Za-z0-9_]*)::(~?[A-Za-z_][A-Za-z0-9_]*)')
SOURCE_FILE = re.compile(r'([A-Za-z0-9_]+\.(?:cpp|CPP|c|C|h|H))\b')

# The standard COM slots at the head of a primary vtable, by the interface the
# class's first base chain reaches (Microsoft's own declarations).
IUNKNOWN = ['QueryInterface', 'AddRef', 'Release']
COM_SLOTS = {
    'IPersistStream': IUNKNOWN + ['GetClassID', 'IsDirty', 'Load', 'Save', 'GetSizeMax'],
    'IPersist': IUNKNOWN + ['GetClassID'],
    'IClassFactory': IUNKNOWN + ['CreateInstance', 'LockServer'],
    'IUnknown': IUNKNOWN,
}


class Image:
    """The PE's sections, enough to read a vtable or a string at a VA."""

    def __init__(self, path):
        self.data = open(path, 'rb').read()
        pe = struct.unpack_from('<I', self.data, 0x3C)[0]
        nsec, optsize = struct.unpack_from('<H', self.data, pe + 6)[0], struct.unpack_from('<H', self.data, pe + 20)[0]
        self.base = struct.unpack_from('<I', self.data, pe + 24 + 28)[0]
        self.sections = []                       # (va, size, file offset, raw size, executable)
        for i in range(nsec):
            s = pe + 24 + optsize + 40 * i
            vsize, rva, rsize, roff, chars = struct.unpack_from('<IIII12xI', self.data, s + 8)
            self.sections.append((self.base + rva, max(vsize, rsize), roff, rsize, bool(chars & 0x20000000)))

    def offset(self, va, data_only=False):
        for start, size, roff, rsize, executable in self.sections:
            if start <= va < start + min(size, rsize) and not (data_only and executable):
                return roff + va - start
        return None

    def dword(self, va):
        off = self.offset(va)
        return struct.unpack_from('<I', self.data, off)[0] if off is not None else None

    def string(self, va, minimum=4):
        """The C string starting at va in a data section, or None. It has to
        start there (the byte before is not text), be printable and end."""
        off = self.offset(va, data_only=True)
        if off is None or (off > 0 and 0x20 <= self.data[off - 1] < 0x7F):
            return None
        end = self.data.find(b'\0', off, off + 512)
        raw = self.data[off:end] if end >= 0 else b''
        if len(raw) < minimum or any(not (0x20 <= b < 0x7F or b in (9, 10, 13)) for b in raw):
            return None
        return raw.decode('ascii')


def c_string(s, limit=60):
    """A string as it would be written in C, shortened for a comment."""
    s = s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    s = s.replace('*/', '*\\/')
    return '"%s"' % (s if len(s) <= limit else s[:limit] + '...')


def ident(*parts):
    """Class__Method from its parts, each sanitised on its own."""
    return '__'.join(sanitize(p) or 'unnamed' for p in parts)


def vtable_slots(image, rtti):
    """{class: [slot VAs]} from RTTI's primary vtables."""
    out = {}
    for cls, info in rtti.get('classes', {}).items():
        va = int(info['vtable'], 16)
        out[cls] = [image.dword(va + 4 * i) for i in range(info.get('slots', 0))]
    return out


def com_interface(bases):
    """The COM interface at the head of a class's primary vtable: the first
    base chain (RTTI lists bases depth first) up to its first IUnknown."""
    chain = bases[:bases.index('IUnknown') + 1] if 'IUnknown' in bases else []
    for iface in ('IPersistStream', 'IPersist', 'IClassFactory', 'IUnknown'):
        if iface in chain:
            return iface
    return None


class Function:
    def __init__(self, va, body):
        self.va, self.body = va, body
        self.name = self.why = self.this_class = self.source_file = None
        self.strings = []
        self.windows_calls = sorted(set(WINDOWS_CALL.findall(body)))
        self.calls = set(CALL.findall(body))
        self.callers = 0


def infer(functions, image, rtti, known):
    """Name what the evidence names; record the rest for the headers."""
    vtables = vtable_slots(image, rtti)
    vtable_class = {int(info['vtable'], 16): cls for cls, info in rtti.get('classes', {}).items()}
    bases = {cls: info.get('bases', []) for cls, info in rtti.get('classes', {}).items()}

    # Strings and calls first: every header uses them.
    for f in functions.values():
        seen = set()
        for hexva in CONST.findall(f.body):
            s = image.string(int(hexva, 16))
            if s and s not in seen:
                seen.add(s)
                f.strings.append(s)
                m = SOURCE_FILE.search(s)
                if m and not f.source_file:
                    f.source_file = m.group(1)
        for callee in f.calls:
            target = functions.get(int(callee[4:], 16))
            if target:
                target.callers += 1

    claims = defaultdict(list)                   # name -> [(va, why)]

    # 1. The host's own names for addresses it knows.
    for va, name in known.items():
        if va in functions:
            claims[name].append((va, 'named by the host'))

    # 2. A debug message that names its function: "Class::Method ...", when
    #    exactly one function prints it.
    said = defaultdict(set)
    for f in functions.values():
        for s in f.strings:
            m = METHOD_STRING.match(s)
            if m:
                said[(m.group(1), m.group(2))].add(f.va)
    for (cls, method), vas in said.items():
        if len(vas) == 1:
            va = next(iter(vas))
            msg = next(s for s in functions[va].strings if s.startswith('%s::%s' % (cls, method)))
            claims[ident(cls, method.replace('~', 'destructor_'))].append((va, 'named from its debug message %s' % c_string(msg)))
            functions[va].this_class = functions[va].this_class or cls

    # 3. Virtual slots: each method belongs to the most basic class that has it
    #    in that slot (the fewest slots). COM's own slots by their interface.
    owner = {}
    for cls, slots in vtables.items():
        for i, va in enumerate(slots):
            if va in functions and (va not in owner or len(vtables[cls]) < len(vtables[owner[va][0]])):
                owner[va] = (cls, i)
    deleting = []
    for va, (cls, i) in owner.items():
        iface = com_interface(bases.get(cls, []))
        com = COM_SLOTS.get(iface, [])
        body = functions[va].body
        if i < len(com):
            method, why = com[i], 'slot %d of %s\'s vtable: %s::%s' % (i, cls, iface, com[i])
        elif DELETE_FLAG_TEST.search(body) and RET_4.search(body):
            method, why = 'deleting_destructor', 'slot %d of %s\'s vtable; tests bit 0 of its argument and returns 4 bytes, as MSVC\'s scalar deleting destructor does' % (i, cls)
            deleting.append(va)
        else:
            method, why = 'virtual_%d' % i, 'slot %d of %s\'s vtable (RTTI)' % (i, cls)
        claims[ident(cls, method)].append((va, why))
        functions[va].this_class = functions[va].this_class or cls

    # operator delete: what nearly every deleting destructor calls last.
    last_calls = Counter(CALL.findall(functions[va].body)[-1] for va in deleting if CALL.findall(functions[va].body))
    if last_calls:
        callee, n = last_calls.most_common(1)[0]
        if n >= 10 and n * 2 > len(deleting):
            claims['operator_delete'].append((int(callee[4:], 16), 'the last call of %d of the %d deleting destructors' % (n, len(deleting))))

    # 4. Constructors and destructors: a function that stores a class's vtable
    #    into `this`. A constructor stores its bases' first and its own last; a
    #    destructor its own first and its bases' after.
    for f in functions.values():
        stored = [vtable_class[int(h, 16)] for h in VTABLE_STORE.findall(f.body) if int(h, 16) in vtable_class]
        if not stored or f.va in owner:
            continue
        first, last = stored[0], stored[-1]
        if len(set(stored)) > 1 and last in bases and first in bases.get(last, []):
            claims[ident(last, 'constructor')].append((f.va, 'stores %s\'s vtable after its base %s\'s' % (last, first)))
            f.this_class = f.this_class or last
        elif len(set(stored)) > 1 and first in bases and last in bases.get(first, []):
            claims[ident(first, 'destructor')].append((f.va, 'stores %s\'s vtable, then its base %s\'s' % (first, last)))
            f.this_class = f.this_class or first
        elif len(set(stored)) == 1:
            # Its own vtable only: a constructor calls its base's constructor
            # before the store, a destructor stores first and calls its base's
            # destructor after.
            # (Only for a class with a base of its own: without one, either
            # can store and then call helpers.)
            store_at = VTABLE_STORE.search(f.body).start()
            call = CALL.search(f.body)
            has_base = any(b in vtables and b not in COM_SLOTS for b in bases.get(first, []))
            if not has_base:
                call = None
            if call and call.start() < store_at:
                claims[ident(first, 'constructor')].append((f.va, 'calls a base constructor, then stores %s\'s vtable into this' % first))
            elif call:
                claims[ident(first, 'destructor')].append((f.va, 'stores %s\'s vtable into this, then calls on (a base destructor)' % first))
            else:
                claims[ident(first, 'constructor_or_destructor')].append((f.va, 'stores %s\'s vtable into this and calls nothing' % first))
            f.this_class = f.this_class or first

    # One name per function (the first source above that named it wins), one
    # function per name (later claims get their address appended).
    taken = set()
    for name, vas in claims.items():
        for va, why in vas:
            f = functions[va]
            if f.name:
                continue
            final = name if name not in taken else '%s_%08X' % (name, va)
            taken.add(final)
            f.name, f.why = final, why


def header(f):
    lines = ['/* %s (0x%08X)' % (f.name or 'sub_%08X' % f.va, f.va)]
    if f.why:
        lines.append(' *   ' + f.why)
    if f.this_class:
        lines.append(' *   this (ecx) is a %s' % f.this_class)
    if f.strings:
        lines.append(' *   strings: ' + ', '.join(c_string(s, 40) for s in f.strings[:6]) +
                     (', and %d more' % (len(f.strings) - 6) if len(f.strings) > 6 else ''))
    if f.windows_calls:
        lines.append(' *   calls Windows: ' + ', '.join(f.windows_calls[:10]))
    if f.source_file:
        lines.append(' *   source file: %s (named in one of its messages)' % f.source_file)
    lines.append(' *   called from %d place%s' % (f.callers, '' if f.callers == 1 else 's')
                 if f.callers else ' *   not called directly (a virtual, a callback or an entry point)')
    return '\n'.join(lines) + '\n */\n'


def annotate_constants(text, image, vtable_class):
    """A comment after each line's first constant that is a string or a vtable."""
    def note(line):
        if '/* "' in line:
            return line
        for hexva in CONST.findall(line):
            va = int(hexva, 16)
            if va in vtable_class:
                return line + ' /* %s vtable */' % vtable_class[va]
            s = image.string(va)
            if s:
                return line + ' /* %s */' % c_string(s)
        return line
    return '\n'.join(note(l) for l in text.split('\n'))


def name_lift(gen_dir, image, rtti, known):
    files = sorted(f for f in os.listdir(gen_dir) if f.endswith(('.c', '.h')))
    texts = {f: open(os.path.join(gen_dir, f), encoding='utf-8').read() for f in files}
    if any(MARK in t for t in texts.values()):
        raise SystemExit('%s is already named: lift again first' % gen_dir)

    functions = {}
    for t in texts.values():
        defs = list(FUNC_DEF.finditer(t))
        for i, m in enumerate(defs):
            end = defs[i + 1].start() if i + 1 < len(defs) else len(t)
            functions[int(m.group(1)[4:], 16)] = Function(int(m.group(1)[4:], 16), t[m.start():end])
    infer(functions, image, rtti, known)
    vtable_class = {int(info['vtable'], 16): cls for cls, info in rtti.get('classes', {}).items()}

    rename = {'sub_%08X' % va: f.name for va, f in functions.items() if f.name}
    token = re.compile(r'\bsub_[0-9A-F]{8}\b')
    for fname, t in texts.items():
        if fname.endswith('.c') and FUNC_DEF.search(t):
            t = FUNC_DEF.sub(lambda m: header(functions[int(m.group(1)[4:], 16)]) + m.group(0), t)
            t = annotate_constants(t, image, vtable_class)
            t = t.replace('/* Auto-generated by XWA recompiler - DO NOT EDIT */', '/* Generated by the lift: do not edit */')
            t = MARK + '\n' + t
        t = token.sub(lambda m: rename.get(m.group(0), m.group(0)), t)
        with open(os.path.join(gen_dir, fname), 'w', encoding='utf-8', newline='\n') as out:
            out.write(t)
    return functions


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('exe')
    ap.add_argument('--gen', required=True, help='the lift\'s output directory, rewritten in place')
    ap.add_argument('--rtti', help='tools/cpp/rtti.py\'s JSON')
    ap.add_argument('--known', action='append', default=[], metavar='VA=NAME', help='a name the host knows')
    ap.add_argument('--report', help='write {va: {name, why}} here')
    a = ap.parse_args(argv)
    rtti = json.load(open(a.rtti)) if a.rtti and os.path.exists(a.rtti) else {}
    known = {int(k, 0): v for k, v in (x.split('=', 1) for x in a.known)}
    functions = name_lift(a.gen, Image(a.exe), rtti, known)
    named = Counter(f.why.split(' ')[0] if f.why else None for f in functions.values())
    print('[*] named %d of %d functions (%s)' % (
        sum(1 for f in functions.values() if f.name), len(functions),
        ', '.join('%s %d' % (k, n) for k, n in named.most_common() if k)))
    if a.report:
        with open(a.report, 'w') as out:
            json.dump({'0x%08X' % va: {'name': f.name, 'why': f.why} for va, f in sorted(functions.items()) if f.name},
                      out, indent=1)


def demo():
    """A synthetic lift: a debug-named function, a COM slot, a constructor."""
    import tempfile
    rdata = b'\0MapClass::Init_Clear entry\n\0'
    image = Image.__new__(Image)
    image.data = b'\0' * 0x200 + rdata + struct.pack('<III', 0x00401000, 0x00401100, 0x00401200)
    image.base = 0x400000
    image.sections = [(0x401000, 0x1000, 0, 0, True), (0x500000, 0x100, 0x200, 0x100, False)]
    vt = 0x500000 + len(rdata)
    rtti = {'classes': {'Thing': {'vtable': '0x%08X' % vt, 'slots': 3, 'bases': ['IUnknown']},
                        'Base': {'vtable': '0x%08X' % (vt + 4), 'slots': 0, 'bases': []}}}
    rtti['classes']['Thing']['bases'] = ['Base', 'IUnknown']
    gen = tempfile.mkdtemp()
    with open(os.path.join(gen, 'recomp_0000.c'), 'w') as f:
        f.write('/* Auto-generated by XWA recompiler - DO NOT EDIT */\n'
                'void sub_00401000(void) {\n    eax = 0x00500001u; /* push */\n    RECOMP_CALL(sub_00401300);\n}\n'
                'void sub_00401100(void) {\n}\n'
                'void sub_00401300(void) {\n    MEM32(esi) = 0x%08Xu;\n    MEM32(esi) = 0x%08Xu;\n}\n' % (vt + 4, vt))
    functions = name_lift(gen, image, rtti, {})
    out = open(os.path.join(gen, 'recomp_0000.c')).read()
    assert functions[0x401000].name == 'MapClass__Init_Clear', functions[0x401000].name    # its message beats slot 0
    assert functions[0x401100].name == 'Thing__AddRef', functions[0x401100].name
    assert functions[0x401300].name == 'Thing__constructor', functions[0x401300].name
    assert 'RECOMP_CALL(Thing__constructor)' in out and 'sub_00401300' not in out
    assert '"MapClass::Init_Clear entry\\n"' in out and 'called from 1 place' in out
    try:
        name_lift(gen, image, rtti, {})
        raise AssertionError('named twice')
    except SystemExit:
        pass
    print('name_lift demo: ok')


if __name__ == '__main__':
    if sys.argv[1:] == ['--demo']:
        demo()
    else:
        main()
