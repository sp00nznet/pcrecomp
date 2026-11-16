"""
wine_spec_to_json.py - The Win16 ordinal map, from Wine's .spec files (no IDA).

win16.py resolves `KERNEL.90` to `lstrlen` through win16_imports.json. That
map used to come only from idt_to_json.py, which reads the .idt files IDA
ships. Wine documents the same ordinals in its 16-bit .spec files
(dlls/user.exe16/user.exe16.spec: `90 pascal -ret16 ... ` ...), so this builds
an equivalent map from them:

    python tools/ne/wine_spec_to_json.py -o tools/ne/win16_imports.json
    python tools/ne/wine_spec_to_json.py --specs DIR -o out.json   # offline

Without --specs it downloads the .spec files (a few hundred KB) from the Wine
mirror on GitHub. Names are upper-cased, as idt_to_json writes them. The
output is generated, not shipped: keep it gitignored, like the IDA one.
"""
import argparse
import json
import os
import re
import urllib.request

# NE module name -> Wine's 16-bit DLL directory
MODULES = {
    'KERNEL': 'krnl386.exe16', 'USER': 'user.exe16', 'GDI': 'gdi.exe16',
    'MMSYSTEM': 'mmsystem.dll16', 'COMMDLG': 'commdlg.dll16',
    'TOOLHELP': 'toolhelp.dll16', 'WIN87EM': 'win87em.dll16', 'WING': 'wing.dll16',
    'SHELL': 'shell.dll16', 'VER': 'ver.dll16', 'LZEXPAND': 'lzexpand.dll16',
    'KEYBOARD': 'keyboard.drv16', 'SOUND': 'sound.drv16', 'DDEML': 'ddeml.dll16',
    'CTL3D': 'ctl3d.dll16', 'CTL3DV2': 'ctl3dv2.dll16', 'COMPOBJ': 'compobj.dll16',
    'OLE2': 'ole2.dll16', 'OLECLI': 'olecli.dll16', 'OLESVR': 'olesvr.dll16',
    'STORAGE': 'storage.dll16', 'SYSTEM': 'system.drv16', 'DISPLAY': 'display.drv16',
    'MOUSE': 'mouse.drv16', 'COMM': 'comm.drv16', 'WINSOCK': 'winsock.dll16',
}
URL = 'https://raw.githubusercontent.com/wine-mirror/wine/master/dlls/{0}/{0}.spec'
# `90 pascal -ret16 lstrlen(str) lstrlen16`, `3 stub EnableOEMLayer`,
# `1 equate __0000H 0`, `11 variable Foo(...)`: the name follows the kind and
# its -flags.
LINE = re.compile(r'^\s*(\d+)\s+\w+\s+(?:-\S+\s+)*([A-Za-z_][\w@?$]*)')


def parse(text):
    return {m.group(1): m.group(2).upper() for m in map(LINE.match, text.splitlines()) if m}


def read(module, specs):
    d = MODULES[module]
    if specs:
        with open(os.path.join(specs, d + '.spec'), encoding='utf-8') as f:
            return f.read()
    with urllib.request.urlopen(URL.format(d), timeout=30) as r:
        return r.read().decode('utf-8')


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('-o', '--output', required=True)
    ap.add_argument('--specs', help='directory of <dll>.spec files (default: download)')
    args = ap.parse_args()
    out = {}
    for mod in MODULES:
        try:
            out[mod] = parse(read(mod, args.specs))
        except OSError as e:
            print(f'  {mod}: skipped ({e})')
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(out, f, indent=1, sort_keys=True)
    print(f'wrote {args.output}: {len(out)} modules, {sum(map(len, out.values()))} ordinals')


def demo():
    t = parse('90  pascal -ret16 lstrlen(str) lstrlen16\n3 stub EnableOEMLayer\n# 4 no\n')
    assert t == {'90': 'LSTRLEN', '3': 'ENABLEOEMLAYER'}, t


if __name__ == '__main__':
    demo()
    main()
