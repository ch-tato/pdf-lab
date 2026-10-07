#!/usr/bin/env python3
"""
deobf_s4.py - STATIC deobfuscator for the S4 PDF JavaScript (obj 19).

It NEVER executes the JavaScript. It only reads the text and simulates
the three tricks the malware uses:
  1. string fragments stored in variables:      a = 'funct';
  2. fragments glued together with + / +=:      x += a + b + c;
  3. fragments stored REVERSED and fixed by a   b = wstwaxap('rav;');
     helper function that reverses a string
Every time the script hands a built string to its eval() alias
(e.g. hyltlzyr(gkphk);) we save that string as the next "stage".

Usage:
  python3 -I deobf_s4.py out_s4/js_19.js out_s4/decoded
"""
import ast
import os
import re
import sys

STR_ASSIGN = re.compile(r"^\s*(\w+)\s*=\s*('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")\s*;?\s*$")
CALL_ASSIGN = re.compile(r"^\s*(\w+)\s*=\s*(\w+)\(\s*('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")\s*\)\s*;?\s*$")
CONCAT = re.compile(r"^\s*(\w+)\s*(\+?=)\s*(\w+(?:\s*\+\s*\w+)*)\s*;?\s*$")
SINK = re.compile(r"^\s*(\w+)\(\s*(\w+)\s*\)\s*;?\s*$")
FUNC_DEF = re.compile(r"function\s+(\w+)\s*\(")


def lit(s):
    try:
        return ast.literal_eval(s)
    except Exception:
        return s[1:-1]


def main(src, outdir):
    os.makedirs(outdir, exist_ok=True)
    text = open(src, encoding="latin-1").read()
    vars_ = {}
    reversers = set()
    stage = 0
    unknown_calls = {}

    for line in text.splitlines():
        m = STR_ASSIGN.match(line)
        if m:
            vars_[m.group(1)] = lit(m.group(2))
            continue
        m = CALL_ASSIGN.match(line)
        if m:
            name, func, arg = m.group(1), m.group(2), lit(m.group(3))
            if func in reversers:
                vars_[name] = arg[::-1]
            else:
                unknown_calls[func] = unknown_calls.get(func, 0) + 1
                vars_[name] = arg  # keep raw so nothing is lost
            continue
        m = CONCAT.match(line)
        if m:
            name, op, expr = m.groups()
            parts = [p.strip() for p in expr.split("+")]
            if all(p in vars_ for p in parts):
                val = "".join(vars_[p] for p in parts)
                vars_[name] = (vars_.get(name, "") + val) if op == "+=" else val
            continue
        m = SINK.match(line)
        if m and m.group(2) in vars_:
            payload = vars_[m.group(2)]
            stage += 1
            path = os.path.join(outdir, f"stage{stage}.js")
            with open(path, "w", encoding="latin-1") as f:
                f.write(payload)
            print(f"[+] {m.group(1)}({m.group(2)}) -> eval sink, {len(payload)} chars saved to {path}")
            print("    preview:", payload[:200].replace("\n", " "))
            for fn in FUNC_DEF.findall(payload):
                # a function that walks a string backwards with charAt = reverser
                if "charAt" in payload and "length-1" in payload.replace(" ", ""):
                    reversers.add(fn)
                    print(f"    -> '{fn}' looks like a string-REVERSE helper; decoding its calls")

    if unknown_calls:
        print("[!] calls to unknown helpers (left undecoded):", unknown_calls)
    print(f"[=] done, {stage} stage(s) extracted")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
