#!/usr/bin/env python3
"""
decode_shellcode.py - STATIC decoder for the S4 shellcode. Nothing is executed.

Steps:
  1. take the longest unescape("%u....") string from the decoded JS
     (skipping the 0x9090 NOP / 0x0c0c spray fillers)
  2. convert %uXXXX (UTF-16 little-endian) into raw bytes
  3. read the XOR decoder stub at the start:
        E8 00000000   call $+5         ; GetPC trick
        5D            pop  ebp
        83 C5 xx      add  ebp, xx     ; -> start of encoded body
        B9 nnnnnnnn   mov  ecx, n      ; body length
        B0 kk         mov  al, kk      ; XOR key
        30 45 00      xor  [ebp], al   ; loop ...
  4. XOR-decode the body and print strings + known Windows API hashes

Usage:
  python3 -I decode_shellcode.py out_s4/decoded/stage2_pretty.js out_s4/shellcode_decoded.bin
"""
import re
import string
import struct
import sys

API_HASHES = {  # ROR-13 hashes used by classic Metasploit-style shellcode
    0xEC0E4E8E: "LoadLibraryA",
    0x0E8AFE98: "WinExec",
    0x73E2D87E: "ExitProcess",
    0x702F1A36: "URLDownloadToFileA",
    0x5B8ACA33: "GetTempPathA",
    0x7C0DFCAA: "GetProcAddress",
}


def main(js_path, out_path):
    js = open(js_path, encoding="latin-1").read()
    blobs = re.findall(r'unescape\(\s*["\']((?:%u[0-9a-fA-F]{4})+)["\']\s*\)', js)
    blobs = [b for b in blobs if not re.fullmatch(r"(%u9090|%u0c0c)+", b, re.I)]
    if not blobs:
        sys.exit("no shellcode-like unescape() string found")
    blob = max(blobs, key=len)
    words = re.findall(r"%u([0-9a-fA-F]{4})", blob)
    raw = b"".join(bytes([int(w[2:], 16), int(w[:2], 16)]) for w in words)
    print(f"[+] shellcode: {len(raw)} bytes")
    print("[+] decoder stub:", raw[:25].hex(" "))

    if raw[0] != 0xE8 or raw[5] != 0x5D or raw[6:8] != b"\x83\xc5":
        sys.exit("stub not recognised - inspect manually")
    start = 5 + raw[8]
    length = struct.unpack("<I", raw[10:14])[0]
    key = raw[15]
    print(f"[+] body offset={start}  length={length}  XOR key=0x{key:02x}")

    body = bytes(x ^ key for x in raw[start:start + length])
    open(out_path, "wb").write(body)
    print(f"[+] decoded body saved to {out_path}")

    print("[+] Windows API hashes found:")
    for i in range(len(body) - 3):
        h = struct.unpack("<I", body[i:i + 4])[0]
        if h in API_HASHES:
            print(f"      0x{h:08X} -> {API_HASHES[h]}")

    print("[+] readable strings (>=4 chars):")
    ok = set(string.printable.encode()) - set(b"\t\n\r\x0b\x0c")
    cur = b""
    for x in body + b"\x00":
        if x in ok:
            cur += bytes([x])
        else:
            if len(cur) >= 4:
                print("     ", cur.decode())
            cur = b""


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
