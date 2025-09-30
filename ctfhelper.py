#!/usr/bin/env python3
"""
CTF Helper v1 - single-file Python CLI
Features:
- Base encodings: base16/32/58/64/85
- Caesar cipher (all shifts)
- ROT13, ROT47
- XOR single-byte brute & decrypt with key
- Hash identifier (by length) and wordlist cracker (md5, sha1, sha256)
- Steganography lite: EXIF extractor, LSB text extractor for simple PNG/BMP
- Strings extractor (like `strings`)
- File type detection via magic bytes
- Hex viewer

Usage examples (after making executable):
$ python3 ctfhelper.py base64 --decode "U29tZVRleHQ="
$ python3 ctfhelper.py caesar --brute "uryyb"   # tries all shifts
$ python3 ctfhelper.py xor --brute file.bin
$ python3 ctfhelper.py hash-crack --hash d41d8cd98f00b204e9800998ecf8427e --wordlist wordlist.txt
$ python3 ctfhelper.py steg --exif image.jpg

Dependencies: Pillow (optional, for image EXIF and LSB). Install with `pip install Pillow`.
"""

import argparse
import base64
import binascii
import hashlib
import sys
import os
import string
from pathlib import Path

try:
    from PIL import Image
except Exception:
    Image = None

VERSION = "1.0"

# ---------------------- Utilities ----------------------


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def write_bytes(path, b):
    with open(path, "wb") as f:
        f.write(b)


def is_printable_ascii(data, threshold=0.9):
    if not data:
        return False
    printable = sum(1 for c in data if 32 <= c < 127)
    return (printable / len(data)) >= threshold


# ---------------------- Base58 ----------------------

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(b: bytes) -> str:
    # Simple base58 encode
    n = int.from_bytes(b, "big")
    res = ""
    while n > 0:
        n, r = divmod(n, 58)
        res = BASE58_ALPHABET[r] + res
    # leading zeros
    leading_zeros = 0
    for c in b:
        if c == 0:
            leading_zeros += 1
        else:
            break
    return "1" * leading_zeros + res


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + BASE58_ALPHABET.index(ch)
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    # restore leading zeros
    leading_zeros = len(s) - len(s.lstrip("1"))
    return b"\x00" * leading_zeros + b


# ---------------------- Encodings ----------------------


def handle_base(args):
    data = args.data.encode() if args.data is not None else None
    if args.file:
        data = read_bytes(args.file)
    if args.mode == "base16":
        if args.action == "encode":
            print(binascii.b2a_hex(data).decode())
        else:
            print(binascii.a2b_hex(data).decode(errors="replace"))
    elif args.mode == "base32":
        if args.action == "encode":
            print(base64.b32encode(data).decode())
        else:
            print(base64.b32decode(data).decode(errors="replace"))
    elif args.mode == "base64":
        if args.action == "encode":
            print(base64.b64encode(data).decode())
        else:
            print(base64.b64decode(data).decode(errors="replace"))
    elif args.mode == "base85":
        if args.action == "encode":
            print(base64.a85encode(data).decode())
        else:
            print(base64.a85decode(data).decode(errors="replace"))
    elif args.mode == "base58":
        if args.action == "encode":
            print(b58encode(data))
        else:
            print(b58decode(args.data).decode(errors="replace"))


# ---------------------- Caesar / ROT ----------------------


def caesar_shift(s: str, shift: int) -> str:
    res = []
    for ch in s:
        if "a" <= ch <= "z":
            res.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            res.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
        else:
            res.append(ch)
    return "".join(res)


def handle_caesar(args):
    if args.brute:
        for shift in range(26):
            out = caesar_shift(args.text, shift)
            print(f"shift={shift}: {out}")
    else:
        print(caesar_shift(args.text, args.shift))


def rot13(s: str) -> str:
    return s.translate(
        str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
        )
    )


def rot47(s: str) -> str:
    res = []
    for ch in s:
        o = ord(ch)
        if 33 <= o <= 126:
            res.append(chr(33 + ((o - 33 + 47) % 94)))
        else:
            res.append(ch)
    return "".join(res)


# ---------------------- XOR ----------------------


def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes([b ^ key for b in data])


def handle_xor(args):
    data = read_bytes(args.file)
    if args.key is not None:
        k = (
            int(args.key, 0)
            if isinstance(args.key, str) and args.key.startswith("0x")
            else int(args.key)
        )
        out = xor_bytes(data, k)
        if args.out:
            write_bytes(args.out, out)
            print(f"Written decrypted output to {args.out}")
        else:
            try:
                print(out.decode())
            except Exception:
                print(out)
    elif args.brute:
        found = []
        for k in range(256):
            out = xor_bytes(data, k)
            if b"flag{" in out or b"FLAG{" in out:
                found.append((k, out))
            elif is_printable_ascii(out, threshold=0.85):
                found.append((k, out[:200]))
        for k, out in found:
            print(f"key=0x{k:02x} ->\n{out}\n---")
        if not found:
            print(
                "No likely plaintext found. Try lowering threshold or use --key if you know it."
            )


# ---------------------- Hash tools ----------------------

HASH_LENS = {32: "md5", 40: "sha1", 64: "sha256", 96: "sha384", 128: "sha512"}


def identify_hash(h: str) -> str:
    h = h.strip().lower()
    if all(c in string.hexdigits for c in h):
        return HASH_LENS.get(len(h), "unknown")
    return "unknown"


def handle_hash_ident(args):
    print(identify_hash(args.hash))


def handle_hash_crack(args):
    h = args.hash.strip().lower()
    alg = identify_hash(h)
    if alg == "unknown":
        print(
            "Unknown hash algorithm by length. Proceeding with common algos (md5, sha1, sha256)."
        )
        algs = ["md5", "sha1", "sha256"]
    else:
        algs = [alg]
    if not os.path.exists(args.wordlist):
        print(f"Wordlist not found: {args.wordlist}")
        return
    with open(args.wordlist, "rb", errors="ignore") as f:
        for i, line in enumerate(f):
            word = line.strip()
            if not word:
                continue
            for algo in algs:
                dig = hashlib.new(algo, word).hexdigest()
                if dig == h:
                    print(
                        f"Cracked! Algorithm={algo} word={word.decode(errors='ignore')}"
                    )
                    return
            if i and i % 50000 == 0:
                print(f"Tried {i} words...")
    print("Not found in wordlist.")


# ---------------------- Stego / EXIF / LSB ----------------------


def extract_exif(path):
    if Image is None:
        print(
            "Pillow not installed - EXIF extraction requires `Pillow`. Install with pip install Pillow"
        )
        return
    try:
        img = Image.open(path)
        exif = img._getexif()
        if not exif:
            print("No EXIF metadata found.")
            return
        from PIL.ExifTags import TAGS

        for k, v in exif.items():
            name = TAGS.get(k, k)
            print(f"{name}: {v}")
    except Exception as e:
        print("Failed to read EXIF:", e)


def lsb_extract_from_image(path, min_len=4):
    if Image is None:
        print(
            "Pillow not installed - LSB extraction requires `Pillow`. Install with pip install Pillow"
        )
        return
    img = Image.open(path)
    pixels = list(img.getdata())
    # flatten
    bits = []
    for px in pixels:
        if isinstance(px, int):
            components = [px]
        else:
            components = px[:3]
        for comp in components:
            bits.append(comp & 1)
    # convert bits to bytes
    b = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte = (byte << 1) | bits[i + j]
            else:
                byte = byte << 1
        b.append(byte)
    # search for printable sequences
    s = b.decode("latin1", errors="ignore")
    import re

    for m in re.finditer(r"([ -~]{%d,})" % min_len, s):
        print("Possible hidden text:", m.group(1))


# ---------------------- Strings extractor ----------------------


def handle_strings(args):
    data = read_bytes(args.file)
    min_len = args.min
    res = []
    cur = []
    for b in data:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                res.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        res.append("".join(cur))
    for r in res:
        print(r)


# ---------------------- File type detection ----------------------

MAGIC_MAP = [
    (b"\xff\xd8\xff", "jpg"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"PK\x03\x04", "zip"),
    (b"\x25PDF-", "pdf"),
    (b"Rar!", "rar"),
    (b"\x42\x4d", "bmp"),
]


def detect_file_type(path):
    head = read_bytes(path)[:16]
    for sig, name in MAGIC_MAP:
        if head.startswith(sig):
            return name
    return "unknown"


# ---------------------- Hex viewer ----------------------


def hex_view(path, width=16):
    data = read_bytes(path)
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hexs = " ".join(f"{c:02x}" for c in chunk)
        ascii_ = "".join((chr(c) if 32 <= c < 127 else ".") for c in chunk)
        print(f"{i:08x}: {hexs:<{width * 3}} {ascii_}")


# ---------------------- CLI ----------------------


def build_parser():
    p = argparse.ArgumentParser(
        prog="ctfhelper", description="CTF Helper v1 - quick utilities for CTFs"
    )
    p.add_argument("--version", action="version", version=VERSION)
    sub = p.add_subparsers(dest="cmd")

    # base
    pb = sub.add_parser("base", help="encode/decode baseX")
    pb.add_argument("mode", choices=["base16", "base32", "base58", "base64", "base85"])
    pb.add_argument("action", choices=["encode", "decode"])
    group = pb.add_mutually_exclusive_group(required=True)
    group.add_argument("--data", "-d", help="data string")
    group.add_argument("--file", "-f", help="file to read bytes from")
    pb.set_defaults(func=handle_base)

    # caesar
    pc = sub.add_parser("caesar", help="caesar cipher / brute")
    pc.add_argument("--text", "-t", required=True)
    pc.add_argument("--shift", "-s", type=int, default=13)
    pc.add_argument("--brute", action="store_true")
    pc.set_defaults(func=handle_caesar)

    # rot13/47
    pr13 = sub.add_parser("rot13", help="rot13")
    pr13.add_argument("text")
    pr13.set_defaults(func=lambda args: print(rot13(args.text)))
    pr47 = sub.add_parser("rot47", help="rot47")
    pr47.add_argument("text")
    pr47.set_defaults(func=lambda args: print(rot47(args.text)))

    # xor
    px = sub.add_parser("xor", help="xor tools")
    px.add_argument("--file", "-f", required=True)
    px.add_argument("--key", "-k", help="single byte key (int or 0x..)")
    px.add_argument("--out", "-o", help="output file")
    px.add_argument("--brute", action="store_true")
    px.set_defaults(func=handle_xor)

    # hash ident
    ph = sub.add_parser("hash-ident", help="identify hash by length")
    ph.add_argument("hash")
    ph.set_defaults(func=handle_hash_ident)

    # hash crack
    phc = sub.add_parser(
        "hash-crack", help="crack hash using wordlist (md5/sha1/sha256)"
    )
    phc.add_argument("--hash", required=True)
    phc.add_argument("--wordlist", required=True)
    phc.set_defaults(func=handle_hash_crack)

    # steg
    ps = sub.add_parser("steg", help="steganography helpers")
    ps.add_argument("--exif", help="extract exif from image")
    ps.add_argument("--lsb", help="extract LSB text from image")
    ps.set_defaults(func=handle_steg)

    # strings
    ps2 = sub.add_parser("strings", help="extract printable strings from file")
    ps2.add_argument("--file", "-f", required=True)
    ps2.add_argument("--min", type=int, default=4)
    ps2.set_defaults(func=handle_strings)

    # file type
    pft = sub.add_parser("filetype", help="detect file type via magic bytes")
    pft.add_argument("--file", "-f", required=True)
    pft.set_defaults(func=lambda args: print(detect_file_type(args.file)))

    # hex viewer
    phv = sub.add_parser("hexdump", help="hex viewer")
    phv.add_argument("--file", "-f", required=True)
    phv.add_argument("--width", type=int, default=16)
    phv.set_defaults(func=lambda args: hex_view(args.file, args.width))

    return p


def handle_steg(args):
    if args.exif:
        extract_exif(args.exif)
    if args.lsb:
        lsb_extract_from_image(args.lsb)


def main():
    p = build_parser()
    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        sys.exit(0)
    try:
        args.func(args)
    except Exception as e:
        print("Error:", e)


if __name__ == "__main__":
    main()
