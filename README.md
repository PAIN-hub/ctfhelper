# CTF Helper v1

> Lightweight, fast, single-file CLI toolkit to speed up common CTF tasks — crypto, stego, forensics, and quick decoders.


## Why this repo?

If you're grinding CTFs or just learning offensive security, you need a pocket toolkit that runs anywhere and gets you from puzzle → flag fast. ctfhelper is a single-file Python CLI that covers the essentials and is easy to extend.

## Features (v1)

#### ✅ Encodings: Base16/32/58/64/85 encode & decode

#### ✅ Ciphers: Caesar (brute / shift), ROT13, ROT47

#### ✅ XOR: Single-byte xor decrypt + brute-force

#### ✅ Hash tools: Identify hash by length and dictionary crack (md5/sha1/sha256)

#### ✅ Stego (lite): EXIF extractor, LSB text extraction for PNG/BMP

#### ✅ Forensics: strings-like extractor, file type detection (magic bytes)

#### ✅ Hex viewer: quick hexdump of any file


### decode base64
``` 
python3 ctfhelper.py base base64 decode --data "U29tZVRleHQ="
```

### brute caesar
```
python3 ctfhelper.py caesar --text "uryyb" --brute
```
### xor brute
```
python3 ctfhelper.py xor --file secret.bin --brute
```
### extract exif
```
python3 ctfhelper.py steg --exif image.jpg
```

## Quickstart

#### 1. Clone repository:
```
git clone https://github.com/PAIN-hub/ctfhelper.git
```
#### 2. Redirect to folder:
```
cd ctfhelper
```

#### 3. Create virtualenv (recommended):
``` 
python3 -m venv .venv
source .venv/bin/activate
```

#### 3. Install requirements:
```
pip install -r requirements.txt
```

### 4. Run:
```
python3 ctfhelper.py --help
```

# Recommended extras

rockyou.txt for hash cracking (place path when using --wordlist)

python-magic can be helpful on some platforms for file type detection


# Contributing

Contributions welcome. Want to add a feature? Open an issue describing the feature or submit a PR. Keep it modular: small, tested, and documented.

Roadmap / Stretch goals

PCAP analyzer (HTTP object extraction & credential finder)

> Audio stego tools (WAV/MP3)

> Web UI (Flask + Tailwind) for interactive use

> Plugin system for third-party scripts


License

MIT — drop a star if you like it ⭐

#### Author : ƤȺIƝ

*So go and fuck this up*
