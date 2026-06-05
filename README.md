
# CTF Helper v1

<div align="center">

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python 3.x](https://img.shields.io/badge/python-3.x-blue?logo=python)
![Status: Active](https://img.shields.io/badge/status-active-brightgreen)

**Lightweight, fast, single-file CLI toolkit for rapid CTF flag extraction.**

---

</div>

## 🎯 Why this repo?

If you're grinding CTFs or mastering offensive security, you need a high-performance, portable toolkit that goes from `puzzle` → `flag` in seconds. **CTF Helper** is designed for speed, minimal dependency overhead, and effortless extensibility.

---

## ⚡ Features (v1)

| Category | Functionality |
| :--- | :--- |
| **Encodings** | Base16/32/58/64/85 encode & decode |
| **Ciphers** | Caesar (shift/brute), ROT13, ROT47 |
| **XOR** | Single-byte XOR decrypt & automated brute-force |
| **Hashing** | Hash identification & dictionary attacks (MD5/SHA1/SHA256) |
| **Stegano** | EXIF metadata extraction & LSB text carving (PNG/BMP) |
| **Forensics** | String extraction & Magic-byte file identification |
| **Utility** | Integrated hex viewer for file analysis |

---

## 🛠 Usage Examples

**Decode Base64**
```bash
python3 ctfhelper.py base base64 decode --data "U29tZVRleHQ="

```
**Brute-force Caesar Cipher**
```bash
python3 ctfhelper.py caesar --text "uryyb" --brute

```
**Brute-force XOR Key**
```bash
python3 ctfhelper.py xor --file secret.bin --brute

```
**Extract EXIF Metadata**
```bash
python3 ctfhelper.py steg --exif image.jpg

```
## 🚀 Quickstart
 1. **Clone the repository:**
```bash
   git clone [https://github.com/PAIN-hub/ctfhelper.git](https://github.com/PAIN-hub/ctfhelper.git)
   cd ctfhelper

```
 2. **Environment Setup:**
```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt

```
 3. **Execution:**
```bash
   python3 ctfhelper.py --help

```
> **Pro Tip:** Keep a local copy of rockyou.txt for efficient hash cracking via the --wordlist flag.
> 
## 🏗 Roadmap
 * [ ] **PCAP Engine:** Automated HTTP object/credential extraction.
 * [ ] **Audio Stego:** Frequency analysis and LSB tools for WAV/MP3.
 * [ ] **Web Interface:** Cyber-minimalist dashboard (Flask + Tailwind).
 * [ ] **Plugin System:** Dynamic loading for third-party modules.
## 🤝 Contributing
Contributions are welcome. Please ensure new features are **modular**, **well-tested**, and follow the existing code style. Open an issue first to discuss your implementation plan.
## ⚖️ License
Distributed under the **MIT License**. See LICENSE for more information.
<div align="center">
<sub>Built by ƤȺIƝ | Powered by logic</sub>
</div>
```
