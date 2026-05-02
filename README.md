# ctfbrain - Experimental CTF Automation Framework

**Status: Pre-alpha / Experimental**

ctfbrain is an experimental CTF automation tool that detects challenge types and routes them to specialized modules.

## Installation

```bash
git clone https://github.com/iblamedev/ctfbrain.git
cd ctfbrain
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick Usage

python3 ctfbrain.py level1.py
python3 ctfbrain.py image.jpg
python3 ctfbrain.py http://example.com

## Modules

    Password cracker (XOR decryption)

    Git analysis (multi-branch flags)

    Steganography (LSB extraction)

    Crypto decoders (Base64, hex, rot13, rot47)

    Web recon (basic)

    Forensics (archive extraction)

    Network scanning (basic)

    Reverse engineering (strings, ltrace, strace)

    Privilege escalation (CTF use only)

    many more..

## Known Limitations

    Many modules are incomplete (enhancements can be done)

    False positives are common

    This is an experimental learning project

## Roadmap

MCP (Model Context Protocol) integration is planned for future releases.

## Requirements

pycryptodome>=3.19.0
sympy>=1.12
pwntools>=4.11.0
requests>=2.31.0
paramiko>=3.0.0
Pillow>=10.0.0
colorama>=0.4.6

## Screenshots

<img width="1545" height="813" alt="image" src="https://github.com/user-attachments/assets/3af8660e-405a-4d8d-875b-9e4f58efeb01" />

<img width="508" height="599" alt="image" src="https://github.com/user-attachments/assets/1540c513-cbc3-4e72-a242-69a36bcf62b8" />

The above images shown are example screenshots of a PicoGym WebDecode challenge.
