# ctfbrain - Experimental CTF Automation Framework

**Status: Pre-alpha / Experimental**

ctfbrain is an experimental CTF automation tool that detects challenge types and routes them to specialized modules.

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/ctfbrain.git
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

## Known Limitations

    Many modules are incomplete

    False positives are common

    This is an experimental learning project

## Roadmap

MCP (Model Context Protocol) integration is planned for future releases.

