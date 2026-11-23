<div align="center">

# 🧠 CTFBRAIN
### Modular Context-Aware CTF Automation & Solver Engine

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Category](https://img.shields.io/badge/Focus-Forensics%20%7C%20Crypto%20%7C%20Rev%20%7C%20Binary-ff6b6b?style=for-the-badge)](https://github.com/iblamedev)
[![Architecture](https://img.shields.io/badge/Pipeline-Modular%20Plugin%20Engine-4ecdc4?style=for-the-badge)](https://github.com/iblamedev/ctfbrain)
[![License](https://img.shields.io/badge/License-MIT-success?style=for-the-badge)](LICENSE)

<p align="center">
  <b>An automated triage and reconnaissance framework engineered to compress the first twenty minutes of CTF challenge analysis into seconds.</b>
</p>

[Architecture](#-architecture) • [Core Pipelines](#-core-pipelines) • [Plugin Modules](#-plugin-modules) • [Quickstart](#-quickstart) • [Agentic Roadmap](#-agentic-roadmap-mcp)

</div>

---

## ⚡ Overview

In competitive Capture The Flag (CTF) tournaments, time spent on initial file classification, entropy calculation, and signature hunting represents friction. ctfbrain acts as an intelligent first-responder pipeline that digests challenge binaries, captures, and payloads, automatically extracting strings, decomposing nested structures, and testing baseline exploits.

---

## 🏛️ Architecture

```text
       [ Challenge Artifact / File ]
                     │
                     ▼
      ┌─────────────────────────────┐
      │  Triage & File Classifier   │  ◄── Magic Bytes, MIME, TrID & Metadata
      └──────────────┬──────────────┘
                     │
                     ▼
      ┌─────────────────────────────┐
      │   Shannon Entropy Engine    │  ◄── High: Encrypted/Packed | Low: Plaintext/Code
      └──────────────┬──────────────┘
                     │
      ┌──────────────┴──────────────┐
      ▼                             ▼
┌──────────────────┐       ┌──────────────────┐
│ Static Extractors│       │  Crypto Engines  │
│ • strings -a -e  │       │ • XOR Brute/Key  │
│ • binwalk / carve│       │ • BaseN Decoders │
│ • exiftool / png │       │ • RSA Weak-Key   │
└────────┬─────────┘       └────────┬─────────┘
         │                          │
         └─────────────┬────────────┘
                       │
                       ▼
      ┌─────────────────────────────┐
      │  Regex Flag Hunter (Multi)  │  ◄── CTF{...}, flag{...}, HTB{...}, POCTF{...}
      └──────────────┬──────────────┘
                     │
                     ▼
      ┌─────────────────────────────┐
      │  Summary Markdown Dossier   │
      └─────────────────────────────┘
```

---

## 🚀 Core Pipelines

- **Automated Artifact Classification**: Instant MIME and magic-byte signature extraction coupled with recursive archive and steganography carvers.
- **Shannon Entropy Profiling**: Visual byte-entropy graphing across 256-byte blocks to pinpoint packed shellcode, concealed ciphertext, or injected zip headers.
- **Multi-Format Decoder Streams**: Automated multi-stage decoding across URL, Base64/32/58/85/91, Hex, Rot13/47, Morse, and binary streams.
- **Regex Flag Correlation**: Parallel regex scanner matching standard competition flag wrappers with customizable confidence weighting.

---

## 🧩 Plugin Modules

| Category | Modules Included | Key Capability |
| :--- | :--- | :--- |
| Forensics | `pcap_stream_dumper`, `png_chunk_parser`, `wav_spectrogram` | Automated extraction of HTTP/DNS streams, IHDR CRC repair, LSB carving. |
| Crypto | `xor_auto_key`, `frequency_analyser`, `rsa_wiener_factordb` | Known-plaintext XOR recovery, English digraph scoring, FactorDB integration. |
| Reverse | `elf_header_dumper`, `gdb_script_generator`, `anti_debug_probe` | Quick section mapping, automated Angr symbolic execution harness generation. |
| Web | `jwt_none_forger`, `sqli_oob_listener`, `subdomain_recon` | Alg:none token synthesis, automated Blind SQLi time-delay testing. |

---

## 💻 Quickstart

```bash
# Clone and install
git clone https://github.com/iblamedev/ctfbrain.git
cd ctfbrain
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Run automated triage on a challenge file
python ctfbrain.py triage ./sample_challenge.bin --format=markdown --out=report.md

# Run deep crypto brute-force
python ctfbrain.py crypto --xor-brute ciphertext.hex --wrapper="POCTF{"
```

---

## 🤖 Agentic Roadmap (MCP)

`ctfbrain` is evolving toward integration with the Model Context Protocol (MCP), exposing tool endpoints (`triage_artifact`, `disassemble_function`, `run_angr_path`) directly to local LLMs (Ollama, Claude, GPT-4) to power fully autonomous CTF analysis agents.

---

<div align="center">

**Dev Balaji A**  
[LinkedIn](https://www.linkedin.com/in/dev-balaji) • [GitHub](https://github.com/iblamedev) • [Portfolio](https://devsky.space)

</div>
