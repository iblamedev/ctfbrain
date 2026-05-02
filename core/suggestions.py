from core.colors import red, green, yellow, highlight

def banner(title):
    print(f"\n{yellow('='*10)} {green(title)} {yellow('='*10)}")

def suggest_web(target):
    banner("WEB ATTACK CHECKLIST")
    print(f"1. {highlight('Robots & Sitemaps')}: Check /robots.txt and /sitemap.xml")
    print(f"2. {highlight('Cookies')}: Decode JWTs or change 'admin=false' to 'true'")
    print(f"3. {highlight('Input Fields')}: Try ' OR 1=1 -- or <script>alert(1)</script>")
    print(f"4. {highlight('Source Code')}: View Page Source (Ctrl+U) for comments/hidden inputs")
    print(f"5. {highlight('Headers')}: Check for custom headers in the response")

def suggest_crypto(target):
    banner("CRYPTO CHECKLIST")
    print(f"1. {highlight('Format')}: Identify the hash type (MD5? SHA256?).")
    print(f"2. {highlight('Keys')}: Is it RSA? Check for small 'e' (Wiener's Attack).")
    print(f"3. {highlight('XOR')}: Try bruteforcing single-byte keys.")
    print(f"4. {highlight('Cipher')}: Only letters? Try ROT13 or Vigenere.")
    print(f"5. {highlight('Classic')}: Look for Morse, Braille, or Bacon cipher.")

def suggest_forensics(target):
    banner("FORENSICS CHECKLIST")
    print(f"1. {highlight('Files')}: Did you extract everything with 'binwalk -e'?")
    print(f"2. {highlight('Stego')}: Try 'steghide' with empty password.")
    print(f"3. {highlight('Audio')}: Open in Audacity. Switch view to 'Spectrogram'.")
    print(f"4. {highlight('Morse')}: If it beeps, upload to: https://morsecode.world/international/decoder/audio.html")
    print(f"5. {highlight('Metadata')}: Check comments in 'exiftool'.")

def suggest_binary(target):
    banner("BINARY EXPLOITATION CHECKLIST")
    print(f"1. {highlight('Strings')}: Did you check for hardcoded flags?")
    print(f"2. {highlight('Buffer Overflow')}: formatting input > 100 chars crash it?")
    print(f"3. {highlight('Ghidra/Cutter')}: Decompile to see the logic.")
    print(f"4. {highlight('Permissions')}: Is it SUID? Can you run it as root?")
    print(f"5. {highlight('Ltrace')}: Look for strcmp() (string compare) functions.")

def suggest_network(target):
    banner("NETWORK / SYSTEM CHECKLIST")
    print(f"1. {highlight('Ports')}: Did Nmap miss high ports? Try '-p-'.")
    print(f"2. {highlight('Web')}: Is there a hidden web server on 8080 or 8000?")
    print(f"3. {highlight('SMB')}: Try 'smbclient -N -L \\\\{target}' for null login.")
    print(f"4. {highlight('Versions')}: Search Google for exploits (e.g., 'Apache 2.4.49 exploit').")