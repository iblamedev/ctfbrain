import base64
import re
import urllib.parse
import tempfile
import os
import string
import hashlib
import binascii
import codecs
import quopri
import io
from core.colors import red, green, yellow, highlight
from core.executor import run_cmd
from core.tools import check_tool, requires_tools, check_python_module, get_pip_instructions

ROCKYOU = "/usr/share/wordlists/rockyou.txt"

# Check Python modules
CRYPTO_OK = check_python_module('Crypto.Util.number', 'pycryptodome')
SYMPY_OK = check_python_module('sympy')

# Universal flag pattern
FLAG_PATTERN = r'[a-zA-Z0-9_]+\{[^}]*\}'

# ---------------- HELPER FUNCTIONS ----------------

MORSE_CODE_DICT = {
    '.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G',
    '....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N',
    '---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U',
    '...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z',
    '-----':'0','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5',
    '-....':'6','--...':'7','---..':'8','----.':'9',
    '.-.-.-': '.', '--..--': ',', '..--..': '?', '.----.': "'", '-.-.--': '!',
    '-..-.': '/', '-.--.': '(', '-.--.-': ')', '.-...': '&', '---...': ':',
    '-.-.-.': ';', '-...-': '=', '.-.-.': '+', '-....-': '-', '..--.-': '_',
    '.-..-.': '"', '...-..-': '$', '.--.-.': '@'
}

def is_base64(s):
    return (
        len(s) > 8 and
        re.fullmatch(r"[A-Za-z0-9+/=]+", s) and
        len(s) % 4 == 0 and
        not re.fullmatch(r"[0-9a-fA-F]+", s)
    )

def is_base32(s):
    try:
        if len(s) < 8:
            return False
        return re.fullmatch(r'[A-Z2-7=]+', s) is not None and len(s) % 8 == 0
    except:
        return False

def is_hex(s): 
    return re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0

def is_binary(s):
    if not s:
        return False
    cleaned = re.sub(r'[\s\n]+', '', s)
    return re.fullmatch(r'[01]+', cleaned) is not None and len(cleaned) % 8 == 0

def is_decimal_ascii(data):
    if not data:
        return False, []
    
    if isinstance(data, str):
        parts = re.split(r'[\s,\n]+', data.strip())
    else:
        parts = re.split(r'[\s,\n]+', str(data).strip())
    
    decimals = []
    for part in parts:
        if not part:
            continue
        try:
            num = int(part)
            if 32 <= num <= 126 or num == 10:
                decimals.append(num)
            else:
                return False, []
        except ValueError:
            return False, []
    
    return len(decimals) > 3, decimals

def is_octal(data):
    if not data:
        return False
    parts = re.split(r'[\s\n]+', data.strip())
    for part in parts:
        if not part:
            continue
        if not re.fullmatch(r'[0-7]+', part):
            return False
        try:
            val = int(part, 8)
            if val > 255:
                return False
        except:
            return False
    return len(parts) > 3

def is_quoted_printable(data):
    if '=' not in data:
        return False
    return re.search(r'=[0-9A-Fa-f]{2}', data) is not None

def is_jwt(s): 
    return s.count('.') == 2 and len(s) > 20

def is_hash(s): 
    return re.fullmatch(r"[A-Fa-f0-9]{32,128}", s)

def detect_hash_type(hashval):
    length = len(hashval)
    if length == 32: return "MD5"
    elif length == 40: return "SHA1"
    elif length == 64: return "SHA256"
    elif length == 128: return "SHA512"
    return "Unknown"

def score_text(text):
    if not text: return 0
    printable = [c for c in text if c in string.printable]
    return len(printable) / len(text)

def extract_flag_from_output(output):
    if not output:
        return None
    
    if not isinstance(output, str):
        output = str(output)
    
    flags = re.findall(FLAG_PATTERN, output)
    if flags:
        return flags[0]
    
    base64_patterns = re.findall(r'[A-Za-z0-9+/=]{20,200}', output)
    for b64 in base64_patterns:
        try:
            padded = b64 + '=' * (-len(b64) % 4)
            decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
            flags = re.findall(FLAG_PATTERN, decoded)
            if flags:
                return flags[0]
        except:
            pass
    
    return None

# ---------------- DECODERS ----------------

def decode_decimal_ascii(decimals):
    result = []
    for d in decimals:
        if d == 10:
            result.append('\n')
        else:
            result.append(chr(d))
    return ''.join(result)

def decode_octal(data):
    try:
        parts = re.split(r'[\s\n]+', data.strip())
        bytes_data = bytes(int(p, 8) for p in parts if p)
        return bytes_data.decode('utf-8', errors='ignore')
    except:
        return None

def decode_binary(binary_str):
    cleaned = re.sub(r'[\s\n]+', '', binary_str)
    bytes_data = bytes(int(cleaned[i:i+8], 2) for i in range(0, len(cleaned), 8))
    return bytes_data.decode('utf-8', errors='ignore')

def decode_hex(hex_str):
    try:
        bytes_data = bytes.fromhex(hex_str)
        return bytes_data.decode('utf-8', errors='ignore')
    except:
        return None

def decode_base64(data):
    try:
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except:
        return None

def decode_base32(data):
    try:
        padded = data + '=' * (-len(data) % 8)
        return base64.b32decode(padded).decode('utf-8', errors='ignore')
    except:
        return None

def decode_rot(text, shift=None):
    results = []
    
    if shift is not None:
        out = ""
        for c in text:
            if c.isalpha():
                base = ord('a') if c.islower() else ord('A')
                out += chr((ord(c) - base - shift) % 26 + base)
            else:
                out += c
        return out
    
    for shift in range(1, 26):
        out = ""
        for c in text:
            if c.isalpha():
                base = ord('a') if c.islower() else ord('A')
                out += chr((ord(c) - base - shift) % 26 + base)
            else:
                out += c
        results.append((shift, out))
    
    return results

def decode_rot13(text):
    return codecs.decode(text, 'rot_13')

def decode_rot47(text):
    result = []
    for c in text:
        if 33 <= ord(c) <= 126:
            result.append(chr(33 + ((ord(c) - 33 + 47) % 94)))
        else:
            result.append(c)
    return ''.join(result)

def decode_atbash(text):
    result = ""
    for c in text:
        if c.isalpha():
            if c.islower():
                result += chr(219 - ord(c))
            else:
                result += chr(155 - ord(c))
        else:
            result += c
    return result

def decode_reverse(text):
    return text[::-1]

def decode_url(text):
    try:
        return urllib.parse.unquote(text)
    except:
        return text

def decode_quoted_printable(text):
    try:
        return quopri.decodestring(text.encode()).decode('utf-8', errors='ignore')
    except:
        return None

def decode_ascii85(text):
    try:
        return base64.a85decode(text).decode('utf-8', errors='ignore')
    except:
        try:
            return base64.b85decode(text).decode('utf-8', errors='ignore')
        except:
            return None

def is_morse_likely(text):
    if not text:
        return False
    text = text.strip()
    if re.fullmatch(r'[.\- /]+', text):
        if '.' in text and '-' in text:
            return True
        if len(text) > 5:
            return True
    return False

def is_rot_likely(text):
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return False
    
    if re.search(r'[a-z]{5}[A-Z]{3}\{', text):
        return True
    
    return False

def is_rot47_likely(text):
    if re.search(r'[A-Za-z]+\{[A-Za-z0-9_]+\}', text):
        symbol_count = sum(1 for c in text if 33 <= ord(c) <= 47 or 58 <= ord(c) <= 64)
        if symbol_count > len(text) * 0.2:
            return True
    return False

def is_atbash_likely(text):
    if re.search(r'[A-Za-z]{5,8}\{[A-Za-z0-9_]+\}', text):
        sample = ''.join([c for c in text if c.isalpha()][:10])
        if len(sample) > 3:
            first_half = sum(1 for c in sample if c.lower() <= 'm')
            second_half = len(sample) - first_half
            if abs(first_half - second_half) < 3:
                return True
    return False

def recursive_decode(data, depth=0, max_depth=10, seen=None):
    if seen is None:
        seen = set()
    
    if depth >= max_depth:
        return data
    
    data_hash = hashlib.md5(data.encode()).hexdigest()
    if data_hash in seen:
        print(f"{yellow('[*]')} Detected cyclic decoding - stopping")
        return data
    seen.add(data_hash)
    
    original = data
    decoded = None
    decode_type = None
    
    print(f"{yellow('[*]')} Decode attempt #{depth+1}")
    
    flag = extract_flag_from_output(data)
    if flag:
        return data
    
    if is_base64(data):
        try:
            decoded = decode_base64(data)
            if decoded and score_text(decoded) > 0.5:
                decode_type = "Base64"
                print(f"{green('[+]')} Base64 decoded -> {highlight(decoded[:50])}")
        except:
            pass
    
    if not decoded and is_base32(data):
        try:
            decoded = decode_base32(data)
            if decoded and score_text(decoded) > 0.5:
                decode_type = "Base32"
                print(f"{green('[+]')} Base32 decoded -> {highlight(decoded[:50])}")
        except:
            pass
    
    if not decoded and is_hex(data):
        try:
            decoded = decode_hex(data)
            if decoded and score_text(decoded) > 0.5:
                decode_type = "Hex"
                print(f"{green('[+]')} Hex decoded -> {highlight(decoded[:50])}")
        except:
            pass
    
    if not decoded and is_binary(data):
        try:
            decoded = decode_binary(data)
            if decoded and score_text(decoded) > 0.5:
                decode_type = "Binary"
                print(f"{green('[+]')} Binary decoded -> {highlight(decoded[:50])}")
        except:
            pass
    
    if not decoded:
        is_decimal, decimals = is_decimal_ascii(data)
        if is_decimal:
            decoded = decode_decimal_ascii(decimals)
            if decoded and score_text(decoded) > 0.5:
                decode_type = "Decimal ASCII"
                print(f"{green('[+]')} Decimal ASCII decoded -> {highlight(decoded[:50])}")
    
    if not decoded and is_octal(data):
        decoded = decode_octal(data)
        if decoded and score_text(decoded) > 0.5:
            decode_type = "Octal"
            print(f"{green('[+]')} Octal decoded -> {highlight(decoded[:50])}")
    
    if not decoded and '%' in data:
        decoded = decode_url(data)
        if decoded != original and score_text(decoded) > 0.5:
            decode_type = "URL"
            print(f"{green('[+]')} URL decoded -> {highlight(decoded[:50])}")
    
    if not decoded and len(data) > 10:
        reversed_data = decode_reverse(data)
        if score_text(reversed_data) > 0.6:
            decoded = reversed_data
            decode_type = "Reverse"
            print(f"{green('[+]')} Reverse decoded -> {highlight(decoded[:50])}")
    
    if not decoded and len(data) > 5:
        rot13_data = decode_rot13(data)
        if rot13_data != data and (extract_flag_from_output(rot13_data) or score_text(rot13_data) > 0.6):
            decoded = rot13_data
            decode_type = "ROT13"
            print(f"{green('[+]')} ROT13 decoded -> {highlight(decoded[:50])}")
    
    if not decoded and is_rot47_likely(data):
        rot47_data = decode_rot47(data)
        if rot47_data != data and (extract_flag_from_output(rot47_data) or score_text(rot47_data) > 0.6):
            decoded = rot47_data
            decode_type = "ROT47"
            print(f"{green('[+]')} ROT47 decoded -> {highlight(decoded[:50])}")
    
    if not decoded and is_rot_likely(data):
        rot_results = decode_rot(data)
        for shift, result in rot_results:
            if extract_flag_from_output(result) or 'flag' in result.lower():
                decoded = result
                decode_type = f"ROT-{shift}"
                print(f"{green('[+]')} {decode_type} decoded -> {highlight(decoded[:50])}")
                break
    
    if not decoded and is_atbash_likely(data):
        atbash_data = decode_atbash(data)
        if atbash_data != data and (extract_flag_from_output(atbash_data) or score_text(atbash_data) > 0.6):
            decoded = atbash_data
            decode_type = "Atbash"
            print(f"{green('[+]')} Atbash decoded -> {highlight(decoded[:50])}")
    
    if not decoded and is_quoted_printable(data):
        qp_data = decode_quoted_printable(data)
        if qp_data and score_text(qp_data) > 0.5:
            decoded = qp_data
            decode_type = "Quoted-Printable"
            print(f"{green('[+]')} Quoted-Printable decoded -> {highlight(decoded[:50])}")
    
    if not decoded and len(data) > 5:
        a85_data = decode_ascii85(data)
        if a85_data and score_text(a85_data) > 0.5:
            decoded = a85_data
            decode_type = "ASCII85"
            print(f"{green('[+]')} ASCII85 decoded -> {highlight(decoded[:50])}")
    
    if not decoded or decoded == original:
        return original
    
    flag = extract_flag_from_output(decoded)
    if flag:
        print(f"\n{red('[🏆 FLAG FOUND]')} {highlight(flag)}")
        return flag
    
    return recursive_decode(decoded, depth + 1, max_depth, seen)

def is_unicode_mess(data):
    if not data or len(data) < 10:
        return False
    
    non_ascii_count = sum(1 for c in data if ord(c) > 127)
    return non_ascii_count > len(data) * 0.5

def decode_utf16(data):
    results = []
    encodings = ['utf-16-be', 'utf-16-le']
    
    for encoding in encodings:
        try:
            bytes_data = data.encode('utf-8')
            decoded = bytes_data.decode(encoding, errors='ignore')
            if score_text(decoded) > 0.6 and len(decoded) > 10:
                results.append((encoding, decoded))
        except:
            pass
        
        try:
            bytes_data = data.encode('utf-16-be')
            decoded = bytes_data.decode('utf-8', errors='ignore')
            if score_text(decoded) > 0.6 and len(decoded) > 10:
                results.append(('utf-16-be->utf-8', decoded))
        except:
            pass
    
    return results

# ---------------- RSA SOLVER ----------------

def solve_rsa_from_numbers(data):
    n = re.search(r"N\s*[:=]\s*(\d+)", data, re.I)
    e = re.search(r"e\s*[:=]\s*(\d+)", data, re.I)
    c = re.search(r"(ciphertext|cyphertext)\s*[:=]\s*(\d+)", data, re.I)

    if not (n and c):
        return False, None

    if not CRYPTO_OK:
        print(f"{red('[-]')} pycryptodome not installed (needed for RSA).")
        return False, None

    N = int(n.group(1))
    e_val = int(e.group(1)) if e and e.group(1).isdigit() else 65537
    C = int(c.group(2))

    print(f"{green('[+]')} RSA parameters detected")
    print(f"    N = {N}")
    print(f"    e = {e_val}")
    print(f"    ciphertext = {C}")

    p = q = None

    if SYMPY_OK:
        print(f"{green('[+]')} Factoring with sympy…")
        import sympy as sp
        factors = list(sp.factorint(N).keys())
        if len(factors) == 2:
            p, q = factors
    else:
        print(f"{yellow('[*]')} Trying naive factorization...")
        for i in range(2, 1_000_000):
            if N % i == 0:
                p = i
                q = N // i
                break

    if not p:
        print(f"{red('[-]')} Failed to factor N automatically")
        return False, None

    from Crypto.Util.number import long_to_bytes, inverse
    phi = (p - 1) * (q - 1)
    d = inverse(e_val, phi)
    m = pow(C, d, N)
    flag = long_to_bytes(m).decode(errors="ignore")

    print(f"\n{red('[FLAG FOUND]')} {highlight(flag)}\n")
    return True, flag

# ---------------- HASH CRACKING ----------------

@requires_tools('john')
def crack_hash(hashval):
    hash_type = detect_hash_type(hashval)
    print(f"{green('[+]')} Detected hash type: {hash_type}")
    
    if check_tool("hashid"):
        run_cmd(f"hashid '{hashval}'")

    with tempfile.NamedTemporaryFile(delete=False, mode="w") as f:
        f.write(hashval)
        hashfile = f.name

    try:
        import requests
        try:
            r = requests.get(f"https://md5decrypt.net/en/Api/api.php?hash={hashval}", timeout=5)
            if r.text and len(r.text) > 10:
                print(f"{green('[+]')} Online lookup found: {highlight(r.text)}")
                return r.text
        except:
            pass
        
        run_cmd(f"john --wordlist={ROCKYOU} {hashfile}")
        result = run_cmd(f"john --show {hashfile}")
        
        match = re.search(r':([^:]+)', result)
        if match:
            return match.group(1)
    finally:
        os.unlink(hashfile)
    
    return None

# ---------------- CLASSIC CIPHERS ----------------

def solve_morse(text):
    if not re.fullmatch(r"[.\- /]+", text): return False, None
    words = text.split('  ')
    decoded_words = []
    for word in words:
        letters = word.split()
        decoded_word = ''.join(MORSE_CODE_DICT.get(letter, '?') for letter in letters)
        decoded_words.append(decoded_word)
    result = ' '.join(decoded_words)
    print(highlight(result))
    return True, result

def solve_rot(text):
    for shift in range(1, 26):
        out = ""
        for c in text:
            if c.isalpha():
                base = ord('a') if c.islower() else ord('A')
                out += chr((ord(c) - base + shift) % 26 + base)
            else:
                out += c
        if extract_flag_from_output(out):
            print(f"ROT-{shift}: {highlight(out)}")
            return True, out
    return False, None

def solve_xor(hex_data):
    try:
        raw = bytes.fromhex(hex_data)
    except:
        return False, None

    for k in range(256):
        out = bytes(b ^ k for b in raw)
        try:
            s = out.decode()
            if extract_flag_from_output(s):
                print(f"XOR key {hex(k)}: {highlight(s)}")
                return True, s
        except:
            pass
    return False, None

def solve_base64(data):
    try:
        decoded = base64.b64decode(data).decode(errors="ignore")
        if extract_flag_from_output(decoded) or score_text(decoded) > 0.8:
            print(highlight(decoded))
            return True, decoded
    except:
        pass
    return False, None

# ---------------- MAIN ENTRY ----------------

def run_crypto(data):
    """Run crypto analysis and return flag if found"""
    
    if os.path.exists(data):
        with open(data, "r", errors="ignore") as f:
            data = f.read().strip()

    print(f"{green('[+]')} Analyzing content…")
    
    # Try recursive decoding first
    print(f"{green('[+]')} Attempting recursive decoding...")
    result = recursive_decode(data)
    
    flag = extract_flag_from_output(result)
    if flag:
        return flag
    
    # Try specific decoders
    is_decimal, decimals = is_decimal_ascii(data)
    if is_decimal and len(decimals) > 3:
        print(f"{green('[+]')} Detected decimal ASCII values!")
        decoded = decode_decimal_ascii(decimals)
        print(f"{green('[+]')} Decoded: {highlight(decoded[:100])}")
        flag = extract_flag_from_output(decoded)
        if flag:
            return flag
    
    if is_binary(data):
        print(f"{green('[+]')} Detected binary encoding!")
        try:
            decoded = decode_binary(data)
            if decoded and score_text(decoded) > 0.5:
                print(f"{green('[+]')} Decoded: {highlight(decoded[:100])}")
                flag = extract_flag_from_output(decoded)
                if flag:
                    return flag
        except:
            pass
    
    if is_hex(data):
        print(f"{green('[+]')} Detected hex encoding!")
        decoded = decode_hex(data)
        if decoded and score_text(decoded) > 0.5:
            print(f"{green('[+]')} Decoded: {highlight(decoded[:100])}")
            flag = extract_flag_from_output(decoded)
            if flag:
                return flag
    
    if is_unicode_mess(data):
        print(f"{green('[+]')} Detected possible Unicode encoding issue!")
        utf16_results = decode_utf16(data)
        for encoding, decoded in utf16_results:
            print(f"{green('[+]')} {encoding} decode attempt: {highlight(decoded[:100])}")
            flag = extract_flag_from_output(decoded)
            if flag:
                return flag
    
    # Try RSA
    success, flag = solve_rsa_from_numbers(data)
    if success:
        return flag

    # Try hash cracking
    if is_hash(data):
        result = crack_hash(data)
        if result:
            return result

    # Try Morse
    if is_morse_likely(data):
        success, result = solve_morse(data)
        if success:
            return result

    # Try ROT
    success, result = solve_rot(data)
    if success:
        return result

    # Try XOR
    if is_hex(data):
        success, result = solve_xor(data)
        if success:
            return result

    # Try Base64
    if is_base64(data):
        success, result = solve_base64(data)
        if success:
            return result

    # Try plain text
    if score_text(data) > 0.9 and len(data) > 10:
        if any(x in data.lower() for x in ["flag", "ctf", "pico"]):
            print(f"{green('[+]')} Found potential flag in plaintext: {highlight(data)}")
            return data

    print(f"{yellow('[*]')} Crypto analysis complete - no flag found.")
    return None