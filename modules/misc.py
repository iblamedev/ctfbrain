#!/usr/bin/env python3
"""
Miscellaneous Module for CTF
Handles: Encoding, decoding, magic, weird challenges
"""
import os
import re
import base64
import codecs
import hashlib
import binascii
import quopri
import urllib.parse
from core.colors import red, green, yellow, blue, highlight

FLAG_PATTERN = r'[a-zA-Z0-9_]+\{[^}]*\}'

class MiscSolver:
    def __init__(self):
        self.found_flags = []
    
    def extract_flag(self, text):
        if not text:
            return None
        flags = re.findall(FLAG_PATTERN, str(text))
        if flags:
            return flags[0]
        return None
    
    def decode_base64(self, data):
        try:
            decoded = base64.b64decode(data).decode('utf-8', errors='ignore')
            if decoded:
                print(f"{green('[+]')} Base64 decoded: {highlight(decoded[:50])}")
                return decoded
        except:
            pass
        return None
    
    def decode_base32(self, data):
        try:
            padded = data + '=' * (-len(data) % 8)
            decoded = base64.b32decode(padded).decode('utf-8', errors='ignore')
            if decoded:
                print(f"{green('[+]')} Base32 decoded: {highlight(decoded[:50])}")
                return decoded
        except:
            pass
        return None
    
    def decode_base16(self, data):
        try:
            decoded = bytes.fromhex(data).decode('utf-8', errors='ignore')
            if decoded:
                print(f"{green('[+]')} Hex decoded: {highlight(decoded[:50])}")
                return decoded
        except:
            pass
        return None
    
    def decode_rot13(self, data):
        decoded = codecs.decode(data, 'rot_13')
        print(f"{green('[+]')} ROT13 decoded: {highlight(decoded[:50])}")
        return decoded
    
    def decode_rot47(self, data):
        result = []
        for c in data:
            if 33 <= ord(c) <= 126:
                result.append(chr(33 + ((ord(c) - 33 + 47) % 94)))
            else:
                result.append(c)
        decoded = ''.join(result)
        print(f"{green('[+]')} ROT47 decoded: {highlight(decoded[:50])}")
        return decoded
    
    def decode_atbash(self, data):
        result = []
        for c in data:
            if c.isalpha():
                if c.islower():
                    result.append(chr(219 - ord(c)))
                else:
                    result.append(chr(155 - ord(c)))
            else:
                result.append(c)
        decoded = ''.join(result)
        print(f"{green('[+]')} Atbash decoded: {highlight(decoded[:50])}")
        return decoded
    
    def decode_binary(self, data):
        if not re.fullmatch(r'[01\s]+', data):
            return None
        
        cleaned = re.sub(r'\s', '', data)
        if len(cleaned) % 8 != 0:
            return None
        
        try:
            bytes_data = bytes(int(cleaned[i:i+8], 2) for i in range(0, len(cleaned), 8))
            decoded = bytes_data.decode('utf-8', errors='ignore')
            if decoded:
                print(f"{green('[+]')} Binary decoded: {highlight(decoded[:50])}")
                return decoded
        except:
            pass
        return None
    
    def decode_octal(self, data):
        if not re.fullmatch(r'[0-7\s]+', data):
            return None
        
        try:
            parts = re.split(r'\s+', data.strip())
            bytes_data = bytes(int(p, 8) for p in parts if p)
            decoded = bytes_data.decode('utf-8', errors='ignore')
            if decoded:
                print(f"{green('[+]')} Octal decoded: {highlight(decoded[:50])}")
                return decoded
        except:
            pass
        return None
    
    def decode_decimal(self, data):
        if not re.fullmatch(r'[\d\s]+', data):
            return None
        
        try:
            parts = re.split(r'\s+', data.strip())
            bytes_data = bytes(int(p) for p in parts if p and 0 <= int(p) <= 255)
            decoded = bytes_data.decode('utf-8', errors='ignore')
            if decoded:
                print(f"{green('[+]')} Decimal decoded: {highlight(decoded[:50])}")
                return decoded
        except:
            pass
        return None
    
    def decode_url(self, data):
        try:
            decoded = urllib.parse.unquote(data)
            if decoded != data:
                print(f"{green('[+]')} URL decoded: {highlight(decoded[:50])}")
                return decoded
        except:
            pass
        return None
    
    def decode_quoted_printable(self, data):
        try:
            decoded = quopri.decodestring(data.encode()).decode('utf-8', errors='ignore')
            if decoded:
                print(f"{green('[+]')} Quoted-printable decoded: {highlight(decoded[:50])}")
                return decoded
        except:
            pass
        return None
    
    def decode_ascii85(self, data):
        try:
            decoded = base64.a85decode(data).decode('utf-8', errors='ignore')
            if decoded:
                print(f"{green('[+]')} ASCII85 decoded: {highlight(decoded[:50])}")
                return decoded
        except:
            try:
                decoded = base64.b85decode(data).decode('utf-8', errors='ignore')
                if decoded:
                    print(f"{green('[+]')} Base85 decoded: {highlight(decoded[:50])}")
                    return decoded
            except:
                pass
        return None
    
    def decode_reverse(self, data):
        decoded = data[::-1]
        print(f"{green('[+]')} Reverse decoded: {highlight(decoded[:50])}")
        return decoded
    
    def is_morse(self, data):
        return bool(re.fullmatch(r'[.\- /]+', data.strip()))
    
    def decode_morse(self, data):
        morse_dict = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
            '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
            '----.': '9'
        }
        
        result = []
        for word in data.strip().split('  '):
            for letter in word.split():
                result.append(morse_dict.get(letter, '?'))
            result.append(' ')
        
        decoded = ''.join(result).strip()
        print(f"{green('[+]')} Morse decoded: {highlight(decoded[:50])}")
        return decoded
    
    def solve_misc(self, data):
        print(f"{green('[+]')} Analyzing miscellaneous data...")
        
        if os.path.exists(data):
            with open(data, 'r', errors='ignore') as f:
                data = f.read().strip()
        
        decoders = [
            ('base64', self.decode_base64),
            ('base32', self.decode_base32),
            ('hex', self.decode_base16),
            ('binary', self.decode_binary),
            ('octal', self.decode_octal),
            ('decimal', self.decode_decimal),
            ('url', self.decode_url),
            ('quoted-printable', self.decode_quoted_printable),
            ('ascii85', self.decode_ascii85),
            ('rot13', self.decode_rot13),
            ('rot47', self.decode_rot47),
            ('atbash', self.decode_atbash),
            ('reverse', self.decode_reverse)
        ]
        
        if self.is_morse(data):
            result = self.decode_morse(data)
            if result:
                flag = self.extract_flag(result)
                if flag:
                    return flag
        
        current = data
        for name, decoder in decoders:
            try:
                result = decoder(current)
                if result and result != current:
                    flag = self.extract_flag(result)
                    if flag:
                        return flag
                    current = result
            except:
                continue
        
        flag = self.extract_flag(current)
        if flag:
            return flag
        
        return None


def run_misc(target):
    solver = MiscSolver()
    return solver.solve_misc(target)


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = run_misc(sys.argv[1])
        if result:
            print(f"\n{red('[🏆]')} Flag found: {green(result)}")
        else:
            print(f"{yellow('[-]')} No flag found")