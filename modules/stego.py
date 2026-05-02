#!/usr/bin/env python3
"""
Steganography Module for CTF
Handles: Image stego (LSB, zsteg, steghide), metadata analysis, Base64 decoding
"""
import os
import re
import subprocess
import base64
import tempfile
from PIL import Image
from core.colors import red, green, yellow, blue, highlight
from core.tools import check_tool

FLAG_PATTERN = r'[a-zA-Z0-9_]+\{[^}]*\}'

class StegoSolver:
    def __init__(self):
        self.found_flags = []
    
    def extract_flag(self, text):
        if not text:
            return None
        flags = re.findall(FLAG_PATTERN, str(text))
        if flags:
            return flags[0]
        return None
    
    def decode_base64_from_text(self, text):
        """Extract and decode Base64 strings from text"""
        if not text:
            return None
        
        base64_patterns = re.findall(r'[A-Za-z0-9+/=]{20,200}', text)
        for b64 in base64_patterns:
            try:
                padded = b64 + '=' * (-len(b64) % 4)
                decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
                flag = self.extract_flag(decoded)
                if flag:
                    print(f"{green('[+]')} Found Base64 encoded flag!")
                    return flag
            except:
                pass
        return None
    
    def check_exiftool(self, filepath):
        """Check metadata with exiftool"""
        if not check_tool("exiftool"):
            print(f"{yellow('[*]')} exiftool not installed")
            return None
        
        print(f"{green('[+]')} Running exiftool...")
        result = subprocess.getoutput(f"exiftool {filepath}")
        print(result[:500])
        
        # Check for Base64 in metadata
        flag = self.decode_base64_from_text(result)
        if flag:
            return flag
        
        flag = self.extract_flag(result)
        if flag:
            return flag
        return None
    
    def check_strings(self, filepath):
        """Check strings in file"""
        if not check_tool("strings"):
            return None
        
        print(f"{green('[+]')} Running strings...")
        result = subprocess.getoutput(f"strings {filepath}")
        
        # Check for Base64 in strings
        flag = self.decode_base64_from_text(result)
        if flag:
            return flag
        
        flag = self.extract_flag(result)
        if flag:
            return flag
        return None
    
    def check_zsteg(self, filepath):
        """Check PNG with zsteg"""
        if not filepath.lower().endswith('.png'):
            return None
        if not check_tool("zsteg"):
            return None
        
        print(f"{green('[+]')} Running zsteg...")
        result = subprocess.getoutput(f"zsteg -a {filepath}")
        print(result[:500])
        
        flag = self.decode_base64_from_text(result)
        if flag:
            return flag
        
        flag = self.extract_flag(result)
        if flag:
            return flag
        return None
    
    def check_steghide(self, filepath):
        """Check with steghide (empty password)"""
        if not check_tool("steghide"):
            return None
        
        print(f"{green('[+]')} Trying steghide with empty password...")
        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.getoutput(
                f"steghide extract -sf {filepath} -p '' -xf {tmpdir}/extracted 2>&1"
            )
            
            if "wrote extracted data" in result:
                print(f"{green('[+]')} Steghide extraction successful!")
                extracted = f"{tmpdir}/extracted"
                if os.path.exists(extracted):
                    with open(extracted, 'r', errors='ignore') as f:
                        content = f.read()
                        flag = self.decode_base64_from_text(content)
                        if flag:
                            return flag
                        flag = self.extract_flag(content)
                        if flag:
                            return flag
            
            flag = self.decode_base64_from_text(result)
            if flag:
                return flag
            
            flag = self.extract_flag(result)
            if flag:
                return flag
        return None
    
    def check_stegseek(self, filepath):
        """Check with stegseek (bruteforce)"""
        if not check_tool("stegseek"):
            return None
        
        print(f"{green('[+]')} Trying stegseek with rockyou...")
        result = subprocess.getoutput(
            f"stegseek {filepath} /usr/share/wordlists/rockyou.txt -sf /dev/stdout -t 10 2>/dev/null"
        )
        
        flag = self.decode_base64_from_text(result)
        if flag:
            return flag
        
        flag = self.extract_flag(result)
        if flag:
            return flag
        return None
    
    def check_binwalk(self, filepath):
        """Check for embedded files"""
        if not check_tool("binwalk"):
            return None
        
        print(f"{green('[+]')} Running binwalk...")
        result = subprocess.getoutput(f"binwalk {filepath}")
        print(result)
        
        flag = self.decode_base64_from_text(result)
        if flag:
            return flag
        
        flag = self.extract_flag(result)
        if flag:
            return flag
        
        if "ZIP" in result or "RAR" in result or "7-zip" in result:
            extract_dir = f"extracted_{os.path.basename(filepath)}"
            print(f"{green('[+]')} Extracting to {extract_dir}...")
            os.makedirs(extract_dir, exist_ok=True)
            subprocess.run(f"binwalk -e {filepath} -C {extract_dir}", shell=True)
            
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', errors='ignore') as f:
                            content = f.read()
                            flag = self.decode_base64_from_text(content)
                            if flag:
                                return flag
                            flag = self.extract_flag(content)
                            if flag:
                                return flag
                    except:
                        pass
        return None
    
    def solve_image(self, filepath):
        """Solve image steganography"""
        print(f"{green('[+]')} Analyzing image: {filepath}")
        
        methods = [
            ('exiftool', self.check_exiftool),
            ('strings', self.check_strings),
            ('zsteg', self.check_zsteg),
            ('steghide', self.check_steghide),
            ('binwalk', self.check_binwalk),
            ('stegseek', self.check_stegseek)
        ]
        
        for name, method in methods:
            print(f"{yellow('[*]')} Trying {name}...")
            result = method(filepath)
            if result:
                return result
        
        return None


def run_stego(filepath):
    """Main steganography solver"""
    solver = StegoSolver()
    
    if not os.path.exists(filepath):
        print(f"{red('[-]')} File not found: {filepath}")
        return None
    
    return solver.solve_image(filepath)


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = run_stego(sys.argv[1])
        if result:
            print(f"\n{red('[🏆]')} Flag found: {green(result)}")
        else:
            print(f"{yellow('[-]')} No flag found")