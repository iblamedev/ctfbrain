#!/usr/bin/env python3
"""
Password Cracker Module for CTF
Handles: Hardcoded passwords, XOR encryption, basic reverse engineering
"""
import os
import re
import subprocess
import base64
from core.colors import red, green, yellow, blue, highlight

# Module availability flag
PASSWORD_CRACKER_AVAILABLE = True

FLAG_PATTERN = r'[a-zA-Z0-9_]+\{[^}]*\}'

class PasswordCracker:
    def __init__(self, target):
        self.target = target
        self.target_dir = os.path.dirname(os.path.abspath(target))
        self.found_flags = []
    
    def extract_flag(self, text):
        if not text:
            return None
        flags = re.findall(FLAG_PATTERN, str(text))
        if flags:
            return flags[0]
        return None
    
    def find_encrypted_file(self, script_content):
        """Find encrypted file name from script content"""
        enc_pattern = r"open\(['\"]([^'\"]+\.enc)['\"]"
        enc_match = re.search(enc_pattern, script_content)
        if enc_match:
            enc_file = enc_match.group(1)
            # Check if file exists in same directory
            full_path = os.path.join(self.target_dir, enc_file)
            if os.path.exists(full_path):
                return full_path
        return None
    
    def manual_xor_decrypt(self, enc_file, password):
        """Manually decrypt using XOR without running the script"""
        try:
            with open(enc_file, 'rb') as f:
                enc_data = f.read()
            
            # Try to decode as string
            try:
                enc_str = enc_data.decode('utf-8')
            except:
                enc_str = enc_data.decode('latin-1')
            
            # XOR decryption
            key = password
            new_key = key
            i = 0
            while len(new_key) < len(enc_str):
                new_key = new_key + key[i]
                i = (i + 1) % len(key)
            
            decrypted = ''.join([chr(ord(enc_str[j]) ^ ord(new_key[j])) for j in range(len(enc_str))])
            
            flag = self.extract_flag(decrypted)
            if flag:
                print(f"{green('[+]')} Successfully decrypted with password '{password}'")
                return flag
        except Exception as e:
            print(f"{yellow('[*]')} XOR decryption failed: {e}")
        return None
    
    def analyze_python_file(self, filepath):
        """Analyze Python file for hardcoded passwords and XOR functions"""
        print(f"{green('[+]')} Analyzing Python file: {filepath}")
        
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            
            # Look for password comparison patterns
            password_patterns = [
                r'user_pw\s*==\s*["\']([^"\']+)["\']',
                r'password\s*==\s*["\']([^"\']+)["\']',
                r'input.*==\s*["\']([^"\']+)["\']',
                r'if.*==\s*["\']([^"\']+)["\']',
                r'pw\s*=\s*["\']([^"\']+)["\']',
                r'key\s*=\s*["\']([^"\']+)["\']'
            ]
            
            passwords = []
            for pattern in password_patterns:
                matches = re.findall(pattern, content)
                passwords.extend(matches)
            
            if passwords:
                print(f"{green('[+]')} Found potential passwords: {passwords}")
                
                # Find encrypted file
                enc_file = self.find_encrypted_file(content)
                if enc_file:
                    print(f"{green('[+]')} Found encrypted file: {enc_file}")
                    
                    # Try each password with manual XOR decryption
                    for password in passwords:
                        result = self.manual_xor_decrypt(enc_file, password)
                        if result:
                            return result
                else:
                    print(f"{yellow('[*]')} No encrypted file found in same directory")
            
            return None
            
        except Exception as e:
            print(f"{yellow('[*]')} Error analyzing Python file: {e}")
            return None
    
    def analyze_binary(self, filepath):
        """Analyze binary for strings that might be passwords"""
        print(f"{green('[+]')} Analyzing binary: {filepath}")
        
        # Extract strings
        strings_output = subprocess.getoutput(f"strings {filepath}")
        
        # Look for password-like strings (4-8 chars, alphanumeric)
        password_candidates = re.findall(r'\b[a-zA-Z0-9]{4,8}\b', strings_output)
        
        # Also look for hex strings
        hex_candidates = re.findall(r'\b[0-9a-fA-F]{4,8}\b', strings_output)
        
        all_candidates = list(set(password_candidates + hex_candidates))
        
        if all_candidates:
            print(f"{green('[+]')} Found {len(all_candidates)} password candidates")
            return all_candidates[0] if all_candidates else None
        
        return None
    
    def solve(self):
        """Main password cracking function"""
        print(f"{green('[+]')} 🔍 Starting password cracker on: {self.target}")
        
        if not os.path.exists(self.target):
            print(f"{red('[-]')} File not found")
            return None
        
        # Check file type
        file_type = subprocess.getoutput(f"file -b {self.target}")
        
        if 'Python' in file_type or self.target.endswith('.py'):
            return self.analyze_python_file(self.target)
        elif 'ELF' in file_type or 'executable' in file_type:
            return self.analyze_binary(self.target)
        elif self.target.endswith('.enc'):
            # If it's an encrypted file, look for the Python script
            py_file = self.target.replace('.enc', '.py')
            if os.path.exists(py_file):
                return self.analyze_python_file(py_file)
        
        return None


def run_password_cracker(target):
    """Main password cracker entry point"""
    cracker = PasswordCracker(target)
    return cracker.solve()


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = run_password_cracker(sys.argv[1])
        if result:
            print(f"\n{red('[🏆]')} Flag found: {green(result)}")
        else:
            print(f"{yellow('[-]')} No password found")