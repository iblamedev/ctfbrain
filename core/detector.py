import os
import subprocess
import re
import sys
import time
import socket
import shlex
import base64
from core.dispatcher import dispatch
from core.colors import green, red, yellow, blue

# Universal flag pattern: ANY prefix{ANY content}
FLAG_PATTERN = r'[a-zA-Z0-9_]+\{[^}]*\}'

# Check for new modules
try:
    from modules.smb_enum import run_smb_enum
    SMB_AVAILABLE = True
except ImportError:
    SMB_AVAILABLE = False

try:
    from modules.wpscan_integration import run_wpscan
    WPSCAN_AVAILABLE = True
except ImportError:
    WPSCAN_AVAILABLE = False

try:
    from modules.privesc_auto import run_privesc_auto
    PRIVESC_AUTO_AVAILABLE = True
except ImportError:
    PRIVESC_AUTO_AVAILABLE = False

try:
    from modules.ghidra_analyzer import run_binary_analyzer
    GHIDRA_AVAILABLE = True
except ImportError:
    GHIDRA_AVAILABLE = False

try:
    from modules.password_cracker import run_password_cracker
    PASSWORD_CRACKER_AVAILABLE = True
except ImportError:
    PASSWORD_CRACKER_AVAILABLE = False

def run_cmd_safe(cmd):
    """Safe command execution with timeout"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10,
            check=False
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[TIMEOUT] Command execution timed out"
    except Exception as e:
        return f"[ERROR] {str(e)}"

def should_use_deep_mode(target):
    """Determine if deep mode should be used"""
    if isinstance(target, str):
        if target.startswith(('http://', 'https://')):
            if any(x in target for x in ['login', 'admin', 'api', 'graphql']):
                return True
        
        if os.path.exists(target):
            try:
                safe_target = shlex.quote(target)
                file_info = run_cmd_safe(f"file -b {safe_target}").lower()
                if any(x in file_info for x in ['archive', 'compressed', 'image', 'pdf', 'executable']):
                    return True
                # Directories often need deep searching
                if os.path.isdir(target):
                    return True
            except:
                pass
        
        ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
        domain_pattern = r"^[a-zA-Z0-9-]+\.[a-zA-Z]+$"
        if re.match(ip_pattern, target) or re.match(domain_pattern, target):
            return True
    
    return False

def should_use_persistent_mode(target):
    """Determine if persistent mode should be used"""
    interval = 15
    
    if isinstance(target, str):
        if target.startswith(('http://', 'https://')):
            if any(x in target for x in ['game', 'play', 'challenge', 'slow']):
                interval = 10
                return True, interval
        
        if ':' in target and not target.startswith('http'):
            parts = target.split(':')
            if len(parts) == 2 and parts[1].isdigit():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((parts[0], int(parts[1])))
                    sock.close()
                    if result == 0:
                        interval = 5
                        return True, interval
                except:
                    pass
        
        if 'picoctf.net' in target or 'ctfd' in target:
            interval = 15
            return True, interval
    
    return False, interval

def check_for_flag_in_output(output, source=""):
    """Check if output contains a flag pattern (any prefix{any text})"""
    if not isinstance(output, str):
        return False
    
    flags = re.findall(FLAG_PATTERN, output)
    for flag in flags:
        print(f"\n{red('[🏆 FLAG FOUND]')} {green(flag)} {red('[🏆]')}")
        if source:
            print(f"{yellow('[📍]')} Found in: {source}")
        return True
    
    base64_patterns = re.findall(r'[A-Za-z0-9+/=]{20,200}', output)
    for b64 in base64_patterns:
        try:
            padded = b64 + '=' * (-len(b64) % 4)
            decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
            flags = re.findall(FLAG_PATTERN, decoded)
            if flags:
                print(f"\n{red('[🏆 FLAG FOUND]')} {green(flags[0])} {red('[🏆]')}")
                print(f"{yellow('[📍]')} Found Base64 encoded in: {source}")
                return True
        except:
            pass
    
    return False

def extract_flag_from_output(output):
    """Extract flag from command output (any prefix{any text})"""
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

def is_likely_encoded(data):
    """Check if data looks like it might be encoded"""
    if not data or len(data) < 10:
        return False
    
    if re.match(r'^[A-Za-z0-9+/=]+$', data) and len(data) % 4 == 0:
        return True
    
    if re.match(r'^[0-9a-fA-F]+$', data) and len(data) % 2 == 0:
        return True
    
    if re.match(r'^[01\s]+$', data) and len(data.replace(' ', '').replace('\n', '')) % 8 == 0:
        return True
    
    if re.match(r'^(\d+\s+){3,}', data):
        return True
    
    if '%' in data and re.search(r'%[0-9A-Fa-f]{2}', data):
        return True
    
    return False

def detect_syntax_error(content):
    """Check if content looks like code with syntax errors"""
    if not isinstance(content, str):
        return False
    
    patterns = [
        (r'String::from\([^)]*\)(?![;\n])', 'rust'),
        (r'\bret\s*;', 'rust'),
        (r'println!\(\s*":\?"', 'rust'),
        (r'if\s+.*[^:]\s*$', 'python'),
        (r'def\s+\w+\(.*\)\s*[^:]\s*$', 'python'),
        (r'print\s+\w+', 'python'),
        (r'printf\s*\([^)]*\)(?![;\n])', 'c'),
        (r'cout\s*<<[^;]+$', 'cpp'),
        (r'System\.out\.println\s*\([^)]*\)(?![;\n])', 'java'),
    ]
    
    detected_langs = set()
    for pattern, lang in patterns:
        if re.search(pattern, content, re.MULTILINE):
            detected_langs.add(lang)
    
    return detected_langs

def detect(target, timeout=300):
    """Autonomous detection - routes to appropriate modules"""
    print(f"{green('[+]')} 🧠 Analyzing target: {target[:80]}")
    print(f"{blue('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}")
    
    # Handle directories specially
    if os.path.isdir(target):
        print(f"{green('[+]')} Directory detected - performing recursive search")
        try:
            from modules.forensics import search_directory_for_flags
            result = search_directory_for_flags(target)
            if result:
                return result
        except ImportError:
            # Fallback to simple find
            print(f"{yellow('[*]')} Using simple file search...")
            found_flags = []
            for root, dirs, files in os.walk(target):
                for file in files:
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', errors='ignore') as f:
                            content = f.read()
                            flag = extract_flag_from_output(content)
                            if flag:
                                print(f"{green('[+]')} Found flag in {filepath}")
                                found_flags.append(flag)
                    except:
                        pass
            if found_flags:
                return found_flags[0]
        return None
    
    # Check if target is a file and read it
    if os.path.isfile(target):
        try:
            with open(target, 'r', errors='ignore') as f:
                content = f.read().strip()
                if check_for_flag_in_output(content, "file content"):
                    return content
        except:
            pass

    # Raw crypto/encoded data (for strings, not files)
    if isinstance(target, str) and not os.path.exists(target) and is_likely_encoded(target):
        print(f"{green('[+]')} Treating input as encoded data - routing to Crypto.")
        result = dispatch("crypto", target)
        if check_for_flag_in_output(result, "crypto module"):
            return result

    # Syntax error detection (for code strings)
    if isinstance(target, str) and len(target) > 50 and not os.path.exists(target):
        detected_langs = detect_syntax_error(target)
        if detected_langs:
            lang = detected_langs.pop()
            print(f"{green('[+]')} Programming syntax error challenge detected! ({blue(lang.upper())})")
            
            try:
                from modules.syntax_fixer import fix_syntax
                result = fix_syntax(code=target, language=lang, run=True)
                if result and check_for_flag_in_output(str(result), "syntax fixer"):
                    return result
            except ImportError:
                pass

    # Manual commands
    if target == "pwn":
        try:
            from modules.binary import generate_pwn_template
            generate_pwn_template("binary")
        except ImportError:
            pass
        return

    if target == "script":
        print(f"{green('[+]')} Manual PrivEsc Trigger detected.")
        dispatch("privesc", target)
        return

    # Web URL
    if target.startswith(("http://", "https://")):
        print(f"{green('[+]')} Web URL detected.")
        
        if 'wordpress' in target.lower() or 'wp' in target.lower() or 'blog' in target.lower():
            print(f"{yellow('[*]')} Possible WordPress site detected")
            if WPSCAN_AVAILABLE:
                result = run_wpscan(target)
                if result and check_for_flag_in_output(result, "wpscan module"):
                    return result
        
        result = dispatch("web", target)
        if result and check_for_flag_in_output(result, "web module"):
            return result
        return None
    
    # Host:port (interactive/warmup)
    if ':' in target and not target.startswith('http'):
        parts = target.split(':')
        if len(parts) == 2 and parts[1].isdigit():
            host = parts[0]
            port = int(parts[1])
            
            if port in [139, 445]:
                print(f"{green('[+]')} SMB service detected on port {port}")
                if SMB_AVAILABLE:
                    result = run_smb_enum(host)
                    if result and check_for_flag_in_output(result, "smb module"):
                        return result
                else:
                    print(f"{yellow('[*]')} SMB module not available")
            
            print(f"{green('[+]')} Network service detected on port {port}.")
            try:
                from modules.warmup import run_warmup
                result = run_warmup(f"{host}:{port}")
                if result and check_for_flag_in_output(result, "warmup module"):
                    return result
            except ImportError:
                pass
            
            result = dispatch("network", target)
            if result and check_for_flag_in_output(result, "network module"):
                return result
            return None

    # ============ FILE ANALYSIS ============
    if os.path.isfile(target):
        try:
            safe_target = shlex.quote(target)
            file_info = run_cmd_safe(f"file -b {safe_target}").lower()
            file_size = os.path.getsize(target)
            print(f"{green('[+]')} File detected: {file_info} ({file_size} bytes)")
        except Exception:
            file_info = "unknown"
        
        # ============ PYTHON FILES - Check for password crackers FIRST ============
        if target.endswith('.py') or 'python' in file_info:
            print(f"{green('[+]')} 🐍 Python file detected - checking for password cracker")
            if PASSWORD_CRACKER_AVAILABLE:
                result = run_password_cracker(target)
                if result:
                    if check_for_flag_in_output(result, "password cracker"):
                        return result
                    return result
            # Fall back to syntax fixer if password cracker fails
            print(f"{yellow('[*]')} Trying syntax fixer as fallback...")
            try:
                from modules.syntax_fixer import fix_syntax
                result = fix_syntax(file_path=target, language='python', run=True)
                if result and check_for_flag_in_output(str(result), "syntax fixer"):
                    return result
            except ImportError:
                pass
            return None
        
        # ============ IMAGE FILES ============
        image_exts = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp']
        if any(target.lower().endswith(ext) for ext in image_exts) or 'image' in file_info:
            print(f"{green('[+]')} 🖼️ Image file detected - routing to Steganography.")
            try:
                from modules.stego import run_stego
                result = run_stego(target)
                if result:
                    if check_for_flag_in_output(result, "stego module"):
                        return result
                    return result
            except ImportError:
                print(f"{yellow('[*]')} Stego module not found")
            return None
        
        # ============ OTHER SOURCE CODE FILES ============
        source_exts = ['.rs', '.c', '.cpp', '.java', '.js', '.go', '.rb', '.php']
        if any(target.lower().endswith(ext) for ext in source_exts):
            print(f"{green('[+]')} Source code file detected - routing to Syntax Fixer.")
            try:
                from modules.syntax_fixer import fix_syntax
                result = fix_syntax(file_path=target, language=None, run=True)
                if result and check_for_flag_in_output(str(result), "syntax fixer"):
                    return result
            except ImportError:
                pass
            return None
        
        # ============ BINARY EXECUTABLES ============
        if ("elf" in file_info or "pe32" in file_info or "executable" in file_info) and "text" not in file_info:
            print(f"{green('[+]')} Binary executable detected.")
            
            if GHIDRA_AVAILABLE:
                result = run_binary_analyzer(target)
                if result and check_for_flag_in_output(result, "ghidra analyzer"):
                    return result
            
            try:
                from modules.reverse import run_reverse
                result = run_reverse(target)
                if result and check_for_flag_in_output(result, "reverse module"):
                    return result
            except ImportError:
                pass
            
            result = dispatch("binary", target)
            if result and check_for_flag_in_output(result, "binary module"):
                return result
            return None
        
        # ============ FORENSICS ARTIFACTS ============
        if any(x in file_info for x in ["archive", "compressed", "capture", "pcap", "pdf", "filesystem", "audio", "wave", "mp3", "wav"]):
            print(f"{green('[+]')} Forensics artifact detected - routing to Forensics.")
            result = dispatch("forensics", target)
            if result and check_for_flag_in_output(result, "forensics module"):
                return result
            return None
        
        # ============ TEXT FILES ============
        if "text" in file_info:
            print(f"{green('[+]')} Text file detected - routing to Crypto/Misc.")
            result = dispatch("crypto", target)
            if result and check_for_flag_in_output(result, "crypto module"):
                return result
            print(f"{yellow('[*]')} No flag found in text file.")
            return None
        
        # ============ GIT REPOSITORY ============
        if os.path.isdir(target) and os.path.isdir(os.path.join(target, '.git')):
            print(f"{green('[+]')} Git repository detected - routing to Git module.")
            try:
                from modules.git import run_git
                result = run_git(target)
                if result and check_for_flag_in_output(result, "git module"):
                    return result
            except ImportError:
                print(f"{yellow('[*]')} Git module not found")
            return None
        
        # ============ UNKNOWN FILE TYPE ============
        print(f"{yellow('[?]')} Unknown file type - trying crypto...")
        result = dispatch("crypto", target)
        if result and check_for_flag_in_output(result, "crypto module"):
            return result
        return None

    # Network target (IP/domain)
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    domain_pattern = r"^[a-zA-Z0-9-]+\.[a-zA-Z]+$"

    if re.match(ip_pattern, target) or re.match(domain_pattern, target):
        print(f"{green('[+]')} Network Target detected.")
        result = dispatch("network", target)
        if check_for_flag_in_output(result, "network module"):
            return result
        
        # Try OSINT for domains
        if re.match(domain_pattern, target):
            try:
                from modules.osint import run_osint
                result = run_osint(target)
                if result and check_for_flag_in_output(result, "osint module"):
                    return result
            except ImportError:
                pass
        return None

    # Cloud endpoints
    if "s3.amazonaws.com" in target or "blob.core.windows.net" in target:
        print(f"{green('[+]')} Cloud Endpoint detected.")
        result = dispatch("cloud", target)
        if check_for_flag_in_output(result, "cloud module"):
            return result
        return None

    # Final fallback
    print(f"{green('[+]')} Treating input as encoded data.")
    try:
        from modules.misc import run_misc
        result = run_misc(target)
        if result and check_for_flag_in_output(result, "misc module"):
            return result
    except ImportError:
        pass
    
    result = dispatch("crypto", target)
    if check_for_flag_in_output(result, "crypto module"):
        return result
    
    return None