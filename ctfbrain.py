#!/usr/bin/env python3
"""
ctfbrain - Autonomous CTF Challenge Solver
Main entry point - ONLY calls detector.py
"""
import sys
import os
import argparse
import time
import re
import base64
import subprocess
import shlex

# Fix path resolution - use script directory, not cwd
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(script_dir)

from core.detector import detect, should_use_deep_mode, should_use_persistent_mode
from core.colors import red, green, yellow, blue, banner_logo
from core.tools import verify_essential_tools, check_compiler
from core.session_manager import list_sessions, cleanup_sessions

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

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='ctfbrain - Autonomous CTF Challenge Solver',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ctfbrain 10.10.11.23                    Network scan + auto-exploit
  ctfbrain http://site.com                 Web recon + auto-cookie + dirbust
  ctfbrain challenge.jpg                   Forensics + auto-extract
  ctfbrain 5f4dcc3b5...                    Auto-detect hash type + crack
  ctfbrain ./program                        Binary analysis + auto-pwn
  ctfbrain broken.rs -r                     Auto-fix + compile + run
  ctfbrain secret.txt                       Auto-detect encoding (base64, hex, etc)
  
  SMB ENUMERATION:
    ctfbrain 10.10.11.23 --smb              Enumerate SMB shares
    
  WORDPRESS SCANNER:
    ctfbrain http://site.com --wpscan       Auto WordPress enumeration
    
  PRIVILEGE ESCALATION:
    ctfbrain --privesc                       Auto privilege escalation on local system
    ctfbrain user@host --privesc              Remote privilege escalation via SSH
    
  SESSION MANAGEMENT:
    ctfbrain --list-sessions                 List active sessions
    ctfbrain --cleanup                        Clean up all sessions
    
  BINARY ANALYSIS:
    ctfbrain ./binary --ghidra               Deep binary analysis with Ghidra
        """
    )
    
    parser.add_argument(
        'target', 
        nargs='?', 
        help='Target (IP, URL, file, hash, host:port, or source code)'
    )
    
    parser.add_argument(
        '-l', '--language',
        help='Force language for syntax fixing'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file for fixed code'
    )
    
    parser.add_argument(
        '-r', '--run',
        action='store_true',
        help='Compile and run after fixing syntax'
    )
    
    parser.add_argument(
        '--force-deep',
        action='store_true',
        help='Force deep mode (try ALL modules)'
    )
    
    parser.add_argument(
        '--force-persist',
        type=int,
        metavar='SECONDS',
        help='Force persistent mode with custom interval'
    )
    
    parser.add_argument(
        '--ssh',
        nargs=3,
        metavar=('HOST:PORT', 'USERNAME', 'PASSWORD'),
        help='SSH explorer mode: --ssh <host:port> <username> <password>'
    )
    
    parser.add_argument(
        '--smb',
        action='store_true',
        help='SMB enumeration mode'
    )
    
    parser.add_argument(
        '--wpscan',
        action='store_true',
        help='WordPress scanner mode'
    )
    
    parser.add_argument(
        '--privesc',
        action='store_true',
        help='Automatic privilege escalation mode'
    )
    
    parser.add_argument(
        '--ghidra',
        action='store_true',
        help='Deep binary analysis with Ghidra'
    )
    
    parser.add_argument(
        '--list-sessions',
        action='store_true',
        help='List all active sessions'
    )
    
    parser.add_argument(
        '--cleanup',
        action='store_true',
        help='Clean up all sessions and listeners'
    )
    
    parser.add_argument(
        '--warmup',
        action='store_true',
        help='Warmup mode for netcat/math/python challenges'
    )
    
    parser.add_argument(
        '--stego',
        action='store_true',
        help='Steganography mode for image analysis'
    )
    
    parser.add_argument(
        '--osint',
        action='store_true',
        help='OSINT mode for domain/username reconnaissance'
    )
    
    parser.add_argument(
        '--reverse',
        action='store_true',
        help='Reverse engineering mode for binaries'
    )
    
    parser.add_argument(
        '--misc',
        action='store_true',
        help='Misc mode for encoding/decoding challenges'
    )
    
    parser.add_argument(
        '--username',
        help='Username for SSH/Warmup challenges'
    )
    
    parser.add_argument(
        '--password',
        help='Password for SSH/Warmup challenges'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=300,
        help='Timeout in seconds for each module (default: 300)'
    )
    
    parser.add_argument(
        '--max-attempts',
        type=int,
        default=10,
        help='Maximum persistent attempts (default: 10)'
    )
    
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress banner and verbose output'
    )
    
    parser.add_argument(
        '--no-verify',
        action='store_true',
        help='Skip tool verification'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='ctfbrain v5.0 - ULTIMATE CTF SOLVER'
    )
    
    return parser.parse_args()

def show_banner():
    """Display the ctfbrain banner"""
    print(banner_logo)
    print(f"{blue('════════════════════════════════════════════')}")
    print(f"{green('🚀 ctfbrain v5.0 - ULTIMATE CTF SOLVER')}")
    print(f"{blue('════════════════════════════════════════════')}\n")

def ssh_explorer_mode(host_port, username, password):
    """Run SSH explorer mode"""
    print(f"\n{blue('='*60)}")
    print(f"{green('🔐 SSH EXPLORER MODE ACTIVATED')}")
    print(f"{blue('='*60)}\n")
    print(f"{green('[+]')} Connecting to {host_port} as {username}...")
    
    try:
        from modules.warmup import run_warmup
        result = run_warmup(host_port, username=username, password=password, mode='ssh')
        if result:
            print(f"\n{red('[🏆]')} FLAG FOUND: {green(result)}")
        return result
    except ImportError:
        print(f"{red('[-]')} Warmup module not found!")
        return None

def smb_enum_mode(target):
    """Run SMB enumeration mode"""
    print(f"\n{blue('='*60)}")
    print(f"{green('📁 SMB ENUMERATION MODE ACTIVATED')}")
    print(f"{blue('='*60)}\n")
    
    try:
        from modules.smb_enum import run_smb_enum
        result = run_smb_enum(target)
        if result:
            print(f"\n{red('[🏆]')} FLAG FOUND: {green(result)}")
        return result
    except ImportError:
        print(f"{red('[-]')} SMB enumeration module not found!")
        return None

def wpscan_mode(target):
    """Run WordPress scanner mode"""
    print(f"\n{blue('='*60)}")
    print(f"{green('🔐 WORDPRESS SCANNER MODE ACTIVATED')}")
    print(f"{blue('='*60)}\n")
    
    try:
        from modules.wpscan_integration import run_wpscan
        result = run_wpscan(target)
        if result:
            print(f"\n{red('[🏆]')} RESULT: {green(result)}")
        return result
    except ImportError:
        print(f"{red('[-]')} WordPress scanner module not found!")
        return None

def privesc_mode(target=None):
    """Run privilege escalation mode"""
    print(f"\n{blue('='*60)}")
    print(f"{green('👑 PRIVILEGE ESCALATION MODE ACTIVATED')}")
    print(f"{blue('='*60)}\n")
    
    try:
        from modules.privesc_auto import run_privesc_auto
        result = run_privesc_auto(target)
        if result:
            print(f"\n{red('[🏆]')} FLAG FOUND: {green(result)}")
        return result
    except ImportError:
        print(f"{red('[-]')} Privilege escalation module not found!")
        return None

def ghidra_mode(target):
    """Run Ghidra binary analysis mode"""
    print(f"\n{blue('='*60)}")
    print(f"{green('🔧 GHIDRA BINARY ANALYSIS MODE ACTIVATED')}")
    print(f"{blue('='*60)}\n")
    
    try:
        from modules.ghidra_analyzer import run_binary_analyzer
        result = run_binary_analyzer(target)
        if result:
            print(f"\n{red('[🏆]')} RESULT: {green(result)}")
        return result
    except ImportError:
        print(f"{red('[-]')} Ghidra analyzer module not found!")
        return None

def warmup_mode(target, username=None, password=None):
    """Run warmup mode for netcat/math/python challenges"""
    print(f"\n{blue('='*60)}")
    print(f"{green('🔥 WARMUP CHALLENGE MODE ACTIVATED')}")
    print(f"{blue('='*60)}\n")
    
    try:
        from modules.warmup import run_warmup
        result = run_warmup(target, username=username, password=password)
        if result:
            print(f"\n{red('[🏆]')} FLAG FOUND: {green(result)}")
        return result
    except ImportError:
        print(f"{red('[-]')} Warmup module not found!")
        return None

def stego_mode(filepath):
    """Run steganography mode"""
    print(f"\n{blue('='*60)}")
    print(f"{green('🕵️ STEGANOGRAPHY MODE ACTIVATED')}")
    print(f"{blue('='*60)}\n")
    
    try:
        from modules.stego import run_stego
        result = run_stego(filepath)
        if result:
            print(f"\n{red('[🏆]')} FLAG FOUND: {green(result)}")
        return result
    except ImportError:
        print(f"{red('[-]')} Stego module not found!")
        return None

def osint_mode(target):
    """Run OSINT mode"""
    print(f"\n{blue('='*60)}")
    print(f"{green('🌐 OSINT MODE ACTIVATED')}")
    print(f"{blue('='*60)}\n")
    
    try:
        from modules.osint import run_osint
        result = run_osint(target)
        if result:
            print(f"\n{red('[🏆]')} FLAG FOUND: {green(result)}")
        return result
    except ImportError:
        print(f"{red('[-]')} OSINT module not found!")
        return None

def reverse_mode(filepath):
    """Run reverse engineering mode"""
    print(f"\n{blue('='*60)}")
    print(f"{green('🔧 REVERSE ENGINEERING MODE ACTIVATED')}")
    print(f"{blue('='*60)}\n")
    
    try:
        from modules.reverse import run_reverse
        result = run_reverse(filepath)
        if result:
            print(f"\n{red('[🏆]')} FLAG FOUND: {green(result)}")
        return result
    except ImportError:
        print(f"{red('[-]')} Reverse module not found!")
        return None

def misc_mode(target):
    """Run misc mode for encoding/decoding"""
    print(f"\n{blue('='*60)}")
    print(f"{green('🎲 MISC/ENCODING MODE ACTIVATED')}")
    print(f"{blue('='*60)}\n")
    
    try:
        from modules.misc import run_misc
        result = run_misc(target)
        if result:
            print(f"\n{red('[🏆]')} FLAG FOUND: {green(result)}")
        return result
    except ImportError:
        print(f"{red('[-]')} Misc module not found!")
        return None

def intelligent_mode(target, args):
    """Let ctfbrain decide the best approach"""
    
    print(f"{green('[+]')} 🧠 Analyzing target to choose best strategy...")
    
    # First, try normal detection
    result = detect(target, timeout=args.timeout)
    
    # Check if we got a flag
    if result:
        if isinstance(result, str):
            flags = re.findall(r'[a-zA-Z0-9_]+\{[^}]*\}', result)
            if flags:
                print(f"\n{red('[🏆 FLAG FOUND]')} {green(flags[0])}")
                return flags[0]
    
    # If no flag found, decide what to do next
    file_is_text = False
    if os.path.exists(target):
        try:
            safe_target = shlex.quote(target)
            file_info = run_cmd_safe(f"file -b {safe_target}").lower()
            if 'text' in file_info:
                file_is_text = True
        except:
            pass
    
    if file_is_text and not args.force_deep:
        print(f"{yellow('[*]')} No flag found in text file. Try manual inspection.")
        return None
    
    use_deep = should_use_deep_mode(target)
    use_persistent, interval = should_use_persistent_mode(target)
    
    if use_persistent and not args.force_deep:
        print(f"\n{yellow('[!]')} No flag found in initial scan.")
        print(f"{green('[+]')} Target appears to be a LIVE service that may need time.")
        print(f"{green('[+]')} Switching to PERSISTENT mode (interval: {interval}s)")
        return run_persistent_mode(target, interval, args.max_attempts, args.timeout)
    
    elif (use_deep or args.force_deep) and not file_is_text:
        print(f"\n{yellow('[!]')} No flag found in initial scan.")
        print(f"{green('[+]')} Target appears complex - switching to DEEP mode")
        return run_deep_mode(target, args.timeout)
    
    else:
        print(f"\n{yellow('[!]')} No flag found and no further strategies suggested.")
        return None

def run_deep_mode(target, timeout):
    """Run deep mode - try ALL modules"""
    print(f"\n{blue('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}")
    print(f"{green('[🔍]')} DEEP MODE ACTIVATED")
    print(f"{blue('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}")
    
    modules = [
        ('crypto', '🔐 Crypto Analysis'),
        ('web', '🌐 Web Recon'),
        ('binary', '💻 Binary Analysis'),
        ('forensics', '🔎 Forensics'),
        ('network', '📡 Network Scan'),
        ('cloud', '☁️ Cloud Recon'),
        ('privesc', '👑 Privilege Escalation'),
        ('warmup', '🔥 Warmup'),
        ('stego', '🕵️ Steganography'),
        ('reverse', '🔧 Reverse Engineering'),
        ('osint', '🌐 OSINT'),
        ('misc', '🎲 Misc/Encoding'),
        ('smb', '📁 SMB Enumeration'),
        ('wpscan', '🔐 WordPress Scanner'),
        ('ghidra', '🔧 Ghidra Analysis')
    ]
    
    for module_name, module_desc in modules:
        print(f"\n{yellow('[🔄]')} Trying {module_desc} module...")
        try:
            from core.dispatcher import dispatch
            result = dispatch(module_name, target)
            
            if result and isinstance(result, str):
                flags = re.findall(r'[a-zA-Z0-9_]+\{[^}]*\}', result)
                if flags:
                    print(f"\n{red('[🏆]')} FLAG FOUND in {module_desc}!")
                    return flags[0]
        except Exception as e:
            print(f"{yellow('[!]')} {module_desc} module error: {e}")
            continue
    
    print(f"\n{red('[-]')} No flag found in any module after deep scan.")
    return None

def run_persistent_mode(target, interval, max_attempts, timeout):
    """Run persistent mode - keep trying"""
    print(f"\n{blue('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}")
    print(f"{green('[🔄]')} PERSISTENT MODE ACTIVATED")
    print(f"{blue('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}")
    print(f"{green('[+]')} Retrying every {interval} seconds (max {max_attempts} attempts)")
    print(f"{yellow('[!]')} Press Ctrl+C to stop\n")
    
    attempt = 1
    while attempt <= max_attempts:
        print(f"{blue('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}")
        print(f"{green('[+]')} Attempt #{attempt}")
        print(f"{blue('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}")
        
        try:
            result = detect(target, timeout=timeout)
            
            if result and isinstance(result, str):
                flags = re.findall(r'[a-zA-Z0-9_]+\{[^}]*\}', result)
                if flags:
                    print(f"\n{red('[🏆]')} FLAG FOUND on attempt #{attempt}!")
                    return flags[0]
        except KeyboardInterrupt:
            print(f"\n{yellow('[!]')} Stopped by user")
            break
        except Exception as e:
            print(f"{yellow('[!]')} Error on attempt #{attempt}: {e}")
        
        if attempt < max_attempts:
            print(f"\n{yellow('[+]')} Waiting {interval} seconds before next attempt...")
            time.sleep(interval)
        
        attempt += 1
    
    print(f"\n{red('[-]')} No flag found after {max_attempts} attempts.")
    return None

def main():
    """Main entry point"""
    args = parse_arguments()
    
    if not args.quiet:
        show_banner()
    
    if not args.no_verify:
        verify_essential_tools()
    
    # ============ SESSION MANAGEMENT ============
    if args.list_sessions:
        list_sessions()
        return
    
    if args.cleanup:
        cleanup_sessions()
        print(f"{green('[+]')} All sessions cleaned up")
        return
    
    # ============ SPECIFIC MODES ============
    
    # SSH Explorer Mode
    if args.ssh:
        host_port, username, password = args.ssh
        ssh_explorer_mode(host_port, username, password)
        return
    
    # SMB Enumeration Mode
    if args.smb and args.target:
        smb_enum_mode(args.target)
        return
    
    # WordPress Scanner Mode
    if args.wpscan and args.target:
        wpscan_mode(args.target)
        return
    
    # Privilege Escalation Mode
    if args.privesc:
        privesc_mode(args.target)
        return
    
    # Ghidra Analysis Mode
    if args.ghidra and args.target:
        ghidra_mode(args.target)
        return
    
    # Warmup Mode
    if args.warmup and args.target:
        warmup_mode(args.target, args.username, args.password)
        return
    
    # Stego Mode
    if args.stego and args.target:
        stego_mode(args.target)
        return
    
    # OSINT Mode
    if args.osint and args.target:
        osint_mode(args.target)
        return
    
    # Reverse Mode
    if args.reverse and args.target:
        reverse_mode(args.target)
        return
    
    # Misc Mode
    if args.misc and args.target:
        misc_mode(args.target)
        return
    
    # ============ STDIN SUPPORT ============
    
    if args.target is None:
        if not sys.stdin.isatty():
            data = sys.stdin.read().strip()
            if data:
                try:
                    if args.language:
                        print(f"{green('[+]')} Pipe mode with language: {blue(args.language)}")
                        try:
                            from modules.syntax_fixer import fix_syntax
                            fix_syntax(
                                code=data, 
                                language=args.language, 
                                run=args.run,
                                output=args.output
                            )
                        except ImportError:
                            print(f"{red('[-]')} Syntax fixer module not found")
                    else:
                        # Auto-detect from stdin
                        if args.misc:
                            misc_mode(data)
                        else:
                            intelligent_mode(data, args)
                except KeyboardInterrupt:
                    print(f"\n{red('[!]')} Operation interrupted by user.")
                except Exception as e:
                    print(f"\n{red('[!]')} Critical Error: {e}")
                return

        print(f"{red('[-]')} No target specified and no input piped.")
        print(f"{yellow('[!]')} Use -h for help or see examples below:\n")
        print(f"  ctfbrain 10.10.11.23")
        print(f"  ctfbrain http://example.com")
        print(f"  ctfbrain challenge.jpg")
        print(f"  ctfbrain --ssh wily-courier.picoctf.net:55295 ctf-player 8c606eb1")
        print(f"  ctfbrain 10.10.11.23 --smb")
        print(f"  ctfbrain http://site.com --wpscan")
        print(f"  ctfbrain --privesc")
        sys.exit(1)

    target = args.target

    # ============ FILE EXTENSION DETECTION ============
    
    if os.path.isfile(target):
        ext = os.path.splitext(target)[1].lower()
        
        # Source code files
        lang_map = {
            '.rs': 'rust', '.py': 'python', '.c': 'c', '.cpp': 'cpp', 
            '.cc': 'cpp', '.java': 'java', '.js': 'javascript', 
            '.go': 'go', '.rb': 'ruby', '.php': 'php', '.pl': 'perl',
            '.swift': 'swift', '.kt': 'kotlin', '.zig': 'zig',
            '.hs': 'haskell', '.exs': 'elixir', '.ex': 'elixir'
        }
        
        # Image files - auto-route to stego
        image_exts = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp']
        
        # Binary files - auto-route to reverse/ghidra
        binary_exts = ['.elf', '.exe', '.bin', '.o', '.out', '.so']
        
        if ext in lang_map:
            detected_lang = lang_map[ext]
            print(f"{green('[+]')} Source file detected: {blue(detected_lang.upper())}")
            
            if args.run:
                try:
                    from modules.syntax_fixer import fix_syntax
                    fix_syntax(
                        file_path=target,
                        language=args.language or detected_lang,
                        run=args.run,
                        output=args.output
                    )
                    
                    if args.output is None and args.run:
                        default_output = f"{target}.fixed"
                        print(f"{yellow('[!]')} No output file specified, using: {blue(default_output)}")
                    
                    return
                    
                except ImportError:
                    print(f"{yellow('[!]')} Syntax fixer module not found, falling back to detector...")
                except Exception as e:
                    print(f"{red('[-]')} Error fixing syntax: {e}")
                    print(f"{yellow('[!]')} Falling back to intelligent mode...")
        
        elif ext in image_exts or args.stego:
            stego_mode(target)
            return
            
        elif ext in binary_exts or args.reverse or args.ghidra:
            if args.ghidra:
                ghidra_mode(target)
            else:
                reverse_mode(target)
            return

    # ============ INTELLIGENT MODE ============
    
    try:
        result = intelligent_mode(target, args)
        
        if result:
            if isinstance(result, str):
                flags = re.findall(r'[a-zA-Z0-9_]+\{[^}]*\}', result)
                if flags:
                    print(f"\n{red('[🏆 FLAG FOUND]')} {green(flags[0])}")
                else:
                    print(f"\n{red('[🏆]')} Result: {green(result)}")
    except KeyboardInterrupt:
        print(f"\n{red('[!]')} Operation interrupted by user.")
    except Exception as e:
        print(f"\n{red('[!]')} Critical Error: {e}")

if __name__ == "__main__":
    main()