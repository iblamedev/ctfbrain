#!/usr/bin/env python3
"""
Interactive narrative & shell handler for ctfbrain.
Auto-plays interactive fiction, menu choices, and basic shells.
"""
import sys
import re
import time
from pwn import *
from core.colors import red, green, yellow, blue, highlight

FLAG_PATTERN = r'[a-zA-Z0-9_]+\{[^}]*\}'

class InteractiveSolver:
    def __init__(self, host=None, port=None):
        self.host = host
        self.port = port
        self.io = None
    
    def connect(self):
        print(f"{green('[+]')} Connecting to {self.host}:{self.port}...")
        self.io = remote(self.host, self.port)
        return True
    
    def check_for_flag(self, data):
        if not data:
            return False
        flags = re.findall(FLAG_PATTERN, data)
        for flag in flags:
            print(f"\n{red('[🏆 FLAG FOUND]')} {highlight(flag)}\n")
            return True
        return False
    
    def auto_press_enter(self):
        while True:
            try:
                line = self.io.recvline(timeout=1).decode(errors='ignore')
                print(f"  {line.strip()}")
                
                if self.check_for_flag(line):
                    return True
                
                if 'Press Enter' in line or '---' in line:
                    print(f"{yellow('  [↩]')} Sending Enter...")
                    self.io.sendline(b'')
                    time.sleep(0.3)
                    
            except EOFError:
                print(f"{red('[!] Connection closed')}")
                break
            except:
                break
        return False
    
    def solve_menu(self):
        print(f"{green('[+]')} Interactive Menu Detection Active")
        
        while True:
            try:
                data = self.io.recvuntil(b'> ', timeout=2).decode(errors='ignore')
                print(f"\n{data}")
                
                if self.check_for_flag(data):
                    return True
                
                choice_match = re.search(r'\[([a-z0-9,/]+)\]', data.lower())
                if choice_match:
                    choices = choice_match.group(1).replace(' ', '').split('/')
                    print(f"{blue('[?]')} Detected choices: {choices}")
                    
                    if any(word in data.lower() for word in ['register', 'account']):
                        selected = 'c' if 'c' in choices else choices[0]
                        print(f"{green('[→]')} Selecting: {selected}")
                        self.io.sendline(selected.encode())
                        
                    elif any(word in data.lower() for word in ['play', 'game']):
                        selected = 'a' if 'a' in choices else choices[0]
                        print(f"{green('[→]')} Selecting: {selected}")
                        self.io.sendline(selected.encode())
                        
                    else:
                        print(f"{yellow('[?]')} Selecting first: {choices[0]}")
                        self.io.sendline(choices[0].encode())
                    
                    continue
                
                if 'options:' in data.lower() or 'choose' in data.lower():
                    time.sleep(0.5)
                    more_data = self.io.recvuntil(b'> ', timeout=2).decode(errors='ignore')
                    print(more_data)
                    self.io.sendline(b'c')
                
                else:
                    print(f"{yellow('  [↩]')} Pressing Enter...")
                    self.io.sendline(b'')
                    
            except EOFError:
                print(f"{red('[!] Connection closed')}")
                break
            except:
                try:
                    self.io.sendline(b'')
                except:
                    break
        
        return False
    
    def solve_shell(self):
        print(f"{green('[+]')} Interactive Shell Detected")
        print(f"{yellow('[!]')} Type 'flag', 'cat flag.txt', or 'ls' to start")
        print(f"{yellow('[!]')} Type 'exit' to return\n")
        
        self.io.interactive()
        return True
    
    def auto_solve(self):
        if not self.connect():
            return False
        
        print(f"\n{blue('='*60)}")
        print(f"{green('🧠 ctfbrain INTERACTIVE MODE')}")
        print(f"{blue('='*60)}\n")
        
        try:
            self.io.sendline(b'whoami')
            response = self.io.recvline(timeout=1).decode()
            if 'not found' not in response and len(response) > 0:
                return self.solve_shell()
        except:
            pass
        
        if self.solve_menu():
            return True
            
        return self.auto_press_enter()


def run_interactive(target):
    if ':' in target:
        host, port = target.split(':')
        port = int(port)
        solver = InteractiveSolver(host=host, port=port)
    else:
        return None
    
    try:
        solver.auto_solve()
    except KeyboardInterrupt:
        print(f"\n{yellow('[!]')} Interrupted")
    except Exception as e:
        print(f"{red('[!]')} Error: {e}")


if __name__ == '__main__':
    if len(sys.argv) > 1:
        run_interactive(sys.argv[1])