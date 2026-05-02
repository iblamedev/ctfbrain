import shutil
import os
import subprocess
import re
from core.colors import red, green, yellow, highlight
from core.executor import run_cmd
from core.tools import check_tool, requires_tools

FLAG_PATTERN = r'[a-zA-Z0-9_]+\{[^}]*\}'

def generate_pwn_template(binary_path):
    """Generate pwntools template"""
    if os.path.exists("solve.py"):
        return

    print(f"\n{green('[+]')} Auto-generating Pwntools Template...")
    
    try:
        import pwn
    except ImportError:
        print(f"{red('[-]')} Pwntools not installed.")
        return
    
    template = f"""from pwn import *

# Set up the binary
elf = context.binary = ELF("{binary_path}")

# --- CONNECTION ---
# 1. Local Process
p = process()

# 2. Remote (CTF)
# p = remote("IP", 1337)

# 3. Debug
# gdb.attach(p, gdbscript='''
#     b *main
#     c
# ''')

# --- EXPLOIT ---
print(p.recvall())
# payload = b"A"*40 + p64(elf.symbols['win'])
# p.sendline(payload)
p.interactive()
"""
    with open("solve.py", "w") as f:
        f.write(template)
    
    print(f"{green('[SUCCESS]')} Created 'solve.py'.")

def extract_flag_from_output(output):
    """Extract flag from output"""
    if not output:
        return None
    flags = re.findall(FLAG_PATTERN, str(output))
    if flags:
        return flags[0]
    return None

@requires_tools('checksec', 'ROPgadget', 'radare2')
def run_binary(target):
    """Run binary analysis and return flag if found"""
    print(f"{green('[+]')} Running Binary Analysis on: {target}")

    if not os.path.exists(target):
        print(f"{red('[-] File not found.')}")
        return None
        
    try:
        os.chmod(target, 0o755)
    except: 
        pass

    if check_tool("strings"):
        print(f"{green('[+]')} Checking strings for flags...")
        result = subprocess.getoutput(f"strings -a {target}")
        flag = extract_flag_from_output(result)
        if flag:
            print(f"\n{red('[🏆 FLAG FOUND]')} {highlight(flag)}")
            return flag

    try:
        result = subprocess.run([f"./{target}"], capture_output=True, text=True, timeout=5)
        output = result.stdout + result.stderr
        flag = extract_flag_from_output(output)
        if flag:
            print(f"\n{red('[🏆 FLAG FOUND]')} {highlight(flag)}")
            return flag
    except:
        pass

    run_cmd(f"file {target}")

    if check_tool("checksec"):
        run_cmd(f"checksec --file={target}")

    if check_tool("ROPgadget"):
        print(f"{green('[+]')} Searching for ROP Gadgets...")
        run_cmd(f"ROPgadget --binary {target} | grep 'pop rdi' | head -n 5")

    if check_tool("rabin2"):
        print(f"{green('[+]')} Radare2 Info...")
        run_cmd(f"rabin2 -I {target}")

    generate_pwn_template(target)

    print(f"\n{green('[+]')} Binary analysis complete - no flag found.")
    return None