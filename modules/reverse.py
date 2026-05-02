#!/usr/bin/env python3
"""
Reverse Engineering Module for CTF
Handles: Binary analysis, decompilation, string extraction, dynamic analysis
"""
import os
import re
import subprocess
import tempfile
from core.colors import red, green, yellow, blue, highlight
from core.executor import run_cmd
from core.tools import check_tool

FLAG_PATTERN = r'[a-zA-Z0-9_]+\{[^}]*\}'

class ReverseSolver:
    def __init__(self):
        self.found_flags = []
    
    def extract_flag(self, text):
        if not text:
            return None
        flags = re.findall(FLAG_PATTERN, str(text))
        if flags:
            return flags[0]
        return None
    
    def check_strings(self, binary):
        """Extract strings from binary"""
        if not check_tool("strings"):
            return None
        
        print(f"{green('[+]')} Extracting strings...")
        result = subprocess.getoutput(f"strings -a {binary}")
        
        for line in result.split('\n'):
            if re.search(FLAG_PATTERN, line):
                print(f"{yellow('[*]')} Found potential flag: {line}")
                return line
        
        return None
    
    def check_file_info(self, binary):
        """Get file information"""
        result = subprocess.getoutput(f"file {binary}")
        print(f"{green('[+]')} File info: {result}")
        
        flag = self.extract_flag(result)
        if flag:
            return flag
        return None
    
    def check_checksec(self, binary):
        """Check binary security features"""
        if not check_tool("checksec"):
            return None
        
        result = subprocess.getoutput(f"checksec --file={binary}")
        print(result)
        
        flag = self.extract_flag(result)
        if flag:
            return flag
        return None
    
    def check_ltrace(self, binary):
        """Trace library calls"""
        if not check_tool("ltrace"):
            return None
        
        print(f"{green('[+]')} Tracing library calls...")
        try:
            result = subprocess.getoutput(f"ltrace -f {binary} 2>&1 | head -50")
            print(result)
            
            flag = self.extract_flag(result)
            if flag:
                return flag
        except:
            pass
        return None
    
    def check_strace(self, binary):
        """Trace system calls"""
        if not check_tool("strace"):
            return None
        
        print(f"{green('[+]')} Tracing system calls...")
        try:
            result = subprocess.getoutput(f"strace -f {binary} 2>&1 | head -50")
            print(result)
            
            flag = self.extract_flag(result)
            if flag:
                return flag
        except:
            pass
        return None
    
    def check_radare2(self, binary):
        """Basic radare2 analysis"""
        if not check_tool("radare2"):
            return None
        
        print(f"{green('[+]')} Running radare2 analysis...")
        
        if check_tool("rabin2"):
            result = subprocess.getoutput(f"rabin2 -I {binary}")
            print(result)
            
            flag = self.extract_flag(result)
            if flag:
                return flag
        
        result = subprocess.getoutput(f"rabin2 -zz {binary} | grep -i flag")
        if result:
            print(result)
            flag = self.extract_flag(result)
            if flag:
                return flag
        
        return None
    
    def check_objdump(self, binary):
        """Check with objdump"""
        if not check_tool("objdump"):
            return None
        
        print(f"{green('[+]')} Checking with objdump...")
        result = subprocess.getoutput(f"objdump -d {binary} | head -100")
        
        flag = self.extract_flag(result)
        if flag:
            return flag
        return None
    
    def run_binary(self, binary):
        """Run the binary and capture output"""
        print(f"{green('[+]')} Running binary...")
        try:
            os.chmod(binary, 0o755)
            result = subprocess.run([f"./{binary}"], capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
            print(output)
            
            flag = self.extract_flag(output)
            if flag:
                return flag
        except subprocess.TimeoutExpired:
            print(f"{yellow('[*]')} Binary execution timed out")
        except Exception as e:
            print(f"{yellow('[*]')} Could not run binary: {e}")
        
        return None
    
    def solve_binary(self, binary):
        """Solve reverse engineering challenge"""
        print(f"{green('[+]')} Analyzing binary: {binary}")
        
        if not os.path.exists(binary):
            print(f"{red('[-]')} Binary not found")
            return None
        
        try:
            os.chmod(binary, 0o755)
        except:
            pass
        
        methods = [
            ('file info', self.check_file_info),
            ('strings', self.check_strings),
            ('run', self.run_binary),
            ('checksec', self.check_checksec),
            ('radare2', self.check_radare2),
            ('objdump', self.check_objdump),
            ('ltrace', self.check_ltrace),
            ('strace', self.check_strace)
        ]
        
        for name, method in methods:
            print(f"\n{yellow('[*]')} Trying {name}...")
            result = method(binary)
            if result:
                return result
        
        return None


def run_reverse(filepath):
    """Main reverse engineering solver"""
    solver = ReverseSolver()
    
    if not os.path.exists(filepath):
        print(f"{red('[-]')} File not found: {filepath}")
        return None
    
    return solver.solve_binary(filepath)


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = run_reverse(sys.argv[1])
        if result:
            print(f"\n{red('[🏆]')} Flag found: {green(result)}")
        else:
            print(f"{yellow('[-]')} No flag found")