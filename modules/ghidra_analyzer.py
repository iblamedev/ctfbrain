#!/usr/bin/env python3
"""
Basic Binary Analyzer (Ghidra-like functionality without Ghidra)
Handles: Basic decompilation simulation, string analysis, vulnerability pattern matching
"""
import os
import re
import subprocess
import tempfile
from core.colors import red, green, yellow, blue, highlight

FLAG_PATTERN = r'[a-zA-Z0-9_]+\{[^}]*\}'

class BinaryAnalyzer:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.strings = []
        self.functions = []
    
    def extract_flag(self, text):
        if not text:
            return None
        flags = re.findall(FLAG_PATTERN, str(text))
        if flags:
            return flags[0]
        return None
    
    def check_ghidra(self):
        """Check if Ghidra is installed (optional)"""
        return os.path.exists("/opt/ghidra") or os.path.exists(os.path.expanduser("~/ghidra"))
    
    def analyze_with_ghidra(self):
        """Use Ghidra headless if available"""
        ghidra_path = None
        if os.path.exists("/opt/ghidra"):
            ghidra_path = "/opt/ghidra"
        elif os.path.exists(os.path.expanduser("~/ghidra")):
            ghidra_path = os.path.expanduser("~/ghidra")
        
        if not ghidra_path:
            return None
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, "analysis.txt")
            cmd = f"{ghidra_path}/support/analyzeHeadless {tmpdir} temp -import {self.binary_path} -postScript DumpStrings.java -scriptlog {output_file}"
            subprocess.run(cmd, shell=True, timeout=30)
            
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    return f.read()
        return None
    
    def analyze_with_radare2(self):
        """Use radare2 for basic analysis"""
        try:
            # Get functions
            cmd = f"r2 -qc 'afl' {self.binary_path}"
            functions = subprocess.getoutput(cmd)
            
            # Get strings with xrefs
            cmd = f"r2 -qc 'izz' {self.binary_path}"
            strings = subprocess.getoutput(cmd)
            
            # Get decompiled main if possible
            cmd = f"r2 -qc 's main; pdd' {self.binary_path} 2>/dev/null"
            decompiled = subprocess.getoutput(cmd)
            
            return {
                'functions': functions,
                'strings': strings,
                'decompiled': decompiled
            }
        except:
            return None
    
    def analyze_with_objdump(self):
        """Basic analysis with objdump"""
        try:
            # Get disassembly
            cmd = f"objdump -d {self.binary_path} | head -200"
            disassembly = subprocess.getoutput(cmd)
            
            # Get headers
            cmd = f"objdump -h {self.binary_path}"
            headers = subprocess.getoutput(cmd)
            
            return {
                'disassembly': disassembly,
                'headers': headers
            }
        except:
            return None
    
    def extract_strings(self):
        """Extract strings from binary"""
        cmd = f"strings -a {self.binary_path}"
        output = subprocess.getoutput(cmd)
        self.strings = output.split('\n')
        return self.strings
    
    def find_env_variable_patterns(self):
        """Look for getenv() calls and environment variable usage"""
        interesting_patterns = []
        
        for s in self.strings:
            if 'getenv' in s or 'setenv' in s:
                interesting_patterns.append(s)
                print(f"{yellow('[*]')} Found env function: {s}")
            
            # Look for admin variable (like in walkthrough)
            if 'admin' in s.lower() and '=' not in s:
                interesting_patterns.append(s)
                print(f"{red('[!]')} Potential admin variable: {s}")
        
        return interesting_patterns
    
    def find_comparison_patterns(self):
        """Look for comparison patterns that might be password checks"""
        comparisons = []
        
        # This would need disassembly analysis
        # For now, just look for strings that look like comparisons
        for s in self.strings:
            if len(s) == 32 and re.match(r'^[a-f0-9]+$', s):
                comparisons.append(s)
                print(f"{yellow('[*]')} Possible hash: {s}")
        
        return comparisons
    
    def analyze_binary(self):
        """Main binary analysis function"""
        print(f"{green('[+]')} 🔍 Analyzing binary: {self.binary_path}")
        
        # Basic file info
        file_info = subprocess.getoutput(f"file {self.binary_path}")
        print(f"{green('[+]')} {file_info}")
        
        # Extract strings
        self.extract_strings()
        print(f"{green('[+]')} Found {len(self.strings)} strings")
        
        # Look for environment variable patterns
        env_patterns = self.find_env_variable_patterns()
        
        # Check for checker binary pattern (like in walkthrough)
        if 'checker' in self.binary_path:
            print(f"\n{red('[!]')} Detected 'checker' binary - look for getenv('admin')")
            
            # Look for admin string
            if any('admin' in s.lower() for s in self.strings):
                print(f"{green('[+]')} Binary references 'admin' - try: export admin=1 && ./{self.binary_path}")
                return "Set environment variable: admin=1"
        
        # Try radare2 analysis
        r2_data = self.analyze_with_radare2()
        if r2_data and r2_data.get('decompiled'):
            print(f"\n{yellow('[*]')} Decompiled code snippet:")
            print(r2_data['decompiled'][:500])
            
            # Look for interesting patterns in decompiled code
            if 'getenv' in r2_data['decompiled']:
                print(f"{red('[!]')} Binary uses getenv() - possible environment variable vulnerability")
        
        # Try objdump analysis
        objdump_data = self.analyze_with_objdump()
        if objdump_data:
            # Look for comparisons in disassembly
            if 'cmp' in objdump_data['disassembly']:
                print(f"{yellow('[*]')} Found comparison instructions - possible password check")
        
        # Look for flags in strings
        for s in self.strings:
            flag = self.extract_flag(s)
            if flag:
                return flag
        
        return None


def run_binary_analyzer(binary_path):
    """Main binary analyzer entry point"""
    analyzer = BinaryAnalyzer(binary_path)
    return analyzer.analyze_binary()


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = run_binary_analyzer(sys.argv[1])
        if result:
            print(f"\n{red('[🏆]')} Result: {green(result)}")
        else:
            print(f"{yellow('[-]')} No vulnerabilities found")