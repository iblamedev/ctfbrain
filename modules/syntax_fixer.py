#!/usr/bin/env python3
"""
ULTIMATE Multi-Language Syntax & Logic Error Fixer
Automatically detects, fixes, and runs ANY programming language!
"""
import re
import subprocess
import tempfile
import os
from pathlib import Path
from core.colors import red, green, yellow, blue, highlight

class SyntaxFixer:
    def __init__(self):
        self.fixes = []
        self.languages = {
            'rust': self.fix_rust,
            'python': self.fix_python,
            'c': self.fix_c,
            'cpp': self.fix_cpp,
            'java': self.fix_java,
            'javascript': self.fix_javascript,
            'go': self.fix_go,
            'ruby': self.fix_ruby,
            'php': self.fix_php,
        }
        
        self.run_commands = {
            'rust': self.run_rust,
            'python': self.run_python,
            'c': self.run_c,
            'cpp': self.run_cpp,
            'java': self.run_java,
            'javascript': self.run_javascript,
            'go': self.run_go,
            'ruby': self.run_ruby,
            'php': self.run_php,
        }

    def fix_rust(self, code):
        self.fixes = []
        
        code = re.sub(r'(let\s+\w+\s*=\s*String::from\([^)]*\))(?![;\n])', r'\1;', code)
        
        if re.search(r'\bret\s*;', code):
            code = re.sub(r'\bret\s*;', 'return;', code)
            self.fixes.append("Changed 'ret;' to 'return;'")
        
        if re.search(r'println!\(\s*":\?"', code):
            code = re.sub(r'println!\(\s*":\?"', 'println!("{}"', code)
            self.fixes.append("Fixed println! format placeholder")
        
        if re.search(r'&\s*String', code) and re.search(r'push_str', code):
            code = re.sub(r'(&\s*)String(?=\s*[,)])', r'\1mut String', code)
            self.fixes.append("Changed &String to &mut String")
        
        code = re.sub(r'(&\s*)String(\s*[,)])', r'\1mut String\2', code)
        
        if 'std::slice::from_raw_parts' in code:
            pattern = r'unsafe\s*{\s*let\s+(\w+)\s*=\s*(std::slice::from_raw_parts\([^;]+\))\s*;\s*}'
            if re.search(pattern, code, re.DOTALL):
                code = re.sub(pattern, r'let \1 = unsafe { \2 };', code, flags=re.DOTALL)
                self.fixes.append("Fixed unsafe block - moved variable outside")
        
        if 'let mut key = String::from("CSUCKS");' in code:
            if 'key.' not in code and '&mut key' not in code:
                code = code.replace('let mut key =', 'let key =')
                self.fixes.append("Removed unnecessary 'mut'")
        
        if self.fixes:
            print(f"{green('[+]')} Rust fixes applied:")
            for fix in self.fixes:
                print(f"  {yellow('•')} {fix}")
        
        return code

    def fix_python(self, code):
        self.fixes = []
        lines = code.split('\n')
        fixed_lines = []
        
        for line in lines:
            original = line
            
            for keyword in ['if', 'elif', 'else', 'while', 'for', 'def', 'class']:
                pattern = rf'^\s*{keyword}\s+.*?(?<!:)\s*$'
                if re.match(pattern, line, re.IGNORECASE):
                    line = line.rstrip() + ':'
                    self.fixes.append(f"Added missing colon after '{keyword}'")
                    break
            
            if re.match(r'^\s*print\s+', line):
                line = re.sub(r'print\s+(.+)', r'print(\1)', line)
                self.fixes.append("Converted Python 2 print to Python 3")
            
            if re.search(r'(\w+)\s*\+\+\s*', line):
                line = re.sub(r'(\w+)\s*\+\+\s*', r'\1 += 1', line)
                self.fixes.append("Fixed ++ operator")
            
            fixed_lines.append(line)
        
        code = '\n'.join(fixed_lines)
        if 'input(' in code and 'import sys' not in code:
            code = 'import sys\n' + code
            self.fixes.append("Added missing import sys")
        
        return code

    def fix_c(self, code):
        self.fixes = []
        lines = code.split('\n')
        fixed_lines = []
        
        if 'printf' in code and '#include <stdio.h>' not in code:
            fixed_lines.append('#include <stdio.h>')
            self.fixes.append("Added missing #include <stdio.h>")
        
        for line in lines:
            if (not line.strip().startswith('#') and 
                not line.strip().endswith(('{', '}', ';')) and 
                line.strip()):
                
                if re.match(r'^\s*\w+\s*\(.*\)', line) or re.match(r'^\s*\w+\s*=', line):
                    line = line.rstrip() + ';'
                    self.fixes.append("Added missing semicolon")
            
            if re.search(r'main\(\)', line):
                line = line.replace('main()', 'int main()')
                self.fixes.append("Fixed main() signature")
            
            fixed_lines.append(line)
        
        code = '\n'.join(fixed_lines)
        if 'return 0' not in code and 'int main' in code:
            code += '\n    return 0;\n}'
            self.fixes.append("Added return 0; to main")
        
        return code

    def fix_cpp(self, code):
        return self.fix_c(code)

    def fix_java(self, code):
        self.fixes = []
        
        class_match = re.search(r'class\s+(\w+)', code)
        if class_match:
            class_name = class_match.group(1)
            if class_name != 'Main':
                code = re.sub(r'class\s+\w+', 'class Main', code)
                self.fixes.append("Renamed class to Main")
        
        if re.search(r'public\s+static\s+void\s+main\s*\([^)]*\)', code):
            code = re.sub(
                r'public\s+static\s+void\s+main\s*\([^)]*\)',
                'public static void main(String[] args)',
                code
            )
            self.fixes.append("Fixed main method signature")
        
        return code

    def fix_javascript(self, code):
        self.fixes = []
        lines = code.split('\n')
        fixed_lines = []
        
        for line in lines:
            if (not line.strip().endswith(('{', '}', ';', ')')) and 
                not line.strip().startswith('//') and 
                line.strip()):
                
                if 'var ' in line or 'let ' in line or 'const ' in line or 'console.log' in line:
                    line = line.rstrip() + ';'
                    self.fixes.append("Added missing semicolon")
            
            fixed_lines.append(line)
        
        return '\n'.join(fixed_lines)

    def fix_go(self, code):
        self.fixes = []
        
        if not re.search(r'package\s+\w+', code):
            code = 'package main\n' + code
            self.fixes.append("Added package main")
        
        if 'fmt.Println' in code and 'import "fmt"' not in code:
            code = code.replace('package main\n', 'package main\n\nimport "fmt"\n')
            self.fixes.append("Added missing import fmt")
        
        return code

    def fix_ruby(self, code):
        self.fixes = []
        
        if re.search(r'(\w+)\s*=\s*gets\.chomp', code):
            code = re.sub(r'(\w+)\s*=\s*gets\.chomp', r'\1 = gets.chomp', code)
            self.fixes.append("Fixed gets.chomp")
        
        return code

    def fix_php(self, code):
        self.fixes = []
        lines = code.split('\n')
        fixed_lines = []
        
        if not code.strip().startswith('<?php'):
            fixed_lines.append('<?php')
            self.fixes.append("Added <?php opening tag")
        
        for line in lines:
            if line.strip() and not line.strip().startswith('<?php'):
                if (not line.strip().endswith((';', '{', '}'))) and not line.strip().startswith('//'):
                    if 'echo' in line or '$' in line:
                        line = line.rstrip() + ';'
                        self.fixes.append("Added missing semicolon")
                fixed_lines.append(line)
        
        return '\n'.join(fixed_lines)

    def detect_language(self, code, filename=None):
        scores = {}
        
        if filename:
            ext_map = {
                '.rs': 'rust', '.py': 'python', '.c': 'c', '.cpp': 'cpp', 
                '.java': 'java', '.js': 'javascript', '.go': 'go',
                '.rb': 'ruby', '.php': 'php'
            }
            ext = os.path.splitext(filename)[1].lower()
            if ext in ext_map:
                return ext_map[ext]
        
        patterns = {
            'rust': [r'fn\s+main\(', r'let\s+mut', r'String::from', r'println!'],
            'python': [r'def\s+\w+\s*\(', r'if\s+__name__\s*==', r'import\s+\w+', r'print\('],
            'c': [r'#include\s*<stdio\.h>', r'int\s+main\s*\(', r'printf\s*\('],
            'cpp': [r'#include\s*<iostream>', r'using\s+namespace\s+std', r'cout\s*<<'],
            'java': [r'public\s+class', r'public\s+static\s+void\s+main', r'System\.out\.println'],
            'javascript': [r'console\.log', r'function\s+\w+\s*\(', r'var\s+\w+\s*='],
            'go': [r'package\s+main', r'func\s+main\(\)', r'fmt\.Println'],
            'ruby': [r'def\s+\w+', r'puts\s+\w+', r'#!.*ruby'],
            'php': [r'<\?php', r'echo\s+\$', r'\$\w+\s*='],
        }
        
        for lang, lang_patterns in patterns.items():
            score = 0
            for pattern in lang_patterns:
                if re.search(pattern, code, re.MULTILINE):
                    score += 1
            if score > 0:
                scores[lang] = score
        
        return max(scores, key=scores.get) if scores else 'unknown'

    def auto_fix(self, code, language=None, filename=None):
        self.fixes = []
        print(f"{green('[+]')} 🔧 Analyzing code for issues...")
        
        if not language:
            language = self.detect_language(code, filename)
            print(f"{green('[+]')} 📝 Detected language: {blue(language.upper())}")
        else:
            print(f"{green('[+]')} 📝 Using specified language: {blue(language.upper())}")
        
        if language in self.languages:
            fixed_code = self.languages[language](code)
            return fixed_code, language
        else:
            return self.generic_fix(code), language

    def generic_fix(self, code):
        self.fixes = []
        lines = code.split('\n')
        fixed_lines = []
        
        for line in lines:
            stripped = line.strip()
            if (stripped and 
                not stripped.endswith(('{', '}', ';', ')')) and
                not stripped.startswith(('#', '//'))):
                
                if '=' in stripped or 'print' in stripped or 'return' in stripped:
                    line = line.rstrip() + ';'
                    self.fixes.append("Added missing semicolon")
            
            fixed_lines.append(line)
        
        return '\n'.join(fixed_lines)

    def run_rust(self, code, tmpdir):
        cargo_dir = tmpdir / 'rust_project'
        cargo_dir.mkdir()
        src_dir = cargo_dir / 'src'
        src_dir.mkdir()
        
        with open(src_dir / 'main.rs', 'w') as f:
            f.write(code)
        
        with open(cargo_dir / 'Cargo.toml', 'w') as f:
            f.write("""[package]
name = "ctf_solver"
version = "0.1.0"
edition = "2021"

[dependencies]
xor_cryptor = "1.2.3"
""")
        
        print(f"{yellow('[>]')} Compiling Rust...")
        result = subprocess.run(['cargo', 'run'], cwd=cargo_dir, capture_output=True, text=True)
        return result.stdout + result.stderr

    def run_python(self, code, tmpdir):
        with open(tmpdir / 'script.py', 'w') as f:
            f.write(code)
        print(f"{yellow('[>]')} Running Python...")
        result = subprocess.run(['python3', 'script.py'], cwd=tmpdir, capture_output=True, text=True)
        return result.stdout + result.stderr

    def run_c(self, code, tmpdir):
        with open(tmpdir / 'program.c', 'w') as f:
            f.write(code)
        print(f"{yellow('[>]')} Compiling C...")
        compile_result = subprocess.run(['gcc', 'program.c', '-o', 'program'], 
                                      cwd=tmpdir, capture_output=True, text=True)
        if compile_result.returncode == 0:
            run_result = subprocess.run(['./program'], cwd=tmpdir, capture_output=True, text=True)
            return run_result.stdout + run_result.stderr
        return compile_result.stderr

    def run_cpp(self, code, tmpdir):
        with open(tmpdir / 'program.cpp', 'w') as f:
            f.write(code)
        print(f"{yellow('[>]')} Compiling C++...")
        compile_result = subprocess.run(['g++', 'program.cpp', '-o', 'program'], 
                                      cwd=tmpdir, capture_output=True, text=True)
        if compile_result.returncode == 0:
            run_result = subprocess.run(['./program'], cwd=tmpdir, capture_output=True, text=True)
            return run_result.stdout + run_result.stderr
        return compile_result.stderr

    def run_java(self, code, tmpdir):
        with open(tmpdir / 'Main.java', 'w') as f:
            f.write(code)
        print(f"{yellow('[>]')} Compiling Java...")
        compile_result = subprocess.run(['javac', 'Main.java'], cwd=tmpdir, 
                                      capture_output=True, text=True)
        if compile_result.returncode == 0:
            run_result = subprocess.run(['java', 'Main'], cwd=tmpdir, 
                                      capture_output=True, text=True)
            return run_result.stdout + run_result.stderr
        return compile_result.stderr

    def run_javascript(self, code, tmpdir):
        with open(tmpdir / 'script.js', 'w') as f:
            f.write(code)
        print(f"{yellow('[>]')} Running JavaScript...")
        result = subprocess.run(['node', 'script.js'], cwd=tmpdir, 
                              capture_output=True, text=True)
        return result.stdout + result.stderr

    def run_go(self, code, tmpdir):
        with open(tmpdir / 'main.go', 'w') as f:
            f.write(code)
        print(f"{yellow('[>]')} Running Go...")
        result = subprocess.run(['go', 'run', 'main.go'], cwd=tmpdir, 
                              capture_output=True, text=True)
        return result.stdout + result.stderr

    def run_ruby(self, code, tmpdir):
        with open(tmpdir / 'script.rb', 'w') as f:
            f.write(code)
        print(f"{yellow('[>]')} Running Ruby...")
        result = subprocess.run(['ruby', 'script.rb'], cwd=tmpdir, 
                              capture_output=True, text=True)
        return result.stdout + result.stderr

    def run_php(self, code, tmpdir):
        with open(tmpdir / 'script.php', 'w') as f:
            f.write(code)
        print(f"{yellow('[>]')} Running PHP...")
        result = subprocess.run(['php', 'script.php'], cwd=tmpdir, 
                              capture_output=True, text=True)
        return result.stdout + result.stderr

    def compile_and_run(self, code, language, tmpdir):
        if language in self.run_commands:
            return self.run_commands[language](code, tmpdir)
        return f"No runner available for {language}"


def fix_syntax(code=None, file_path=None, language=None, run=False, output=None):
    fixer = SyntaxFixer()
    
    filename = None
    if file_path:
        filename = os.path.basename(file_path)
        try:
            with open(file_path, 'r') as f:
                code = f.read()
            print(f"{green('[+]')} 📂 Loaded code from {file_path}")
        except Exception as e:
            print(f"{red('[-]')} Failed to read file: {e}")
            return None
    
    if not code:
        print(f"{red('[-]')} No code provided")
        return None
    
    print(f"\n{blue('='*60)}")
    print(f"{green('🧠 ctfbrain ULTIMATE AUTO-FIXER')}")
    print(f"{blue('='*60)}\n")
    
    print(f"{yellow('[ Original Code ]')}")
    print("-" * 40)
    print(code[:300] + "..." if len(code) > 300 else code)
    print()
    
    fixed_code, detected_lang = fixer.auto_fix(code, language, filename)
    
    if fixer.fixes:
        print(f"{green('[✅]')} Applied {len(fixer.fixes)} fixes:")
        for fix in fixer.fixes[:10]:
            print(f"  {yellow('•')} {fix}")
    else:
        print(f"{green('[✅]')} No fixes needed!")
    
    print(f"\n{green('[ Fixed Code ]')}")
    print("-" * 40)
    print(fixed_code[:300] + "..." if len(fixed_code) > 300 else fixed_code)
    print()
    
    if output:
        try:
            with open(output, 'w') as f:
                f.write(fixed_code)
            print(f"{green('[💾]')} Fixed code saved to: {blue(output)}")
        except Exception as e:
            print(f"{red('[-]')} Failed to save: {e}")
    
    if run:
        print(f"\n{yellow('[🚀]')} COMPILE & RUN MODE")
        print("-" * 40)
        
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            output_text = fixer.compile_and_run(fixed_code, detected_lang, tmpdir)
            
            flag_patterns = [r'picoCTF\{.*?\}', r'flag\{.*?\}', r'CTF\{.*?\}']
            
            print(f"\n{yellow('[📟]')} PROGRAM OUTPUT:")
            print("-" * 40)
            print(output_text)
            
            for pattern in flag_patterns:
                flags = re.findall(pattern, output_text)
                for flag in flags:
                    print(f"\n{red('[🏆 FLAG FOUND]')} {highlight(flag)}\n")
    
    return fixed_code


if __name__ == '__main__':
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description='🧠 ctfbrain ULTIMATE AUTO-FIXER')
    parser.add_argument('file', nargs='?', help='Source code file to fix')
    parser.add_argument('-l', '--language', help='Force language')
    parser.add_argument('-o', '--output', help='Save fixed code to file')
    parser.add_argument('-r', '--run', action='store_true', help='AUTO-COMPILE AND AUTO-RUN!')
    
    args = parser.parse_args()
    
    if args.file:
        fix_syntax(
            file_path=args.file,
            language=args.language,
            run=args.run,
            output=args.output
        )
    else:
        if not sys.stdin.isatty():
            code = sys.stdin.read()
            fix_syntax(
                code=code,
                language=args.language,
                run=args.run,
                output=args.output
            )
        else:
            parser.print_help()