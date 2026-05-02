#!/usr/bin/env python3
"""
Git Repository Analysis Module for CTF
Handles: Multi-branch flags, commit history, merge conflicts
"""
import os
import re
import subprocess
from core.colors import red, green, yellow, blue, highlight

FLAG_PATTERN = r'[a-zA-Z0-9_]+\{[^}]*\}'

class GitSolver:
    def __init__(self):
        self.found_flags = []
        self.flag_parts = []
        self.repo_path = None
    
    def extract_flag(self, text):
        if not text:
            return None
        flags = re.findall(FLAG_PATTERN, str(text))
        if flags:
            return flags[0]
        return None
    
    def extract_string_from_print(self, line):
        patterns = [
            r'print\(["\']([^"\']+)["\']',
            r'print\(([^,]+),',
            r'end=[\'"]([^\'"]+)[\'"]',
        ]
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        return None
    
    def extract_flag_parts_from_file(self, content):
        parts = []
        lines = content.split('\n')
        for line in lines:
            if 'Printing the flag' in line:
                continue
            text = self.extract_string_from_print(line)
            if text and len(text) > 3:
                text = text.strip()
                if text and text not in parts:
                    print(f"{green('[+]')} Found flag part: {text}")
                    parts.append(text)
        return parts
    
    def run_git_command(self, cmd, repo_path=None):
        if repo_path is None:
            repo_path = self.repo_path
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )
            return result.stdout + result.stderr
        except Exception as e:
            return f"Error: {e}"
    
    def is_git_repo(self, path):
        git_dir = os.path.join(path, '.git')
        return os.path.isdir(git_dir)
    
    def get_all_branches(self):
        output = self.run_git_command("git branch -a")
        branches = []
        for line in output.split('\n'):
            line = line.strip()
            if line and not line.startswith('*'):
                branch = line.replace('remotes/origin/', '').strip()
                if branch and branch not in branches:
                    branches.append(branch)
            elif line.startswith('*'):
                branch = line[1:].strip()
                if branch and branch not in branches:
                    branches.append(branch)
        return branches
    
    def get_current_branch(self):
        output = self.run_git_command("git branch --show-current")
        return output.strip()
    
    def checkout_branch(self, branch):
        return self.run_git_command(f"git checkout {branch}")
    
    def get_file_content(self, filename, branch=None):
        if branch:
            output = self.run_git_command(f"git show {branch}:{filename}")
        else:
            try:
                with open(os.path.join(self.repo_path, filename), 'r') as f:
                    output = f.read()
            except:
                output = self.run_git_command(f"cat {filename}")
        return output
    
    def solve_multi_branch(self):
        print(f"{green('[+]')} Checking all branches for flag parts...")
        
        original_branch = self.get_current_branch()
        print(f"{yellow('[*]')} Current branch: {original_branch}")
        
        branches = self.get_all_branches()
        print(f"{green('[+]')} Found {len(branches)} branches: {branches}")
        
        flag_parts = []
        flag_files = ['flag.py', 'flag.txt', 'flag', 'message.txt']
        
        for branch in branches:
            print(f"\n{yellow('[*]')} Checking branch: {branch}")
            self.checkout_branch(branch)
            
            for filename in flag_files:
                content = self.get_file_content(filename, branch)
                if content and content.strip():
                    flag = self.extract_flag(content)
                    if flag:
                        print(f"{green('[+]')} Found complete flag in {branch}/{filename}: {flag}")
                        return flag
                    
                    parts = self.extract_flag_parts_from_file(content)
                    flag_parts.extend(parts)
        
        self.checkout_branch(original_branch)
        
        if flag_parts:
            seen = set()
            unique_parts = []
            for part in flag_parts:
                if part not in seen:
                    seen.add(part)
                    unique_parts.append(part)
            
            assembled = ''.join(unique_parts)
            print(f"\n{red('[🏆]')} Assembled flag: {green(assembled)}")
            
            if assembled.startswith('picoCTF{') and assembled.endswith('}'):
                return assembled
            elif 'picoCTF{' in assembled:
                match = re.search(r'picoCTF\{[^}]*\}', assembled)
                if match:
                    return match.group(0)
            else:
                return 'picoCTF{' + assembled + '}'
        
        return None
    
    def solve_git(self, repo_path):
        self.repo_path = repo_path
        
        if not self.is_git_repo(repo_path):
            return None
        
        print(f"{green('[+]')} 🔍 Analyzing Git repository: {repo_path}")
        
        result = self.solve_multi_branch()
        if result:
            return result
        
        print(f"\n{yellow('[-]')} No flag found in Git repository.")
        return None


def run_git(repo_path):
    """Main git entry point - only runs for actual git repos"""
    if not os.path.isdir(repo_path) or not os.path.isdir(os.path.join(repo_path, '.git')):
        return None
    
    solver = GitSolver()
    return solver.solve_git(repo_path)


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = run_git(sys.argv[1])
        if result:
            print(f"\n{red('[🏆]')} Flag found: {green(result)}")
        else:
            print(f"{yellow('[-]')} No flag found")