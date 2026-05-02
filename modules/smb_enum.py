#!/usr/bin/env python3
"""
SMB Enumeration Module for CTF
Handles: SMB share discovery, file download, automated analysis
"""
import os
import re
import subprocess
import tempfile
from core.colors import red, green, yellow, blue, highlight
from core.tools import check_tool

FLAG_PATTERN = r'[a-zA-Z0-9_]+\{[^}]*\}'

class SMBEnumerator:
    def __init__(self, target):
        self.target = target
        self.shares = []
        self.downloaded_files = []
    
    def extract_flag(self, text):
        if not text:
            return None
        flags = re.findall(FLAG_PATTERN, str(text))
        if flags:
            return flags[0]
        return None
    
    def check_smbclient(self):
        """Check if smbclient is installed"""
        if not check_tool("smbclient"):
            print(f"{yellow('[!]')} smbclient not installed. Try: sudo apt install smbclient")
            return False
        return True
    
    def list_shares(self):
        """List all available SMB shares (including null session)"""
        print(f"{green('[+]')} Enumerating SMB shares on {self.target}")
        
        # Try with null session first
        cmd = f"smbclient -L //{self.target} -N -g 2>/dev/null"
        result = subprocess.getoutput(cmd)
        
        # Parse shares
        shares = []
        for line in result.split('\n'):
            if '|' in line:
                parts = line.split('|')
                if len(parts) >= 2:
                    share_name = parts[1].strip()
                    if share_name and share_name not in ['IPC$', 'print$']:
                        shares.append(share_name)
                        print(f"{green('[+]')} Found share: {share_name}")
        
        self.shares = shares
        return shares
    
    def enumerate_share(self, share_name):
        """Enumerate a specific share and list files"""
        print(f"{yellow('[*]')} Enumerating share: {share_name}")
        
        # Create temp directory for downloads
        download_dir = f"smb_downloads_{share_name}"
        os.makedirs(download_dir, exist_ok=True)
        
        # List files in share
        cmd = f"smbclient //{self.target}/{share_name} -N -c 'ls' 2>/dev/null"
        result = subprocess.getoutput(cmd)
        
        files = []
        for line in result.split('\n'):
            # Parse smbclient ls output
            parts = line.split()
            if len(parts) >= 4 and parts[0][0] != '.':
                filename = parts[3] if len(parts) > 3 else None
                if filename and filename not in ['.', '..']:
                    files.append(filename)
                    print(f"{green('[+]')} Found file: {filename}")
        
        return files, download_dir
    
    def download_file(self, share_name, filename, download_dir):
        """Download a specific file from share"""
        print(f"{yellow('[*]')} Downloading {filename} from {share_name}...")
        
        local_path = os.path.join(download_dir, filename)
        cmd = f"smbclient //{self.target}/{share_name} -N -c 'get {filename} {local_path}' 2>/dev/null"
        subprocess.run(cmd, shell=True)
        
        if os.path.exists(local_path):
            print(f"{green('[+]')} Downloaded to {local_path}")
            self.downloaded_files.append(local_path)
            return local_path
        return None
    
    def analyze_file(self, filepath):
        """Analyze downloaded file with appropriate module"""
        print(f"{yellow('[*]')} Analyzing {filepath}...")
        
        # Check file type
        file_type = subprocess.getoutput(f"file -b {filepath}").lower()
        
        # Image files - use stego
        if 'image' in file_type or filepath.endswith(('.jpg', '.jpeg', '.png', '.gif')):
            try:
                from modules.stego import run_stego
                result = run_stego(filepath)
                if result:
                    return result
            except ImportError:
                pass
        
        # Archive files - extract and analyze
        elif 'archive' in file_type or filepath.endswith(('.zip', '.tar', '.gz')):
            try:
                from modules.forensics import extract_archive
                result = extract_archive(filepath)
                if result and isinstance(result, str):
                    flag = self.extract_flag(result)
                    if flag:
                        return flag
            except ImportError:
                pass
        
        # Text files - read directly
        elif 'text' in file_type:
            try:
                with open(filepath, 'r', errors='ignore') as f:
                    content = f.read()
                    flag = self.extract_flag(content)
                    if flag:
                        return flag
            except:
                pass
        
        # Binary files - check strings
        else:
            strings = subprocess.getoutput(f"strings {filepath}")
            flag = self.extract_flag(strings)
            if flag:
                return flag
        
        return None
    
    def auto_download_all(self, share_name):
        """Download all files from a share"""
        files, download_dir = self.enumerate_share(share_name)
        
        for filename in files:
            local_path = self.download_file(share_name, filename, download_dir)
            if local_path:
                flag = self.analyze_file(local_path)
                if flag:
                    return flag
        
        return None
    
    def enumerate(self):
        """Main SMB enumeration function"""
        print(f"{green('[+]')} 🔍 Starting SMB enumeration on {self.target}")
        
        if not self.check_smbclient():
            return None
        
        # List all shares
        shares = self.list_shares()
        
        # Check each share
        for share in shares:
            print(f"\n{yellow('[*]')} Processing share: {share}")
            
            # Try to download all files
            flag = self.auto_download_all(share)
            if flag:
                return flag
            
            # Try anonymous login
            try:
                result = subprocess.getoutput(f"smbclient //{self.target}/{share} -N -c 'ls' 2>&1")
                if 'NT_STATUS_ACCESS_DENIED' not in result:
                    print(f"{green('[+]')} Anonymous access allowed on {share}")
            except:
                pass
        
        return None


def run_smb_enum(target):
    """Main SMB enumeration entry point"""
    enumerator = SMBEnumerator(target)
    return enumerator.enumerate()


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = run_smb_enum(sys.argv[1])
        if result:
            print(f"\n{red('[🏆]')} Flag found: {green(result)}")
        else:
            print(f"{yellow('[-]')} No flag found")