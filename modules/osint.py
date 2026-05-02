#!/usr/bin/env python3
"""
OSINT Module for CTF
Handles: Social media recon, metadata analysis, google dorks, whois, etc.
"""
import os
import re
import subprocess
import requests
import json
from core.colors import red, green, yellow, blue, highlight
from core.tools import check_tool

FLAG_PATTERN = r'[a-zA-Z0-9_]+\{[^}]*\}'

class OSINTSolver:
    def __init__(self):
        self.found_flags = []
    
    def extract_flag(self, text):
        if not text:
            return None
        flags = re.findall(FLAG_PATTERN, str(text))
        if flags:
            return flags[0]
        return None
    
    def check_website(self, url):
        """Check website for hidden info"""
        print(f"{green('[+]')} Checking website: {url}")
        
        try:
            r = requests.get(url, timeout=10)
            
            flag = self.extract_flag(r.text)
            if flag:
                return flag
            
            for header, value in r.headers.items():
                flag = self.extract_flag(value)
                if flag:
                    return flag
            
            for cookie in r.cookies:
                flag = self.extract_flag(cookie.value)
                if flag:
                    return flag
            
            comments = re.findall(r'<!--(.*?)-->', r.text, re.DOTALL)
            for comment in comments:
                flag = self.extract_flag(comment)
                if flag:
                    return flag
            
            hidden = re.findall(r'<input[^>]*type="hidden"[^>]*value="([^"]*)"', r.text)
            for value in hidden:
                flag = self.extract_flag(value)
                if flag:
                    return flag
        
        except Exception as e:
            print(f"{yellow('[*]')} Website check failed: {e}")
        
        return None
    
    def check_robots(self, url):
        """Check robots.txt"""
        try:
            r = requests.get(f"{url.rstrip('/')}/robots.txt", timeout=5)
            if r.status_code == 200:
                print(f"{green('[+]')} Found robots.txt")
                flag = self.extract_flag(r.text)
                if flag:
                    return flag
                
                for line in r.text.split('\n'):
                    if 'Disallow:' in line:
                        path = line.split(':')[1].strip()
                        if path:
                            print(f"{yellow('[*]')} Found disallowed path: {path}")
        except:
            pass
        return None
    
    def check_sitemap(self, url):
        """Check sitemap.xml"""
        try:
            r = requests.get(f"{url.rstrip('/')}/sitemap.xml", timeout=5)
            if r.status_code == 200:
                print(f"{green('[+]')} Found sitemap.xml")
                flag = self.extract_flag(r.text)
                if flag:
                    return flag
        except:
            pass
        return None
    
    def check_git(self, url):
        """Check for exposed .git folder"""
        try:
            r = requests.get(f"{url.rstrip('/')}/.git/HEAD", timeout=5)
            if r.status_code == 200 and 'ref:' in r.text:
                print(f"{green('[+]')} Found exposed .git repository!")
                flag = self.extract_flag(r.text)
                if flag:
                    return flag
        except:
            pass
        return None
    
    def check_env(self, url):
        """Check for .env file"""
        try:
            r = requests.get(f"{url.rstrip('/')}/.env", timeout=5)
            if r.status_code == 200:
                print(f"{green('[+]')} Found .env file")
                flag = self.extract_flag(r.text)
                if flag:
                    return flag
        except:
            pass
        return None
    
    def check_backup(self, url):
        """Check for backup files"""
        backups = ['backup.zip', 'backup.tar', 'backup.tar.gz', 'www.zip', 'www.tar', 'site.zip']
        for backup in backups:
            try:
                r = requests.get(f"{url.rstrip('/')}/{backup}", timeout=5)
                if r.status_code == 200:
                    print(f"{green('[+]')} Found backup file: {backup}")
                    with open(backup, 'wb') as f:
                        f.write(r.content)
                    print(f"{yellow('[*]')} Downloaded {backup}")
                    
                    if backup.endswith('.zip'):
                        subprocess.run(f"unzip -o {backup} -d extracted_{backup}", shell=True)
                    else:
                        subprocess.run(f"tar -xf {backup} -C extracted_{backup}", shell=True)
                    
                    if os.path.exists(f"extracted_{backup}"):
                        for root, dirs, files in os.walk(f"extracted_{backup}"):
                            for file in files:
                                filepath = os.path.join(root, file)
                                try:
                                    with open(filepath, 'r', errors='ignore') as f:
                                        content = f.read()
                                        flag = self.extract_flag(content)
                                        if flag:
                                            return flag
                                except:
                                    pass
            except:
                pass
        return None
    
    def check_social(self, username):
        """Check social media for username"""
        sites = [
            f"https://twitter.com/{username}",
            f"https://github.com/{username}",
            f"https://instagram.com/{username}",
            f"https://linkedin.com/in/{username}",
            f"https://facebook.com/{username}"
        ]
        
        for site in sites:
            try:
                r = requests.get(site, timeout=5)
                if r.status_code == 200:
                    print(f"{green('[+]')} Found profile: {site}")
                    flag = self.extract_flag(r.text)
                    if flag:
                        return flag
            except:
                pass
        return None
    
    def check_whois(self, domain):
        """Check whois information"""
        if not check_tool("whois"):
            return None
        
        try:
            result = subprocess.getoutput(f"whois {domain}")
            flag = self.extract_flag(result)
            if flag:
                return flag
        except:
            pass
        return None
    
    def check_dns(self, domain):
        """Check DNS records"""
        record_types = ['A', 'MX', 'TXT', 'NS', 'CNAME']
        
        for record in record_types:
            try:
                result = subprocess.getoutput(f"dig {domain} {record}")
                flag = self.extract_flag(result)
                if flag:
                    return flag
            except:
                pass
        return None
    
    def solve_osint(self, target):
        """Main OSINT solver"""
        print(f"{green('[+]')} Running OSINT on: {target}")
        
        if target.startswith(('http://', 'https://')):
            methods = [
                ('website', self.check_website),
                ('robots', self.check_robots),
                ('sitemap', self.check_sitemap),
                ('git', self.check_git),
                ('env', self.check_env),
                ('backup', self.check_backup)
            ]
            
            for name, method in methods:
                print(f"\n{yellow('[*]')} Checking {name}...")
                result = method(target)
                if result:
                    return result
        
        elif '.' in target and ' ' not in target:
            domain = target.split('/')[0]
            methods = [
                ('whois', self.check_whois),
                ('dns', self.check_dns)
            ]
            
            for name, method in methods:
                print(f"\n{yellow('[*]')} Checking {name}...")
                result = method(domain)
                if result:
                    return result
        
        else:
            result = self.check_social(target)
            if result:
                return result
        
        return None


def run_osint(target):
    """Main OSINT entry point"""
    solver = OSINTSolver()
    return solver.solve_osint(target)


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = run_osint(sys.argv[1])
        if result:
            print(f"\n{red('[🏆]')} Flag found: {green(result)}")
        else:
            print(f"{yellow('[-]')} No flag found")