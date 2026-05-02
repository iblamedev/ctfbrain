import requests
import re
import urllib.parse
import time
from core.colors import red, green, yellow, highlight
from core.tools import check_tool

FLAG_PATTERN = r'[a-zA-Z0-9_]+\{[^}]*\}'

def normalize_url(target):
    if not target.startswith("http"):
        return "http://" + target
    return target

def extract_flag(text):
    """Find and return flag patterns."""
    flags = re.findall(FLAG_PATTERN, str(text))
    if flags:
        return flags[0]
    return None

def extract_partial_flags(text, source=""):
    """Extract partial flag parts from comments or text"""
    if not text:
        return []
    
    patterns = [
        r'part \d+:?\s*([a-zA-Z0-9_{}]+)',
        r'part of the flag:?\s*([a-zA-Z0-9_{}]+)',
        r'flag part:?\s*([a-zA-Z0-9_{}]+)',
        r'#\s*([a-zA-Z0-9_{}]+)',
        r'//\s*([a-zA-Z0-9_{}]+)',
        r'/\*\s*([a-zA-Z0-9_{}]+)\s*\*/',
        r'<!--\s*([a-zA-Z0-9_{}]+)\s*-->',
    ]
    
    found_parts = []
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            if len(match) > 3 and not match.startswith('http'):
                found_parts.append(match)
                print(f"{yellow('[🔍]')} Found potential flag part in {source}: {highlight(match)}")
    
    return found_parts

def check_common_files(target):
    """Check for common CTF files and return flag if found"""
    common_files = [
        '/robots.txt', '/source', '/src', '/flag', '/admin', 
        '/backup', '/login.php', '/admin.php', '/.git/',
        '/.env', '/phpinfo.php', '/info.php', '/flag.txt',
        '/secret', '/hidden', '/private', '/.hidden',
        '/backup.zip', '/backup.tar', '/www.zip', '/www.tar',
        '/mycss.css', '/myjs.js', '/.htaccess', '/sitemap.xml'
    ]
    
    flag_parts = []
    
    for file in common_files:
        url = target.rstrip('/') + file
        print(f"{yellow('[*]')} Checking {url}...")
        time.sleep(0.2)
        
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                flag = extract_flag(r.text)
                if flag:
                    return flag
                
                parts = extract_partial_flags(r.text, file)
                if parts:
                    flag_parts.extend(parts)
                
                for header, value in r.headers.items():
                    flag = extract_flag(value)
                    if flag:
                        return flag
        except:
            pass
    
    if flag_parts:
        all_text = ' '.join(flag_parts)
        full_flag_pattern = r'(picoCTF\{[^}]+\})'
        match = re.search(full_flag_pattern, all_text)
        if match:
            print(f"\n{red('[🏆 ASSEMBLED FLAG]')} {highlight(match.group(1))}")
            return match.group(1)
    
    return None

def run_web(target):
    """Autonomous web solver - returns flag if found."""
    target = normalize_url(target)
    print(f"{green('[+]')} Running Autonomous Web Solver on: {target}\n")
    
    try:
        r = requests.get(target, timeout=10)
        print(f"{green('[+]')} Initial response code: {r.status_code}")
        
        flag = extract_flag(r.text)
        if flag:
            return flag
        
        for header, value in r.headers.items():
            flag = extract_flag(value)
            if flag:
                return flag
        
        for cookie in r.cookies:
            flag = extract_flag(cookie.value)
            if flag:
                return flag
        
        print(f"{green('[+]')} Checking common files...")
        flag = check_common_files(target)
        if flag:
            return flag
        
        forms = re.findall(r'<form.*?action=["\'](.*?)["\']', r.text)
        if forms:
            print(f"{green('[+]')} Found forms, trying default credentials...")
            credentials = [
                ('admin', 'admin'), ('admin', 'password'), ('admin', 'password123'),
                ('user', 'user'), ('guest', 'guest'), ('root', 'root')
            ]
            
            for form in forms:
                form_url = target + form if form.startswith('/') else form
                for username, password in credentials:
                    try:
                        r = requests.post(form_url, data={'username': username, 'password': password}, timeout=5)
                        flag = extract_flag(r.text)
                        if flag:
                            return flag
                        
                        for cookie in r.cookies:
                            flag = extract_flag(cookie.value)
                            if flag:
                                return flag
                    except:
                        pass
        
        print(f"\n{green('[+]')} Web analysis complete - no flag found.")
        return None
        
    except Exception as e:
        print(f"{red('[-]')} Error: {e}")
        return None