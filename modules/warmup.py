#!/usr/bin/env python3
"""
Warmup/General Skills Module for CTF
Handles: SSH, netcat, math challenges, Python REPL, etc.
"""
import os
import re
import socket
import telnetlib3
import time
import subprocess
from core.colors import red, green, yellow, blue, highlight
from core.tools import check_tool

FLAG_PATTERN = r'[a-zA-Z0-9_]+\{[^}]*\}'

class WarmupSolver:
    def __init__(self):
        self.found_flags = []
    
    def extract_flag(self, text):
        if not text:
            return None
        if not isinstance(text, str):
            text = str(text)
        flags = re.findall(FLAG_PATTERN, text)
        if flags:
            return flags[0]
        return None
    
    def solve_ssh(self, host, port, username=None, password=None):
        """Connect to SSH and look for flags"""
        print(f"{green('[+]')} Connecting to SSH {host}:{port}")
        
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if username and password:
                try:
                    client.connect(host, port=port, username=username, password=password, timeout=10)
                    
                    # Get banner
                    transport = client.get_transport()
                    if transport and hasattr(transport, 'banner'):
                        banner = transport.banner
                        flag = self.extract_flag(banner)
                        if flag:
                            client.close()
                            return flag
                    
                    # Run common commands
                    commands = [
                        'ls -la', 'cat flag.txt', 'cat .flag', 'env', 'pwd', 'id',
                        'cat *flag*', 'grep -r "pico" .', 'find . -name "*flag*" -exec cat {} \\;'
                    ]
                    for cmd in commands:
                        try:
                            stdin, stdout, stderr = client.exec_command(cmd, timeout=5)
                            output = stdout.read().decode() + stderr.read().decode()
                            flag = self.extract_flag(output)
                            if flag:
                                client.close()
                                return flag
                        except:
                            pass
                    
                    client.close()
                except Exception as e:
                    print(f"{yellow('[*]')} SSH connection failed: {e}")
            else:
                print(f"{yellow('[*]')} No credentials provided")
        except ImportError:
            print(f"{yellow('[*]')} paramiko not installed, try: pip install paramiko")
        
        return None
    
    def solve_netcat(self, host, port):
        """Connect to netcat service and grab banner"""
        print(f"{green('[+]')} Connecting to {host}:{port} via netcat")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            data = sock.recv(4096).decode(errors='ignore')
            flag = self.extract_flag(data)
            if flag:
                sock.close()
                return flag
            
            commands = ['\n', 'help\n', 'ls\n', 'flag\n', 'cat flag.txt\n', 'echo test\n', 'id\n', 'pwd\n']
            for cmd in commands:
                try:
                    sock.send(cmd.encode())
                    time.sleep(0.5)
                    data = sock.recv(4096).decode(errors='ignore')
                    flag = self.extract_flag(data)
                    if flag:
                        sock.close()
                        return flag
                except:
                    pass
            
            sock.close()
        except Exception as e:
            print(f"{yellow('[*]')} Netcat connection failed: {e}")
        return None
    
    def solve_telnet(self, host, port):
        """Connect to telnet service"""
        try:
            tn = telnetlib3.open_connection(host, port, timeout=5)
            data = tn.read_some().decode(errors='ignore')
            flag = self.extract_flag(data)
            tn.close()
            if flag:
                return flag
        except:
            pass
        return None
    
    def solve_python_repl(self, host, port):
        """Solve Python REPL challenges"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            sock.recv(4096)
            
            commands = [
                '__import__("os").system("cat flag.txt")\n',
                'print(open("flag.txt").read())\n',
                'import subprocess; subprocess.run(["cat", "flag.txt"])\n',
                'open("flag.txt").read()\n',
                'exec("import os; os.system(\'cat flag.txt\')")\n',
                'exit()\n'
            ]
            
            for cmd in commands:
                try:
                    sock.send(cmd.encode())
                    time.sleep(1)
                    data = sock.recv(8192).decode(errors='ignore')
                    flag = self.extract_flag(data)
                    if flag:
                        sock.close()
                        return flag
                except:
                    pass
            sock.close()
        except:
            pass
        return None
    
    def solve_math_challenge(self, host, port):
        """Solve math challenges (100 calculations)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            
            data = sock.recv(1024).decode()
            print(f"{yellow('[*]')} Received: {data.strip()}")
            
            for i in range(100):
                problem_match = re.search(r'(\d+)\s*([+\-*/])\s*(\d+)', data)
                if not problem_match:
                    break
                
                a, op, b = problem_match.groups()
                a, b = int(a), int(b)
                
                if op == '+': result = a + b
                elif op == '-': result = a - b
                elif op == '*': result = a * b
                elif op == '/': result = a // b
                
                sock.send(f"{result}\n".encode())
                data = sock.recv(1024).decode()
                
                flag = self.extract_flag(data)
                if flag:
                    sock.close()
                    return flag
                
                if 'correct' in data.lower():
                    print(f"{green('[+]')} Solved {i+1}/100")
            
            sock.close()
        except:
            pass
        return None
    
    def solve_websocket(self, host, port, path="/"):
        """Connect to websocket"""
        try:
            import websocket
            ws = websocket.create_connection(f"ws://{host}:{port}{path}")
            data = ws.recv()
            flag = self.extract_flag(data)
            ws.close()
            if flag:
                return flag
        except ImportError:
            print(f"{yellow('[*]')} websocket-client not installed")
        except:
            pass
        return None
    
    def solve_bash_restricted(self, host, port):
        """Solve restricted bash shells"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            data = sock.recv(4096).decode()
            flag = self.extract_flag(data)
            if flag:
                sock.close()
                return flag
            
            commands = [
                'ls\n', 'cat flag.txt\n', 'cat ./*\n', 'echo *\n',
                '${PATH:0:1}cat flag.txt\n', '/bin/cat flag.txt\n',
                'python3 -c "import os; os.system(\'cat flag.txt\')"\n'
            ]
            
            for cmd in commands:
                try:
                    sock.send(cmd.encode())
                    time.sleep(1)
                    data = sock.recv(4096).decode()
                    flag = self.extract_flag(data)
                    if flag:
                        sock.close()
                        return flag
                except:
                    pass
            
            sock.close()
        except:
            pass
        return None
    
    def auto_solve(self, host, port, **kwargs):
        """Automatically try all methods"""
        print(f"{green('[+]')} Auto-solving warmup challenge on {host}:{port}")
        
        methods = [
            ('netcat', self.solve_netcat),
            ('telnet', self.solve_telnet),
            ('python', self.solve_python_repl),
            ('math', self.solve_math_challenge),
            ('bash', self.solve_bash_restricted),
            ('websocket', self.solve_websocket)
        ]
        
        for name, method in methods:
            print(f"{yellow('[*]')} Trying {name}...")
            result = method(host, port)
            if result:
                return result
        
        if kwargs.get('username') or kwargs.get('password'):
            print(f"{yellow('[*]')} Trying SSH...")
            result = self.solve_ssh(host, port, kwargs.get('username'), kwargs.get('password'))
            if result:
                return result
        
        return None


def run_warmup(target, username=None, password=None, mode=None):
    """Main warmup solver entry point"""
    solver = WarmupSolver()
    
    if ':' in target:
        parts = target.split(':')
        if len(parts) == 2 and parts[1].isdigit():
            host = parts[0]
            port = int(parts[1])
        else:
            host = target
            port = 22
    else:
        host = target
        port = 22
    
    if mode == 'ssh':
        return solver.solve_ssh(host, port, username, password)
    elif mode == 'netcat':
        return solver.solve_netcat(host, port)
    elif mode == 'telnet':
        return solver.solve_telnet(host, port)
    elif mode == 'python':
        return solver.solve_python_repl(host, port)
    elif mode == 'math':
        return solver.solve_math_challenge(host, port)
    elif mode == 'websocket':
        return solver.solve_websocket(host, port)
    elif mode == 'bash':
        return solver.solve_bash_restricted(host, port)
    
    return solver.auto_solve(host, port, username=username, password=password)


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        username = sys.argv[2] if len(sys.argv) > 2 else None
        password = sys.argv[3] if len(sys.argv) > 3 else None
        result = run_warmup(target, username, password)
        if result:
            print(f"\n{red('[🏆]')} Flag found: {green(result)}")
        else:
            print(f"{yellow('[-]')} No flag found")