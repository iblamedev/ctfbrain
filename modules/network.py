import shutil
import os
import subprocess
import re
from core.colors import red, green, yellow, highlight
from core.executor import run_cmd
from core.tools import check_tool, requires_tools

FLAG_PATTERN = r'[a-zA-Z0-9_]+\{[^}]*\}'

def extract_flag_from_output(output):
    """Extract flag from command output"""
    if not output:
        return None
    
    flags = re.findall(FLAG_PATTERN, str(output))
    if flags:
        return flags[0]
    return None

@requires_tools('nmap')
def run_network(target):
    """Run network recon and return flag if found"""
    print(f"{green('[+]')} Running Network Recon on: {target}")

    xml_file = f"nmap_{target.replace('/', '_')}.xml"
    txt_file = f"nmap_{target.replace('/', '_')}.txt"
    
    cmd = f"nmap -Pn -sC -sV -vv --open -T4 {target} -oN {txt_file} -oX {xml_file}"
    scan_output = run_cmd(cmd)
    
    flag = extract_flag_from_output(scan_output)
    if flag:
        return flag

    open_ports = re.findall(r'(\d+)/tcp\s+open\s+(\S+)', scan_output)
    
    for port, service in open_ports:
        print(f"{green('[+]')} Found {service} on port {port}")
        
        try:
            banner = subprocess.getoutput(f"nc -zv {target} {port} 2>&1")
            flag = extract_flag_from_output(banner)
            if flag:
                return flag
        except:
            pass
        
        if service == 'http' or service == 'https' or port in ['80', '443', '8080', '8443']:
            try:
                import requests
                r = requests.get(f"http://{target}:{port}", timeout=5)
                flag = extract_flag_from_output(r.text)
                if flag:
                    return flag
            except:
                pass
        
        elif service == 'ftp' and port == '21':
            result = subprocess.getoutput(f"nmap -Pn -p 21 --script ftp-anon {target}")
            flag = extract_flag_from_output(result)
            if flag:
                return flag
        
        elif service == 'ssh' and port == '22':
            result = subprocess.getoutput(f"nc -zv {target} 22 2>&1")
            flag = extract_flag_from_output(result)
            if flag:
                return flag
        
        elif service == 'smb' and port == '445':
            if check_tool("enum4linux"):
                result = subprocess.getoutput(f"enum4linux -a {target} | grep -i flag")
                flag = extract_flag_from_output(result)
                if flag:
                    return flag

    for port in ['80', '443', '8080', '8000', '8888']:
        try:
            import requests
            r = requests.get(f"http://{target}:{port}", timeout=3)
            flag = extract_flag_from_output(r.text)
            if flag:
                return flag
        except:
            pass

    print(f"\n{green('[+]')} Network analysis complete - no flag found.")
    return None