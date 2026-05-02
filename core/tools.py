#!/usr/bin/env python3
"""
Centralized tool management for ctfbrain.
Caches tool locations and provides installation suggestions.
"""
import shutil
import os
import subprocess
from functools import lru_cache
from core.colors import red, green, yellow, blue, RESET

ESSENTIAL_TOOLS = {
    'nmap': 'nmap',
    'strings': 'binutils',
    'exiftool': 'libimage-exiftool-perl',
    'binwalk': 'binwalk',
    'steghide': 'steghide',
    'john': 'john',
}

FORENSICS_TOOLS = {
    'foremost': 'foremost',
    'zsteg': 'ruby-zsteg',
    'stegseek': 'stegseek',
    'sox': 'sox',
    'tshark': 'tshark',
    'capinfos': 'wireshark-common',
    'pdfinfo': 'poppler-utils',
    'pdftotext': 'poppler-utils',
    'pdfimages': 'poppler-utils',
    'fls': 'sleuthkit',
    'volatility': 'volatility3',
    'vol': 'volatility3',
}

BINARY_TOOLS = {
    'checksec': 'checksec',
    'ROPgadget': 'ropgadget',
    'radare2': 'radare2',
    'rabin2': 'radare2',
    'ltrace': 'ltrace',
    'strace': 'strace',
    'objdump': 'binutils',
}

NETWORK_TOOLS = {
    'enum4linux': 'enum4linux',
    'gobuster': 'gobuster',
    'hydra': 'hydra',
    'smbclient': 'smbclient',
    'searchsploit': 'exploitdb',
}

CLOUD_TOOLS = {
    'aws': 'awscli',
    's3scanner': 's3scanner',
}

CRYPTO_TOOLS = {
    'openssl': 'openssl',
    'hashid': 'hashid',
    'RsaCtfTool': 'RsaCtfTool',
}

LANGUAGE_TOOLS = {
    'rustc': 'rustc',
    'cargo': 'cargo',
    'gcc': 'gcc',
    'g++': 'g++',
    'javac': 'openjdk-17-jdk',
    'java': 'openjdk-17-jre',
    'node': 'nodejs',
    'go': 'golang',
    'ruby': 'ruby',
    'php': 'php',
}

TOOL_CACHE = {}

def check_tool(name):
    if name not in TOOL_CACHE:
        TOOL_CACHE[name] = shutil.which(name)
    return TOOL_CACHE[name]

def get_tool_path(name, required=False):
    path = check_tool(name)
    if required and not path:
        raise RuntimeError(f"Required tool '{name}' not found. {get_install_instructions(name)}")
    return path

@lru_cache(maxsize=128)
def get_install_instructions(tool_name):
    tool_map = {}
    tool_map.update(ESSENTIAL_TOOLS)
    tool_map.update(FORENSICS_TOOLS)
    tool_map.update(BINARY_TOOLS)
    tool_map.update(NETWORK_TOOLS)
    tool_map.update(CLOUD_TOOLS)
    tool_map.update(CRYPTO_TOOLS)
    tool_map.update(LANGUAGE_TOOLS)
    
    package = tool_map.get(tool_name, tool_name)
    
    if os.path.exists('/etc/debian_version'):
        if tool_name == 'zsteg':
            return "sudo gem install zsteg"
        elif tool_name == 'RsaCtfTool':
            return "git clone https://github.com/RsaCtfTool/RsaCtfTool.git && cd RsaCtfTool && pip install -r requirements.txt"
        elif tool_name in ['volatility', 'vol']:
            return "pip install volatility3"
        elif tool_name in ['rustc', 'cargo']:
            return "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        else:
            return f"sudo apt install -y {package}"
    elif os.path.exists('/etc/arch-release'):
        return f"sudo pacman -S {package}"
    elif os.path.exists('/etc/redhat-release'):
        return f"sudo yum install -y {package}"
    else:
        return f"Please install '{tool_name}' manually"

def verify_essential_tools():
    missing = []
    for tool in ESSENTIAL_TOOLS:
        if not check_tool(tool):
            missing.append(tool)
    if missing:
        print("\n[!] Some essential tools are missing:")
        for tool in missing:
            print(f"    - {tool}: {get_install_instructions(tool)}")
        print()
        return False
    return True

def check_python_module(module_name, package_name=None):
    if package_name is None:
        package_name = module_name
    try:
        __import__(module_name)
        return True
    except ImportError:
        return False

def get_pip_instructions(package_name):
    return f"pip install {package_name}"

def requires_tools(*tools):
    def decorator(func):
        def wrapper(*args, **kwargs):
            missing = []
            for tool in tools:
                if not check_tool(tool):
                    missing.append(tool)
            if missing:
                print(f"\n[!] Cannot run {func.__name__}: Missing tools:")
                for tool in missing:
                    print(f"    - {tool}: {get_install_instructions(tool)}")
                return None
            return func(*args, **kwargs)
        return wrapper
    return decorator

def check_compiler(language):
    compilers = {
        'rust': ['rustc', 'cargo'],
        'python': ['python3'],
        'c': ['gcc'],
        'cpp': ['g++'],
        'java': ['javac', 'java'],
        'javascript': ['node'],
        'go': ['go'],
        'ruby': ['ruby'],
        'php': ['php'],
    }
    if language in compilers:
        missing = []
        for tool in compilers[language]:
            if not check_tool(tool):
                missing.append(tool)
        if missing:
            print(f"\n{yellow('[!]')} Missing {language} compiler(s):")
            for tool in missing:
                print(f"    - {tool}: {get_install_instructions(tool)}")
            return False
        return True
    return False