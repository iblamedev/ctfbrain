from core.colors import red, green, yellow, blue, RESET
from core.suggestions import suggest_web, suggest_crypto, suggest_forensics, suggest_binary, suggest_network

# Core modules
from modules.web import run_web
from modules.crypto import run_crypto
from modules.forensics import run_forensics
from modules.binary import run_binary
from modules.network import run_network
from modules.privesc import run_privesc
from modules.cloud import run_cloud

# Optional modules

try:
    from modules.password_cracker import run_password_cracker
    PASSWORD_CRACKER_AVAILABLE = True
except ImportError:
    PASSWORD_CRACKER_AVAILABLE = False

try:
    from modules.warmup import run_warmup
    WARMUP_AVAILABLE = True
except ImportError:
    WARMUP_AVAILABLE = False

try:
    from modules.stego import run_stego
    STEGO_AVAILABLE = True
except ImportError:
    STEGO_AVAILABLE = False

try:
    from modules.reverse import run_reverse
    REVERSE_AVAILABLE = True
except ImportError:
    REVERSE_AVAILABLE = False

try:
    from modules.osint import run_osint
    OSINT_AVAILABLE = True
except ImportError:
    OSINT_AVAILABLE = False

try:
    from modules.misc import run_misc
    MISC_AVAILABLE = True
except ImportError:
    MISC_AVAILABLE = False

try:
    from modules.git import run_git
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False

try:
    from modules.burp import run_burp
    BURP_AVAILABLE = True
except ImportError:
    BURP_AVAILABLE = False

try:
    from modules.interactive import run_interactive
    INTERACTIVE_AVAILABLE = True
except ImportError:
    INTERACTIVE_AVAILABLE = False

try:
    from modules.syntax_fixer import fix_syntax
    SYNTAX_FIXER_AVAILABLE = True
except ImportError:
    SYNTAX_FIXER_AVAILABLE = False

# New modules
try:
    from modules.smb_enum import run_smb_enum
    SMB_AVAILABLE = True
except ImportError:
    SMB_AVAILABLE = False

try:
    from modules.wpscan_integration import run_wpscan
    WPSCAN_AVAILABLE = True
except ImportError:
    WPSCAN_AVAILABLE = False

try:
    from modules.privesc_auto import run_privesc_auto
    PRIVESC_AUTO_AVAILABLE = True
except ImportError:
    PRIVESC_AUTO_AVAILABLE = False

try:
    from modules.ghidra_analyzer import run_binary_analyzer
    GHIDRA_AVAILABLE = True
except ImportError:
    GHIDRA_AVAILABLE = False

def dispatch(category, target, **kwargs):
    """Route to appropriate module based on category"""
    
    if category == "web":
        result = run_web(target)
        suggest_web(target)
        return result
        
    elif category == "crypto":
        result = run_crypto(target)
        suggest_crypto(target)
        return result
        
    elif category == "forensics":
        result = run_forensics(target)
        suggest_forensics(target)
        return result
        
    elif category == "binary":
        result = run_binary(target)
        suggest_binary(target)
        return result
        
    elif category == "network":
        result = run_network(target)
        suggest_network(target)
        return result
        
    elif category == "privesc":
        result = run_privesc(target)
        return result
        
    elif category == "cloud":
        result = run_cloud(target)
        return result
        
    elif category == "warmup":
        if WARMUP_AVAILABLE:
            return run_warmup(target, **kwargs)
        else:
            print(f"{yellow('[!]')} Warmup module not available")
            return None
        
    elif category == "stego":
        if STEGO_AVAILABLE:
            return run_stego(target)
        else:
            print(f"{yellow('[!]')} Steganography module not available")
            return None
        
    elif category == "reverse":
        if REVERSE_AVAILABLE:
            return run_reverse(target)
        else:
            print(f"{yellow('[!]')} Reverse engineering module not available")
            return None
        
    elif category == "osint":
        if OSINT_AVAILABLE:
            return run_osint(target)
        else:
            print(f"{yellow('[!]')} OSINT module not available")
            return None
        
    elif category == "misc":
        if MISC_AVAILABLE:
            return run_misc(target)
        else:
            print(f"{yellow('[!]')} Misc module not available")
            return None
        
    elif category == "password":
        if PASSWORD_CRACKER_AVAILABLE:
            return run_password_cracker(target)
        else:
            print(f"{yellow('[!]')} Password cracker module not available")
            return None
        
    elif category == "git":
        if GIT_AVAILABLE:
            return run_git(target)
        else:
            print(f"{yellow('[!]')} Git module not available")
            return None
        
    elif category == "burp":
        if BURP_AVAILABLE:
            return run_burp(target)
        else:
            print(f"{yellow('[!]')} Burp/web pentest module not available")
            return None
        
    elif category == "interactive":
        if INTERACTIVE_AVAILABLE:
            return run_interactive(target)
        else:
            print(f"{yellow('[!]')} Interactive module not available")
            return None
            
    elif category == "syntax":
        if SYNTAX_FIXER_AVAILABLE:
            return fix_syntax(code=target, run=True)
        else:
            print(f"{yellow('[!]')} Syntax fixer module not available")
            return None
            
    # New module dispatches
    elif category == "smb":
        if SMB_AVAILABLE:
            return run_smb_enum(target)
        else:
            print(f"{yellow('[!]')} SMB enumeration module not available")
            return None
            
    elif category == "wpscan":
        if WPSCAN_AVAILABLE:
            return run_wpscan(target)
        else:
            print(f"{yellow('[!]')} WordPress scanner module not available")
            return None
            
    elif category == "privesc_auto":
        if PRIVESC_AUTO_AVAILABLE:
            return run_privesc_auto(target)
        else:
            print(f"{yellow('[!]')} Privilege escalation module not available")
            return None
            
    elif category == "ghidra":
        if GHIDRA_AVAILABLE:
            return run_binary_analyzer(target)
        else:
            print(f"{yellow('[!]')} Ghidra analyzer module not available")
            return None
            
    else:
        print(f"{red('[-]')} Unknown category: {category}")
        return None