import re

# ANSI Color Codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
BOLD = "\033[1m"
RESET = "\033[0m"
WHITE_BOLD = "\033[1;37m"

def red(text): return f"{RED}{BOLD}{text}{RESET}"
def green(text): return f"{GREEN}{BOLD}{text}{RESET}"
def yellow(text): return f"{YELLOW}{BOLD}{text}{RESET}"
def blue(text): return f"{BLUE}{BOLD}{text}{RESET}"

def highlight(text):
    """Universal Highlighter - catches ANY flag format: prefix{content}"""
    if not text: return text
    text = re.sub(r"\b([a-zA-Z0-9_]+\{[^}]*\})", f"{RED}{BOLD}\\1{RESET}", text)
    if RED in text:
        return text
    return f"{WHITE_BOLD}{text}{RESET}"

banner_logo = f"""{green(r'''
   ______ ______ ______ ____             _
  / ____//_  __// ____// __ ) _____ __ _(_)____
 / /      / /  / /_   / __  |/ ___// __ `/ / __ \\
/ /___   / /  / __/  / /_/ // /   / /_/ / / / / /
\\____/  /_/  /_/    /_____//_/    \\__,_/_/_/ /_/
''')}"""