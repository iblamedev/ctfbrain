import shutil
import os
import subprocess
import tarfile
import zipfile
import gzip
import re
import base64
import tempfile
from core.colors import red, green, yellow, highlight, blue
from core.executor import run_cmd, safe_run_cmd
from core.tools import check_tool

# Universal flag pattern
FLAG_PATTERN = r'[a-zA-Z0-9_]+\{[^}]*\}'

def extract_flag_from_output(output):
    """Extract flag from command output"""
    if not output:
        return None
    
    if not isinstance(output, str):
        output = str(output)
    
    flags = re.findall(FLAG_PATTERN, output)
    if flags:
        return flags[0]
    
    base64_patterns = re.findall(r'[A-Za-z0-9+/=]{20,200}', output)
    for b64 in base64_patterns:
        try:
            padded = b64 + '=' * (-len(b64) % 4)
            decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
            flags = re.findall(FLAG_PATTERN, decoded)
            if flags:
                return flags[0]
        except:
            pass
    
    return None

def analyze_image_with_stegsolve(image_path):
    """Try multiple steganography techniques"""
    results = []
    
    if check_tool("zsteg") and image_path.lower().endswith('.png'):
        print(f"{yellow('[*]')} Running zsteg...")
        result = subprocess.getoutput(f"zsteg -a {image_path}")
        results.append(result)
    
    if check_tool("steghide"):
        print(f"{yellow('[*]')} Trying steghide with empty password...")
        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.getoutput(f"steghide extract -sf {image_path} -p '' -xf {tmpdir}/extracted 2>&1")
            results.append(result)
            
            extracted_file = f"{tmpdir}/extracted"
            if os.path.exists(extracted_file):
                with open(extracted_file, 'r', errors='ignore') as f:
                    content = f.read()
                    results.append(content)
    
    return '\n'.join(results)

def extract_archive(filepath):
    """Extract compressed archives automatically and search for flags"""
    print(f"{green('[+]')} 📦 Archive detected - extracting...")
    
    extract_dir = f"extracted_{os.path.basename(filepath)}"
    os.makedirs(extract_dir, exist_ok=True)
    
    try:
        if filepath.endswith(('.tar.gz', '.tgz', '.tar')):
            print(f"{yellow('[*]')} Extracting tar archive...")
            with tarfile.open(filepath, 'r:*') as tar:
                tar.extractall(extract_dir)
                print(f"{green('[+]')} Extracted to {extract_dir}/")
                
                for root, dirs, files in os.walk(extract_dir):
                    for file in files:
                        full_path = os.path.join(root, file)
                        print(f"{yellow('[*]')} Checking extracted file: {full_path}")
                        
                        try:
                            with open(full_path, 'r', errors='ignore') as f:
                                content = f.read()
                                flag = extract_flag_from_output(content)
                                if flag:
                                    return flag
                        except:
                            if check_tool("strings"):
                                result = subprocess.getoutput(f"strings {full_path}")
                                flag = extract_flag_from_output(result)
                                if flag:
                                    return flag
                return extract_dir
                
        elif filepath.endswith('.zip'):
            print(f"{yellow('[*]')} Extracting zip archive...")
            with zipfile.ZipFile(filepath, 'r') as zipf:
                zipf.extractall(extract_dir)
                print(f"{green('[+]')} Extracted to {extract_dir}/")
                
                for root, dirs, files in os.walk(extract_dir):
                    for file in files:
                        full_path = os.path.join(root, file)
                        print(f"{yellow('[*]')} Checking extracted file: {full_path}")
                        
                        try:
                            with open(full_path, 'r', errors='ignore') as f:
                                content = f.read()
                                flag = extract_flag_from_output(content)
                                if flag:
                                    return flag
                        except:
                            if check_tool("strings"):
                                result = subprocess.getoutput(f"strings {full_path}")
                                flag = extract_flag_from_output(result)
                                if flag:
                                    return flag
                return extract_dir
                
        elif filepath.endswith('.gz') and not filepath.endswith('.tar.gz'):
            print(f"{yellow('[*]')} Extracting gzip file...")
            output_file = filepath[:-3]
            with gzip.open(filepath, 'rb') as f_in:
                with open(output_file, 'wb') as f_out:
                    f_out.write(f_in.read())
            print(f"{green('[+]')} Extracted to {output_file}")
            
            try:
                with open(output_file, 'r', errors='ignore') as f:
                    content = f.read()
                    flag = extract_flag_from_output(content)
                    if flag:
                        return flag
            except:
                if check_tool("strings"):
                    result = subprocess.getoutput(f"strings {output_file}")
                    flag = extract_flag_from_output(result)
                    if flag:
                        return flag
            
            if output_file.endswith('.tar'):
                return extract_archive(output_file)
            
            return None
                
    except Exception as e:
        print(f"{red('[-]')} Extraction failed: {e}")
        return None

def search_directory_for_flags(directory):
    """Recursively search directory for flag files"""
    print(f"{green('[+]')} 🔍 Recursively searching {directory} for flags...")
    
    found_flags = []
    all_files = []
    hidden_files = []
    
    # Walk through all directories
    for root, dirs, files in os.walk(directory):
        # Check for hidden directories
        for d in dirs:
            if d.startswith('.'):
                hidden_dir = os.path.join(root, d)
                print(f"{yellow('[*]')} Found hidden directory: {hidden_dir}")
        
        # Collect all files
        for file in files:
            filepath = os.path.join(root, file)
            all_files.append(filepath)
            
            # Check for hidden files
            if file.startswith('.'):
                hidden_files.append(filepath)
                print(f"{yellow('[*]')} Found hidden file: {filepath}")
    
    print(f"{green('[+]')} Found {len(all_files)} total files to analyze")
    print(f"{green('[+]')} Found {len(hidden_files)} hidden files")
    
    # First check hidden files (more likely to contain flags)
    for filepath in hidden_files:
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
                flag = extract_flag_from_output(content)
                if flag:
                    print(f"{green('[+]')} 🏆 Found flag in hidden file: {filepath}")
                    found_flags.append(flag)
                    return flag  # Return immediately on first find
        except Exception as e:
            # Try strings on binary files
            if check_tool("strings"):
                result = subprocess.getoutput(f"strings {filepath}")
                flag = extract_flag_from_output(result)
                if flag:
                    print(f"{green('[+]')} 🏆 Found flag in hidden file (strings): {filepath}")
                    found_flags.append(flag)
                    return flag
    
    # Then check all other files
    for filepath in all_files:
        if filepath in hidden_files:
            continue  # Already checked
            
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
                flag = extract_flag_from_output(content)
                if flag:
                    print(f"{green('[+]')} 🏆 Found flag in: {filepath}")
                    found_flags.append(flag)
                    return flag
        except Exception as e:
            # Try strings on binary files
            if check_tool("strings") and os.path.getsize(filepath) < 10_000_000:  # Skip huge files
                result = subprocess.getoutput(f"strings {filepath}")
                flag = extract_flag_from_output(result)
                if flag:
                    print(f"{green('[+]')} 🏆 Found flag in (strings): {filepath}")
                    found_flags.append(flag)
                    return flag
    
    # Also check for archived files that might need extraction
    archive_exts = ['.zip', '.tar', '.gz', '.bz2', '.xz']
    for filepath in all_files:
        if any(filepath.endswith(ext) for ext in archive_exts):
            print(f"{yellow('[*]')} Found archive: {filepath} - attempting extraction")
            result = extract_archive(filepath)
            if result and isinstance(result, str):
                flag = extract_flag_from_output(result)
                if flag:
                    return flag
    
    if found_flags:
        return found_flags[0]
    
    print(f"{yellow('[*]')} No flags found in directory search")
    return None

def run_forensics(target):
    """Run forensics analysis and return flag if found"""
    print(f"{green('[+]')} 🔍 Running Forensics pipeline on: {target}")
    
    # Handle directories
    if os.path.isdir(target):
        return search_directory_for_flags(target)
    
    if not os.path.exists(target):
        print(f"{red('[-] File not found.')}")
        return None

    try:
        file_type = subprocess.getoutput(f"file -b {target}")
        file_size = os.path.getsize(target)
        print(f"{green('[+]')} File Type: {file_type}")
        print(f"{green('[+]')} File Size: {file_size} bytes")
    except: 
        file_type = "unknown"

    lower_type = file_type.lower()

    # Check if it's an archive
    is_archive = any(x in lower_type for x in ['archive', 'compressed', 'gzip', 'zip', 'tar']) or \
                 target.endswith(('.tar.gz', '.tgz', '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z'))
    
    if is_archive:
        print(f"\n{blue('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}")
        print(f"{green('[📦]')} Archive detected - extracting...")
        print(f"{blue('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}")
        
        result = extract_archive(target)
        if result and isinstance(result, str):
            flag = extract_flag_from_output(result)
            if flag:
                return flag
        
        print(f"{yellow('[*]')} No flag found in archive contents, continuing...")

    # Metadata check
    if check_tool("exiftool"):
        print(f"\n{blue('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}")
        print(f"{green('[📝]')} Checking metadata...")
        print(f"{blue('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}")
        
        result = subprocess.getoutput(f"exiftool {target}")
        flag = extract_flag_from_output(result)
        if flag:
            return flag

    # Strings check
    if check_tool("strings"):
        print(f"\n{blue('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}")
        print(f"{green('[🔤]')} Checking strings...")
        print(f"{blue('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}")
        
        result = subprocess.getoutput(f"strings -a -n 6 {target}")
        flag = extract_flag_from_output(result)
        if flag:
            return flag

    # Binwalk check
    if check_tool("binwalk"):
        print(f"\n{blue('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}")
        print(f"{green('[📦]')} Checking for embedded files...")
        print(f"{blue('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}")
        
        result = subprocess.getoutput(f"binwalk {target}")
        print(result)
        
        flag = extract_flag_from_output(result)
        if flag:
            return flag

    # Steganography checks
    if "png" in lower_type and check_tool("zsteg"):
        print(f"\n{blue('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}")
        print(f"{green('[🕵️]')} Checking steganography...")
        print(f"{blue('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}")
        
        result = subprocess.getoutput(f"zsteg -a {target}")
        flag = extract_flag_from_output(result)
        if flag:
            return flag
    
    if "jpeg" in lower_type or "jpg" in lower_type:
        if check_tool("steghide"):
            with tempfile.TemporaryDirectory() as tmpdir:
                result = subprocess.getoutput(f"steghide extract -sf {target} -p '' -xf {tmpdir}/extracted 2>&1")
                flag = extract_flag_from_output(result)
                if flag:
                    return flag

    print(f"\n{red('[-]')} Forensics analysis complete - no flag found.")
    return None