import subprocess
import shlex
import os
import signal
import time
from core.colors import red, yellow, highlight

def run_cmd(cmd, timeout=None, shell=True, live_output=True):
    """
    Centralized command execution with live output and timeout support.
    
    Args:
        cmd (str): Command to execute
        timeout (int): Timeout in seconds
        shell (bool): Use shell (True) or not (False)
        live_output (bool): Print output in real-time
    
    Returns:
        str: Command output
    """
    print(f"\n{yellow('[>]')} {cmd}")
    
    try:
        if shell:
            process = subprocess.Popen(
                cmd, shell=True, stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, text=True, 
                preexec_fn=os.setsid  # Create process group for timeout
            )
        else:
            args = shlex.split(cmd)
            process = subprocess.Popen(
                args, stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, text=True,
                preexec_fn=os.setsid
            )
        
        full_output = ""
        start_time = time.time()
        
        while True:
            # Check timeout
            if timeout and (time.time() - start_time) > timeout:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                print(f"{red('[!]')} Command timed out after {timeout}s")
                return full_output
            
            # Read output
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
                
            if line:
                l = line.strip()
                # Highlight interesting patterns
                if "open" in l and "/tcp" in l:
                    print(highlight(l))
                elif "flag" in l.lower() or "pico" in l.lower():
                    print(highlight(l))
                elif "error" in l.lower() or "fail" in l.lower():
                    print(f"{red(l)}")
                elif live_output:
                    print(l)
                full_output += line
        
        return full_output
        
    except Exception as e:
        print(f"{red('[!] Error:')} {e}")
        return ""

def run_cmd_safe(cmd, args=None, timeout=30):
    """
    Safer version with shell=False and escaped arguments.
    Returns output as string.
    
    Args:
        cmd (str): Command to execute
        args (list): List of arguments
        timeout (int): Timeout in seconds
    
    Returns:
        str: Command output
    """
    try:
        if args:
            # Convert args to strings and escape
            cmd_list = [cmd] + [shlex.quote(str(arg)) for arg in args]
        else:
            cmd_list = shlex.split(cmd)
        
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        return result.stdout + result.stderr
        
    except subprocess.TimeoutExpired:
        return f"{red('[!]')} Command timed out after {timeout}s"
    except Exception as e:
        return f"{red('[!] Error:')} {e}"

def safe_run_cmd(cmd, timeout=30):
    """
    Run command and handle binary output safely.
    Useful for PCAP analysis and binary data.
    
    Args:
        cmd (str): Command to execute
        timeout (int): Timeout in seconds
    
    Returns:
        str: Decoded output (with fallback encodings)
    """
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=False,  # Get raw bytes
            timeout=timeout,
            check=False
        )
        
        # Try to decode with multiple encodings
        for encoding in ['utf-8', 'latin-1', 'cp1252', 'ascii']:
            try:
                output = result.stdout.decode(encoding, errors='replace')
                if output and any(c.isprintable() for c in output[:100]):
                    return output
            except:
                pass
        
        # Fallback: return raw hex
        return result.stdout.hex() if result.stdout else ""
        
    except subprocess.TimeoutExpired:
        return f"{red('[!]')} Command timed out after {timeout}s"
    except Exception as e:
        return f"{red('[!] Error:')} {e}"

def run_with_pipe(cmd, input_data, timeout=30):
    """
    Run command with piped input.
    
    Args:
        cmd (str): Command to execute
        input_data (str): Data to pipe to command
        timeout (int): Timeout in seconds
    
    Returns:
        str: Command output
    """
    print(f"\n{yellow('[>]')} echo '...' | {cmd}")
    
    try:
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate(input=input_data, timeout=timeout)
        return stdout + stderr
        
    except subprocess.TimeoutExpired:
        process.kill()
        return f"{red('[!]')} Command timed out after {timeout}s"
    except Exception as e:
        return f"{red('[!] Error:')} {e}"

def run_background(cmd, output_file=None):
    """
    Run command in background and optionally save output to file.
    
    Args:
        cmd (str): Command to execute
        output_file (str): File to save output
    
    Returns:
        subprocess.Popen: Process object
    """
    print(f"\n{yellow('[>]')} {cmd} (background)")
    
    try:
        if output_file:
            with open(output_file, 'w') as f:
                process = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=f,
                    stderr=subprocess.STDOUT,
                    text=True
                )
        else:
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        
        return process
        
    except Exception as e:
        print(f"{red('[!] Error:')} {e}")
        return None

def check_process_running(process):
    """Check if a background process is still running"""
    if process is None:
        return False
    return process.poll() is None

def stop_process(process):
    """Stop a background process gracefully"""
    if process is None:
        return
    
    try:
        process.terminate()
        time.sleep(1)
        if process.poll() is None:
            process.kill()
    except:
        pass

def run_parallel(commands, max_parallel=4, timeout=60):
    """
    Run multiple commands in parallel.
    
    Args:
        commands (list): List of command strings
        max_parallel (int): Maximum parallel processes
        timeout (int): Timeout per command
    
    Returns:
        dict: Command outputs keyed by command
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    results = {}
    
    def run_single(cmd):
        return cmd, run_cmd_safe(cmd, timeout=timeout)
    
    with ThreadPoolExecutor(max_workers=max_parallel) as executor:
        futures = [executor.submit(run_single, cmd) for cmd in commands]
        
        for future in as_completed(futures):
            try:
                cmd, output = future.result(timeout=timeout)
                results[cmd] = output
            except Exception as e:
                results[cmd] = f"Error: {e}"
    
    return results

def interactive_shell(process):
    """
    Interact with a running process (like a reverse shell).
    
    Args:
        process: subprocess.Popen object
    """
    import sys
    import select
    
    print(f"{yellow('[!]')} Entering interactive shell. Type 'exit' to quit.")
    
    try:
        while True:
            # Check if process is still running
            if process.poll() is not None:
                print(f"{red('[!]')} Process terminated")
                break
            
            # Check for output
            reads = [process.stdout, sys.stdin]
            ready, _, _ = select.select(reads, [], [], 0.1)
            
            for fd in ready:
                if fd == process.stdout:
                    line = process.stdout.readline()
                    if not line:
                        print(f"{red('[!]')} Connection closed")
                        return
                    print(line, end='')
                
                if fd == sys.stdin:
                    cmd = sys.stdin.readline()
                    if cmd.lower().strip() == 'exit':
                        return
                    process.stdin.write(cmd)
                    process.stdin.flush()
                    
    except KeyboardInterrupt:
        print(f"\n{yellow('[!]')} Interactive shell interrupted")
    except Exception as e:
        print(f"{red('[!] Error:')} {e}")

# Export commonly used functions
__all__ = [
    'run_cmd',
    'run_cmd_safe',
    'safe_run_cmd',
    'run_with_pipe',
    'run_background',
    'check_process_running',
    'stop_process',
    'run_parallel',
    'interactive_shell'
]