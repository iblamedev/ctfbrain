#!/usr/bin/env python3
"""
Session Manager for reverse shells and meterpreter sessions
"""
import os
import subprocess
import time
import threading
import tempfile
from core.colors import red, green, yellow, blue, highlight

class Session:
    def __init__(self, session_id, session_type, target, port):
        self.id = session_id
        self.type = session_type  # 'reverse_shell', 'meterpreter', 'ssh'
        self.target = target
        self.port = port
        self.process = None
        self.active = True
        self.created_at = time.time()
    
    def close(self):
        if self.process:
            self.process.terminate()
        self.active = False

class SessionManager:
    def __init__(self):
        self.sessions = {}
        self.next_id = 1
        self.listeners = {}
    
    def create_listener(self, port, handler_type='reverse_shell'):
        """Start a listener on a port"""
        print(f"{green('[+]')} Starting {handler_type} listener on port {port}...")
        
        if handler_type == 'reverse_shell':
            # Simple netcat listener
            cmd = f"nc -lvnp {port}"
            process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.listeners[port] = {'process': process, 'type': handler_type}
            return process
        
        elif handler_type == 'meterpreter':
            # Use msfconsole
            rc_file = tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False)
            rc_file.write(f"use exploit/multi/handler\n")
            rc_file.write(f"set PAYLOAD linux/x64/shell_reverse_tcp\n")
            rc_file.write(f"set LHOST 0.0.0.0\n")
            rc_file.write(f"set LPORT {port}\n")
            rc_file.write(f"set ExitOnSession false\n")
            rc_file.write(f"exploit -j\n")
            rc_file.close()
            
            cmd = f"msfconsole -q -r {rc_file.name}"
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.listeners[port] = {'process': process, 'type': handler_type, 'rc_file': rc_file.name}
            return process
        
        return None
    
    def add_session(self, session_type, target, port):
        """Add a new session"""
        session = Session(self.next_id, session_type, target, port)
        self.sessions[self.next_id] = session
        self.next_id += 1
        print(f"{green('[+]')} Session {session.id} created ({session_type})")
        return session.id
    
    def list_sessions(self):
        """List all active sessions"""
        if not self.sessions:
            print(f"{yellow('[*]')} No active sessions")
            return
        
        print(f"\n{blue('='*50)}")
        print(f"{green('Active Sessions:')}")
        print(f"{blue('='*50)}")
        for sid, session in self.sessions.items():
            status = 'ACTIVE' if session.active else 'CLOSED'
            uptime = int(time.time() - session.created_at)
            print(f"  {sid}. {session.type} -> {session.target}:{session.port} [{status}] ({uptime}s)")
        print()
    
    def get_session(self, session_id):
        """Get session by ID"""
        return self.sessions.get(session_id)
    
    def close_session(self, session_id):
        """Close a session"""
        if session_id in self.sessions:
            self.sessions[session_id].close()
            print(f"{yellow('[*]')} Session {session_id} closed")
    
    def upload_file(self, session_id, local_path, remote_path):
        """Upload file to session (simplified)"""
        session = self.get_session(session_id)
        if not session:
            print(f"{red('[-]')} Session not found")
            return False
        
        print(f"{green('[+]')} Uploading {local_path} to {remote_path}...")
        # This would need actual implementation based on session type
        return True
    
    def download_file(self, session_id, remote_path, local_path):
        """Download file from session"""
        session = self.get_session(session_id)
        if not session:
            print(f"{red('[-]')} Session not found")
            return False
        
        print(f"{green('[+]')} Downloading {remote_path} to {local_path}...")
        # This would need actual implementation
        return True
    
    def run_command(self, session_id, command):
        """Run command on session"""
        session = self.get_session(session_id)
        if not session:
            print(f"{red('[-]')} Session not found")
            return None
        
        print(f"{yellow('[*]')} Running: {command}")
        # This would need actual implementation
        return None
    
    def cleanup(self):
        """Clean up all listeners and sessions"""
        for port, listener in self.listeners.items():
            if 'process' in listener:
                listener['process'].terminate()
            if 'rc_file' in listener and os.path.exists(listener['rc_file']):
                os.unlink(listener['rc_file'])
        
        for session in self.sessions.values():
            session.close()


# Global session manager
session_manager = SessionManager()


def create_listener(port, handler_type='reverse_shell'):
    return session_manager.create_listener(port, handler_type)

def add_session(session_type, target, port):
    return session_manager.add_session(session_type, target, port)

def list_sessions():
    session_manager.list_sessions()

def cleanup_sessions():
    session_manager.cleanup()


if __name__ == '__main__':
    # Example usage
    import sys
    if len(sys.argv) > 1:
        if sys.argv[1] == 'listen':
            port = int(sys.argv[2]) if len(sys.argv) > 2 else 4444
            create_listener(port)
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                cleanup_sessions()