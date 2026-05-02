# core/__init__.py
"""
ctfbrain core modules
"""
from .colors import *
from .detector import detect
from .dispatcher import dispatch
from .executor import run_cmd, run_cmd_safe, safe_run_cmd
from .suggestions import *
from .tools import *
from .exploit_db import search_exploits
from .session_manager import create_listener, add_session, list_sessions, cleanup_sessions

__all__ = [
    'detect',
    'dispatch',
    'run_cmd',
    'run_cmd_safe',
    'safe_run_cmd',
    'search_exploits',
    'create_listener',
    'add_session',
    'list_sessions',
    'cleanup_sessions',
]