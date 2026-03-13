# cython: language_level=3

import os
import tomllib
from typing import Dict, List, Any


cdef class Config:
    cdef public list registrars
    cdef public int timeout_seconds
    cdef public bint http_enabled
    cdef public int http_port
    cdef public str ame_path
    
    def __init__(self, registrars: List[str] = None, timeout_seconds: int = 30, http_enabled: bool = True, http_port: int = 8000, ame_path: str = None):
        if registrars is None:
            registrars = ["knolastna.me"]
        self.registrars = [r.lower() for r in registrars]
        self.timeout_seconds = timeout_seconds
        self.http_enabled = http_enabled
        self.http_port = http_port
        if ame_path is None:
            ame_path = os.path.expanduser("~/.config/bonnet/boards")
        self.ame_path = ame_path
    
    @staticmethod
    def load(path: str) -> 'Config':
        if not os.path.exists(path):
            return Config._create_default(path)
        
        with open(path, 'rb') as f:
            data = tomllib.load(f)
        
        registrars = data.get('server', {}).get('registrars', ["knolastna.me"])
        timeout_seconds = data.get('limits', {}).get('timeout_seconds', 30)
        http_enabled = data.get('http', {}).get('enabled', True)
        http_port = data.get('http', {}).get('port', 8000)
        ame_path = data.get('boards', {}).get('path', os.path.expanduser("~/.config/bonnet/boards"))
        
        return Config(registrars=registrars, timeout_seconds=timeout_seconds, http_enabled=http_enabled, http_port=http_port, ame_path=ame_path)
    
    @staticmethod
    def _create_default(path: str) -> 'Config':
        default_content = """[server]
registrars = ["localhost"]

[limits]
timeout_seconds = 30

[http]
enabled = true
port = 8000

[boards]
path = "~/.config/bonnet/boards"
"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        with open(path, 'w') as f:
            f.write(default_content)
        
        os.chmod(path, 0o600)
        
        return Config(registrars=["localhost"], timeout_seconds=30, http_enabled=True, http_port=8000, ame_path=os.path.expanduser("~/.config/bonnet/boards"))
    
    def registrar_valid(self, registrar: str) -> bool:
        if not registrar:
            return False
        return registrar.lower() in self.registrars
