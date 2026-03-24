# cython: language_level=3

import os
import tomllib
from typing import Dict, List, Any


cdef class Config:
    cdef public list registrars
    cdef public int timeout_seconds
    cdef public str ame_path
    cdef public str origin
    cdef public bint anonymous_read
    cdef public str nav_db_path
    cdef public str reports_db_path
    cdef public str punishments_db_path
    cdef public str log_dir
    
    def __init__(self, registrars: List[str] = None, timeout_seconds: int = 30, ame_path: str = None, origin: str = None, anonymous_read: bool = True, nav_db_path: str = None, reports_db_path: str = None, punishments_db_path: str = None, log_dir: str = None):
        if registrars is None:
            registrars = ["knolastna.me"]
        self.registrars = [r.lower() for r in registrars]
        self.timeout_seconds = timeout_seconds
        if ame_path is None:
            ame_path = "/var/spool/boards"
        self.ame_path = ame_path
        if origin is None:
            origin = "localhost"
        self.origin = origin
        self.anonymous_read = anonymous_read
        if nav_db_path is None:
            nav_db_path = "/var/lib/bonnet/nav.db"
        self.nav_db_path = nav_db_path
        if reports_db_path is None:
            reports_db_path = "/var/lib/bonnet/reports.db"
        self.reports_db_path = reports_db_path
        if punishments_db_path is None:
            punishments_db_path = "/var/lib/bonnet/punishments.db"
        self.punishments_db_path = punishments_db_path
        if log_dir is None:
            log_dir = "/var/log/bonnet"
        self.log_dir = log_dir
    
    @staticmethod
    def load(path: str) -> 'Config':
        if not os.path.exists(path):
            return Config._create_default(path)
        
        with open(path, 'rb') as f:
            data = tomllib.load(f)
        
        registrars = data.get('server', {}).get('registrars', ["knolastna.me"])
        origin = data.get('server', {}).get('origin', "localhost")
        timeout_seconds = data.get('limits', {}).get('timeout_seconds', 30)
        ame_path = data.get('boards', {}).get('path', "/var/spool/boards")
        anonymous_read = data.get('server', {}).get('anonymous_read', True)
        nav_db_path = data.get('server', {}).get('nav_db_path', "/var/lib/bonnet/nav.db")
        reports_db_path = data.get('keibatsu', {}).get('reports_path', "/var/lib/bonnet/reports.db")
        punishments_db_path = data.get('keibatsu', {}).get('punishments_path', "/var/lib/bonnet/punishments.db")
        log_dir = data.get('server', {}).get('log_dir', "/var/log/bonnet")
        
        return Config(registrars=registrars, timeout_seconds=timeout_seconds, ame_path=ame_path, origin=origin, anonymous_read=anonymous_read, nav_db_path=nav_db_path, reports_db_path=reports_db_path, punishments_db_path=punishments_db_path, log_dir=log_dir)
    
    @staticmethod
    def _create_default(path: str) -> 'Config':
        default_content = """[server]
registrars = ["localhost"]
origin = "localhost"
anonymous_read = true
nav_db_path = "/var/lib/bonnet/nav.db"
log_dir = "/var/log/bonnet"

[limits]
timeout_seconds = 30

[boards]
path = "/var/spool/boards"

[keibatsu]
reports_path = "/var/lib/bonnet/reports.db"
punishments_path = "/var/lib/bonnet/punishments.db"
"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        with open(path, 'w') as f:
            f.write(default_content)
        
        os.chmod(path, 0o600)
        
        return Config(registrars=["localhost"], timeout_seconds=30, ame_path="/var/spool/boards", origin="localhost", anonymous_read=True, nav_db_path="/var/lib/bonnet/nav.db", reports_db_path="/var/lib/bonnet/reports.db", punishments_db_path="/var/lib/bonnet/punishments.db", log_dir="/var/log/bonnet")
    
    def registrar_valid(self, registrar: str) -> bool:
        if not registrar:
            return False
        return registrar.lower() in self.registrars
