# cython: language_level=3

import threading
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional

from ume import Ume
from crypto import Identity


class ExportHandler(BaseHTTPRequestHandler):
    ume = None
    server_identity = None
    
    def log_message(self, format, *args):
        pass
    
    def do_GET(self):
        if self.path == '/export':
            self._handle_export()
        else:
            self.send_error(404, "Not Found")
    
    def _handle_export(self):
        cdef list users
        cdef list lines
        cdef object user
        cdef bytes content
        cdef bytes signature
        cdef str sig_b64
        
        try:
            users = self.ume.list_all()
            
            lines = ["username,registrar,public_key"]
            for user in users:
                line = f"{user.username},{user.registrar},{user.publickey.hex()}"
                lines.append(line)
            
            content = "\n".join(lines).encode('utf-8')
            
            signature = self.server_identity.sign(content)
            sig_b64 = base64.b64encode(signature).decode('ascii')
            
            self.send_response(200)
            self.send_header('Content-Type', 'text/csv; charset=utf-8')
            self.send_header('X-Signature', sig_b64)
            self.send_header('Content-Length', len(content))
            self.end_headers()
            self.wfile.write(content)
            
        except Exception as e:
            self.send_error(500, str(e))


cdef class PublicUserServer:
    cdef object http_server
    cdef object thread
    cdef int port
    cdef object ume
    cdef object server_identity
    
    def __init__(self, int port, object ume, object server_identity):
        self.port = port
        self.ume = ume
        self.server_identity = server_identity
        self.http_server = None
        self.thread = None
    
    def start(self):
        ExportHandler.ume = self.ume
        ExportHandler.server_identity = self.server_identity
        
        self.http_server = HTTPServer(('0.0.0.0', self.port), ExportHandler)
        
        self.thread = threading.Thread(target=self.http_server.serve_forever, daemon=True)
        self.thread.start()
    
    def stop(self):
        if self.http_server:
            self.http_server.shutdown()
            self.http_server = None