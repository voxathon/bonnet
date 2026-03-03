import sys
import os
import socket
import selectors
import struct
import base64
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) or '.')
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'build'))

from ume import Ume, User
from iixp import accept, Session, FRAME_APP_DATA, FRAME_CLOSE
import nacl.signing

PORT_PRIVILEGED = 272
PORT_STANDARD = 2272

cdef class ClientState:
    cdef public int state
    cdef public object session
    cdef public bytes recv_buf
    cdef public object user
    cdef public list candidates
    
    def __init__(self, int state=0):
        self.state = state
        self.session = None
        self.recv_buf = b''
        self.user = None
        self.candidates = None
    
    STATE_HANDSHAKE = 0
    STATE_IDENTITY_WAIT = 1
    STATE_READY = 2
    STATE_CLOSING = 3

cdef class BonnetServer:
    cdef object selector
    cdef object listen_sock
    cdef object ume
    cdef object server_identity
    cdef dict clients
    cdef int running
    
    def __init__(self, str userfile_path, str identity_path, int port):
        self.selector = selectors.DefaultSelector()
        self.ume = Ume(userfile_path)
        self.clients = {}
        self.running = 1
        
        with open(identity_path, 'rb') as f:
            key_bytes = f.read()
        if len(key_bytes) == 32:
            self.server_identity = nacl.signing.SigningKey(key_bytes)
        else:
            self.server_identity = nacl.signing.SigningKey(key_bytes[:32])
        
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_sock.setblocking(False)
        self.listen_sock.bind(('0.0.0.0', port))
        self.listen_sock.listen(128)
        self.selector.register(self.listen_sock, selectors.EVENT_READ, None)
    
    cdef void run(self):
        while self.running:
            events = self.selector.select(timeout=1.0)
            for key, mask in events:
                if key.data is None:
                    self._accept_connection()
                else:
                    self._handle_client(key.fileobj, key.data, mask)
    
    cdef void _accept_connection(self):
        cdef object client_sock, addr
        cdef ClientState state
        try:
            client_sock, addr = self.listen_sock.accept()
            client_sock.setblocking(False)
            state = ClientState(ClientState.STATE_HANDSHAKE)
            self.selector.register(client_sock, selectors.EVENT_READ, state)
            self.clients[client_sock.fileno()] = (client_sock, state)
        except BlockingIOError:
            pass
        except Exception as e:
            pass
    
    cdef void _handle_client(self, object sock, ClientState state, int mask):
        if state.state == ClientState.STATE_HANDSHAKE:
            self._handle_handshake(sock, state)
        elif state.state == ClientState.STATE_IDENTITY_WAIT:
            if mask & selectors.EVENT_READ:
                self._handle_identity_wait(sock, state)
        elif state.state == ClientState.STATE_READY:
            if mask & selectors.EVENT_READ:
                self._handle_request(sock, state)
    
    cdef void _handle_handshake(self, object sock, ClientState state):
        cdef object session
        cdef list users
        cdef bytes client_id
        cdef str names
        try:
            sock.setblocking(True)
            session = accept(sock, self.server_identity, None)
            sock.setblocking(False)
            
            client_id = session.client_identity
            users = self.ume.get_all_by_publickey(client_id)
            
            if len(users) == 0:
                session.close(401, "Unauthorized: unknown identity")
                self._cleanup_client(sock, state)
                return
            
            state.session = session
            
            if len(users) == 1:
                state.user = users[0]
                state.state = ClientState.STATE_READY
                session.send(b"OK 200 Welcome\n")
            else:
                state.candidates = users
                state.state = ClientState.STATE_IDENTITY_WAIT
                names = ','.join(u.username for u in users)
                session.send(f"IDENTITY_REQUIRED {names}\n".encode('utf-8'))
        except Exception as e:
            self._cleanup_client(sock, state)
    
    cdef void _handle_identity_wait(self, object sock, ClientState state):
        cdef bytes data
        cdef str cmd_line
        cdef list parts
        cdef str username
        cdef object user
        try:
            data = state.session.recv()
            if not data:
                self._cleanup_client(sock, state)
                return
            
            cmd_line = data.decode('utf-8').strip()
            parts = cmd_line.split(None, 1)
            
            if len(parts) != 2 or parts[0].upper() != "IDENTITY":
                state.session.send(b"ERR 400 Expected IDENTITY <username>\n")
                return
            
            username = parts[1]
            for user in state.candidates:
                if user.username == username:
                    state.user = user
                    state.state = ClientState.STATE_READY
                    state.session.send(b"OK 200 Welcome\n")
                    return
            
            state.session.send(b"ERR 403 Username not valid for your identity\n")
        except ConnectionError:
            self._cleanup_client(sock, state)
        except Exception as e:
            try:
                state.session.send(f"ERR 500 Internal error: {e}\n".encode('utf-8'))
            except:
                self._cleanup_client(sock, state)
    
    cdef void _handle_request(self, object sock, ClientState state):
        cdef bytes data
        cdef str cmd_line
        cdef list parts
        cdef str response
        try:
            data = state.session.recv()
            if not data:
                self._cleanup_client(sock, state)
                return
            
            cmd_line = data.decode('utf-8').strip()
            response = self._dispatch_command(cmd_line, state.session.client_identity)
            state.session.send(response.encode('utf-8'))
        except ConnectionError:
            self._cleanup_client(sock, state)
        except Exception as e:
            try:
                state.session.send(f"ERR 500 Internal error: {e}".encode('utf-8'))
            except:
                self._cleanup_client(sock, state)
    
    cdef str _dispatch_command(self, str cmd_line, bytes client_id):
        cdef list parts = cmd_line.split(None, 4)
        cdef str cmd
        if not parts:
            return "ERR 400 Bad Request: empty command"
        
        cmd = parts[0].upper()
        
        if cmd == "IDENTITY":
            return "OK 200 (ignored)\n"
        elif cmd == "REGISTER":
            return self._cmd_register(parts, client_id)
        elif cmd == "GET":
            return self._cmd_get(parts)
        elif cmd == "LIST":
            return self._cmd_list(parts)
        else:
            return f"ERR 400 Bad Request: unknown command '{cmd}'"
    
    cdef str _cmd_register(self, list parts, bytes client_id):
        cdef str username, registrar, pubkey_b64, pass_b64
        cdef bytes publickey, password
        cdef object user
        
        if len(parts) != 5:
            return "ERR 400 Bad Request: REGISTER <username> <registrar> <pubkey_b64> <pass_b64>"
        
        username, registrar, pubkey_b64, pass_b64 = parts[1], parts[2], parts[3], parts[4]
        
        try:
            publickey = base64.b64decode(pubkey_b64)
            password = base64.b64decode(pass_b64)
        except:
            return "ERR 400 Bad Request: invalid base64 encoding"
        
        if len(publickey) != 32:
            return "ERR 400 Bad Request: publickey must be 32 bytes (Ed25519)"
        
        try:
            user = self.ume.put(username, registrar, publickey, password)
            return f"OK 201 Created {user.username} seq={user.seq_numbr}"
        except ValueError as e:
            return f"ERR 409 Conflict: {e}"
    
    cdef str _cmd_get(self, list parts):
        cdef str username
        cdef object user
        
        if len(parts) != 2:
            return "ERR 400 Bad Request: GET <username>"
        
        username = parts[1]
        user = self.ume.get(username=username)
        
        if user is None:
            return f"ERR 404 Not Found: user '{username}'"
        
        pubkey_b64 = base64.b64encode(user.publickey).decode('ascii')
        pass_b64 = base64.b64encode(user.password).decode('ascii')
        return f"OK {user.username} {user.registrar} {pubkey_b64} {pass_b64} seq={user.seq_numbr}"
    
    cdef str _cmd_list(self, list parts):
        cdef list users
        cdef object user
        cdef list lines
        cdef int offset, limit
        
        offset = 0
        limit = 100
        
        if len(parts) >= 2:
            try:
                offset = int(parts[1])
            except:
                pass
        if len(parts) >= 3:
            try:
                limit = int(parts[2])
            except:
                pass
        
        users = self.ume.list_all()
        lines = []
        for user in users[offset:offset + limit]:
            pubkey_b64 = base64.b64encode(user.publickey).decode('ascii')
            lines.append(f"{user.username} {user.registrar} {pubkey_b64} seq={user.seq_numbr}")
        
        return f"OK {len(users)} users\n" + "\n".join(lines)
    
    cdef void _cleanup_client(self, object sock, ClientState state):
        cdef int fd = sock.fileno()
        try:
            self.selector.unregister(sock)
        except:
            pass
        try:
            sock.close()
        except:
            pass
        if fd in self.clients:
            del self.clients[fd]
    
    cpdef void shutdown(self):
        self.running = 0
        try:
            self.listen_sock.close()
        except:
            pass
        self.selector.close()

cdef void load_or_generate_identity(str path):
    if os.path.exists(path):
        return
    key = nacl.signing.SigningKey.generate()
    with open(path, 'wb') as f:
        f.write(bytes(key))
    os.chmod(path, 0o600)

def main():
    parser = argparse.ArgumentParser(description='Bonnet Server')
    parser.add_argument('userfile', help='Path to userfile (trusted users + registration target)')
    parser.add_argument('identity', help='Path to server Ed25519 private key')
    parser.add_argument('--port', type=int, default=PORT_STANDARD, help='Port to listen on (default: 2272)')
    parser.add_argument('--privileged', action='store_true', help='Use privileged port 272')
    args = parser.parse_args()
    
    port = PORT_PRIVILEGED if args.privileged else args.port
    load_or_generate_identity(args.identity)
    
    server = BonnetServer(args.userfile, args.identity, port)
    print(f"Bonnet server listening on port {port}")
    
    try:
        server.run()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.shutdown()

if __name__ == "__main__":
    main()