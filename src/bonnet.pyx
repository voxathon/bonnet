# cython: language_level=3

import asyncio
import websockets
import os
import struct
import base64
import argparse
import time

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) or '.')
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'build'))

from ume import Ume, User
from crypto import Identity, EncryptedSession
import nacl.exceptions

PORT_PRIVILEGED = 272
PORT_STANDARD = 2272

cdef int CHALLENGE_SIZE = 32
cdef int NONCE_SIZE = 24

cdef class BonnetServer:
    cdef str userfile_path
    cdef object ume
    cdef object server_identity
    
    def __init__(self, str userfile_path, str identity_path):
        self.userfile_path = userfile_path
        self.ume = Ume(userfile_path)
        with open(identity_path, 'rb') as f:
            key_bytes = f.read()
        self.server_identity = Identity.from_private_key(key_bytes)
    
    async def handle_connection(self, websocket):
        cdef bytes challenge, client_pubkey, signature
        cdef list users
        cdef object selected_user
        cdef object session

        try:
            # Phase 1: Challenge
            challenge = os.urandom(CHALLENGE_SIZE)
            await websocket.send(struct.pack('>I', len(challenge)) + challenge)

            # Phase 2: Verify signature
            handshake_frame = await self._recv_frame(websocket)
            client_pubkey = handshake_frame[:32]
            signature = handshake_frame[32:96]
            
            if not Identity.verify(client_pubkey, challenge, signature):
                await self._send_error(websocket, 401, "Invalid signature", None)
                return
            
            # Phase 3: Lookup user
            users = self.ume.get_all_by_publickey(client_pubkey)
            if len(users) == 0:
                await self._send_error(websocket, 404, "Unknown identity", None)
                return
            
            # Phase 4: Establish encrypted session
            session = EncryptedSession(
                self.server_identity.private_key,
                client_pubkey
            )
            
            # Phase 5: Handle multi-username or single
            if len(users) == 1:
                selected_user = users[0]
            else:
                selected_user = await self._select_username(websocket, session, users)
                if selected_user is None:
                    return
            
            # Phase 6: Process request
            while True:
                try:
                    await self._handle_request(websocket, session, selected_user)
                except websockets.exceptions.ConnectionClosed:
                    break
            
        except nacl.exceptions.CryptoError:
            await self._send_error(websocket, 400, "Decryption failed", session)
        except Exception as e:
            try:
                await self._send_error(websocket, 500, str(e), session)
            except:
                pass
    
    async def _select_username(self, websocket, session, users):
        username_list = ','.join(u.username for u in users)
        encrypted = session.encrypt(username_list.encode('utf-8'))
        await self._send_frame(websocket, encrypted)
        
        encrypted_response = await self._recv_frame(websocket)
        selected = session.decrypt(encrypted_response).decode('utf-8')
        
        for user in users:
            if user.username == selected:
                return user
        return None
    
    async def _handle_request(self, websocket, session, user):
        encrypted_request = await self._recv_frame(websocket)
        plaintext = session.decrypt(encrypted_request)
        response = self._dispatch_command(plaintext, user)
        encrypted_response = session.encrypt(response)
        await self._send_frame(websocket, encrypted_response)
    
    async def _send_frame(self, websocket, bytes data):
        await websocket.send(struct.pack('>I', len(data)) + data)
    
    async def _recv_frame(self, websocket):
        data = await websocket.recv()
        if isinstance(data, bytes):
            length = struct.unpack('>I', data[:4])[0]
            if len(data) - 4 != length:
                pass
            return data[4:4+length]
        raise ValueError("Expected binary frame")

    async def _send_error(self, websocket, code, message, session):
        # Format ERROR response: [0x01][code(2)][msg_len(1)][message]
        msg_bytes = message.encode('utf-8')
        payload = struct.pack('>BHB', 0x01, code, len(msg_bytes)) + msg_bytes
        
        if session is not None:
            try:
                encrypted = session.encrypt(payload)
                await self._send_frame(websocket, encrypted)
            except Exception:
                pass
        else:
            try:
                await self._send_frame(websocket, payload)
            except Exception:
                pass

    cdef bytes _dispatch_command(self, bytes request, object user):
        cdef int cmd
        if len(request) == 0:
            return self._build_error(400, "Empty request")

        cmd = request[0]
        data = request[1:]
        
        if cmd == 0x01:
            return self._cmd_register(data, user)
        elif cmd == 0x02:
            return self._cmd_get(data)
        elif cmd == 0x03:
            return self._cmd_list(data)
        else:
            return self._build_error(400, f"Unknown command {cmd}")

    cdef bytes _build_error(self, int code, str message):
        msg_bytes = message.encode('utf-8')
        return struct.pack('>BHB', 0x01, code, len(msg_bytes)) + msg_bytes
    
    cdef bytes _cmd_register(self, bytes data, object registrar_user):
        cdef int idx = 0
        cdef int u_len, r_len, p_len
        cdef str username, registrar
        cdef bytes pubkey, password

        try:
            u_len = data[idx]
            idx += 1
            username = data[idx:idx+u_len].decode('utf-8')
            idx += u_len

            r_len = data[idx]
            idx += 1
            registrar = data[idx:idx+r_len].decode('utf-8')
            idx += r_len

            pubkey = data[idx:idx+32]
            idx += 32

            p_len = data[idx]
            idx += 1
            password = data[idx:idx+p_len]
            idx += p_len

            if "@" not in username:
                return self._build_error(400, "Username must contain @homeserver.sex")

            import re
            invalid_chars = re.compile(r'[@<>:"/\\|?*]')
            if invalid_chars.search(username.split('@')[0]):
                return self._build_error(400, "Username contains invalid characters")

            user = self.ume.put(username, registrar, pubkey, password)

            # Format OK Response for REGISTER
            # Let's say OK is [0x00][user.username.encode()]
            u_bytes = user.username.encode('utf-8')
            return struct.pack('>B', 0x00) + u_bytes

        except Exception as e:
            return self._build_error(400, str(e))

    cdef bytes _cmd_get(self, bytes data):
        cdef int u_len
        cdef str username
        cdef object user

        try:
            u_len = data[0]
            username = data[1:1+u_len].decode('utf-8')

            user = self.ume.get(username=username)
            if user is None:
                return self._build_error(404, f"User {username} not found")

            # OK Response GET: [0x00][pubkey(32)][r_len(1)][registrar_bytes]
            r_bytes = user.registrar.encode('utf-8')
            return struct.pack('>B', 0x00) + user.publickey + struct.pack('>B', len(r_bytes)) + r_bytes

        except Exception as e:
            return self._build_error(400, str(e))
    
    cdef bytes _cmd_list(self, bytes data):
        cdef int offset, limit
        cdef list users, lines
        cdef object user

        try:
            if len(data) >= 8:
                offset, limit = struct.unpack('>II', data[:8])
            else:
                offset = 0
                limit = 100

            users = self.ume.list_all()
            page = users[offset:offset+limit]

            # Pack usernames separated by commas, or zero-terminated string?
            # Comma separated string for simplicity
            u_list = ",".join(u.username for u in page).encode('utf-8')
            return struct.pack('>B', 0x00) + u_list

        except Exception as e:
            return self._build_error(400, str(e))

def load_or_generate_identity(str path):
    if os.path.exists(path):
        return
    key = Identity.generate()
    with open(path, 'wb') as f:
        f.write(bytes(key.private_key))
    os.chmod(path, 0o600)

async def main_async():
    cdef str config_dir, default_userfile, default_identity
    cdef BonnetServer server
    
    config_dir = os.path.expanduser('~/.config/bonnet')
    default_userfile = os.path.join(config_dir, 'userfile')
    default_identity = os.path.join(config_dir, 'identity')
    
    parser = argparse.ArgumentParser(description='Bonnet Server')
    parser.add_argument('userfile', nargs='?', default=default_userfile)
    parser.add_argument('identity', nargs='?', default=default_identity)
    parser.add_argument('--port', type=int, default=PORT_STANDARD)
    parser.add_argument('--privileged', action='store_true')
    parser.add_argument('--cert', help='TLS certificate path')
    parser.add_argument('--key', help='TLS private key path')
    args = parser.parse_args()
    
    os.makedirs(config_dir, exist_ok=True)
    if not os.path.exists(args.userfile):
        open(args.userfile, 'a').close()
        os.chmod(args.userfile, 0o600)
    
    port = PORT_PRIVILEGED if args.privileged else args.port
    load_or_generate_identity(args.identity)
    
    server = BonnetServer(args.userfile, args.identity)
    
    ssl_context = None
    if args.cert and args.key:
        import ssl
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(args.cert, args.key)

    async with websockets.serve(
        server.handle_connection,
        '0.0.0.0',
        port,
        ssl=ssl_context
    ):
        print(f"Bonnet server listening on port {port}")
        await asyncio.Future()  # Run forever

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()
