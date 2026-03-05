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
from config import Config
import nacl.exceptions

PORT_PRIVILEGED = 272
PORT_STANDARD = 2272

cdef int CHALLENGE_SIZE = 32
cdef int NONCE_SIZE = 24

cdef class BonnetServer:
    cdef str userfile_path
    cdef object ume
    cdef object server_identity
    cdef object config
    
    def __init__(self, str userfile_path, str identity_path, object config):
        self.userfile_path = userfile_path
        self.ume = Ume(userfile_path)
        self.config = config
        with open(identity_path, 'rb') as f:
            key_bytes = f.read()
        self.server_identity = Identity.from_private_key(key_bytes)
    
    async def handle_connection(self, websocket):
        cdef bytes challenge, client_pubkey, signature
        cdef list users
        cdef object selected_user
        cdef object session
        cdef bint is_anonymous

        try:
            # Set 30-second timeout for entire connection
            async with asyncio.timeout(self.config.timeout_seconds):
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
                    is_anonymous = True
                    selected_user = None
                else:
                    is_anonymous = False
                
                # Phase 4: Establish encrypted session
                session = EncryptedSession(
                    self.server_identity.private_key,
                    client_pubkey
                )
                
                # Phase 5: Handle multi-username or single (skip if anonymous)
                if not is_anonymous:
                    if len(users) == 1:
                        selected_user = users[0]
                    else:
                        selected_user = await self._select_username(websocket, session, users)
                        if selected_user is None:
                            return
                
                # Phase 6: Process single request (short-lived connection)
                await self._handle_request(websocket, session, selected_user, is_anonymous, client_pubkey)
                
        except asyncio.TimeoutError:
            try:
                await self._send_error(websocket, 408, "Connection timeout", session)
                await websocket.close()
            except:
                pass
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
    
    async def _handle_request(self, websocket, session, user, bint is_anonymous, bytes client_pubkey):
        encrypted_request = await self._recv_frame(websocket)
        plaintext = session.decrypt(encrypted_request)
        
        cmd = plaintext[0] if len(plaintext) > 0 else -1
        
        # Anonymous users can ONLY register
        if is_anonymous and cmd != 0x01:
            await self._send_error(websocket, 401, "Anonymous users must register first", session)
            await websocket.close()
            return
        
        response = self._dispatch_command(plaintext, user, client_pubkey)
        encrypted_response = session.encrypt(response)
        await self._send_frame(websocket, encrypted_response)
        
        # Close connection after command (short-lived WebSocket)
        await websocket.close()
    
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

    cdef bytes _dispatch_command(self, bytes request, object user, bytes client_pubkey):
        cdef int cmd
        if len(request) == 0:
            return self._build_error(400, "Empty request")

        cmd = request[0]
        data = request[1:]
        
        if cmd == 0x01:
            return self._cmd_register(data, user, client_pubkey)
        elif cmd == 0x02:
            return self._cmd_get(data)
        elif cmd == 0x03:
            return self._cmd_list(data)
        else:
            return self._build_error(400, f"Unknown command {cmd}")

    cdef bytes _build_error(self, int code, str message):
        msg_bytes = message.encode('utf-8')
        return struct.pack('>BHB', 0x01, code, len(msg_bytes)) + msg_bytes
    
    cdef bytes _cmd_register(self, bytes data, object user, bytes client_pubkey):
        cdef int idx = 0
        cdef int u_len, r_len
        cdef str username, registrar

        try:
            # Parse username
            u_len = data[idx]
            idx += 1
            username = data[idx:idx+u_len].decode('utf-8')
            idx += u_len
            
            # Validate username length
            if u_len > 255:
                return self._build_error(400, "Username too long (max 255 chars)")
            
            if u_len == 0:
                return self._build_error(400, "Username cannot be empty")

            # Parse registrar
            r_len = data[idx]
            idx += 1
            registrar = data[idx:idx+r_len].decode('utf-8')
            idx += r_len
            
            # Validate registrar is not empty
            if r_len == 0:
                return self._build_error(400, "Registrar cannot be empty")

            # Validate username characters
            import re
            invalid_chars = re.compile(r'[@<>:"/\\|?*]')
            if invalid_chars.search(username):
                return self._build_error(400, "Username contains invalid characters")

            # Validate registrar is in whitelist
            if not self.config.registrar_valid(registrar):
                return self._build_error(403, f"Unknown registrar: {registrar}")
            
            # Check for duplicate username
            existing_user = self.ume.get(username=username)
            if existing_user is not None:
                return self._build_error(409, f"Username '{username}' already exists")

            # Register using authenticated pubkey (password field reserved for future HTTP use)
            new_user = self.ume.put(username, registrar, client_pubkey, password=None)

            # Format OK Response for REGISTER
            # OK is [0x00][user.username.encode()]
            u_bytes = new_user.username.encode('utf-8')
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
    default_config = os.path.join(config_dir, 'config.toml')
    
    parser = argparse.ArgumentParser(description='Bonnet Server')
    parser.add_argument('userfile', nargs='?', default=default_userfile)
    parser.add_argument('identity', nargs='?', default=default_identity)
    parser.add_argument('--config', default=default_config, help='Config file path')
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
    
    config = Config.load(args.config)
    
    server = BonnetServer(args.userfile, args.identity, config)
    
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
