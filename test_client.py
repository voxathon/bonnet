import asyncio
import websockets
import struct
import nacl.signing
import nacl.public
import nacl.utils
import nacl.secret
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'build'))

from crypto import Identity, EncryptedSession
from ume import Ume

async def test():
    identity_file = "test_client_id"
    if not os.path.exists(identity_file):
        identity = Identity.generate()
        with open(identity_file, "wb") as f:
            f.write(identity.private_key)
    else:
        with open(identity_file, "rb") as f:
            key_bytes = f.read()
        identity = Identity.from_private_key(key_bytes)

    print(f"Client Public Key: {identity.public_key.hex()}")

    server_identity_file = os.path.expanduser("~/.config/bonnet/identity")
    if not os.path.exists(server_identity_file):
        print(f"Server identity not found at {server_identity_file}")
        return

    with open(server_identity_file, "rb") as f:
        server_key_bytes = f.read()
    server_identity = Identity.from_private_key(server_key_bytes)

    uri = "ws://localhost:2272"
    async with websockets.connect(uri) as websocket:
        # 1. Read Challenge
        challenge_frame = await websocket.recv()
        length = struct.unpack('>I', challenge_frame[:4])[0]
        challenge = challenge_frame[4:4+length]
        print(f"Received challenge: {challenge.hex()}")

        # 2. Sign Challenge
        signature = identity.sign(challenge)

        # 3. Send Handshake
        handshake_payload = identity.public_key + signature
        await websocket.send(struct.pack('>I', len(handshake_payload)) + handshake_payload)

        # 4. Establish Session
        session = EncryptedSession(identity.private_key, server_identity.public_key)
        print("Session established.")

        # 5. First, try to register the user via REGISTER command
        # REGISTER: [0x01][u_len(1)][username][r_len(1)][registrar][pubkey(32)][p_len(1)][password]
        username = b"testuser"
        registrar = b"localhost"
        password = b"testpass"
        register_cmd = struct.pack('>B', 0x01)  # REGISTER command
        register_cmd += struct.pack('>B', len(username)) + username
        register_cmd += struct.pack('>B', len(registrar)) + registrar
        register_cmd += identity.public_key
        register_cmd += struct.pack('>B', len(password)) + password

        encrypted_register = session.encrypt(register_cmd)
        await websocket.send(struct.pack('>I', len(encrypted_register)) + encrypted_register)

        # Read REGISTER response
        reg_resp_frame = await websocket.recv()
        length = struct.unpack('>I', reg_resp_frame[:4])[0]
        encrypted_reg_resp = reg_resp_frame[4:4+length]
        plaintext_reg_resp = session.decrypt(encrypted_reg_resp)

        reg_status = plaintext_reg_resp[0]
        if reg_status == 0x00:
            print(f"REGISTER Success: {plaintext_reg_resp[1:].decode('utf-8')}")
        else:
            # Error format: [0x01][code(2)][msg_len(1)][message]
            error_code = struct.unpack('>H', plaintext_reg_resp[1:3])[0]
            msg_len = plaintext_reg_resp[3]
            error_msg = plaintext_reg_resp[4:4+msg_len].decode('utf-8')
            print(f"REGISTER Failed (code {error_code}): {error_msg}")

        # 6. Send LIST command
        # LIST: [0x03][offset(4)][limit(4)]
        list_cmd = struct.pack('>BII', 0x03, 0, 100)
        encrypted_cmd = session.encrypt(list_cmd)
        await websocket.send(struct.pack('>I', len(encrypted_cmd)) + encrypted_cmd)

        # 7. Read LIST Response
        resp_frame = await websocket.recv()
        length = struct.unpack('>I', resp_frame[:4])[0]
        encrypted_resp = resp_frame[4:4+length]

        plaintext_resp = session.decrypt(encrypted_resp)
        status = plaintext_resp[0]
        if status == 0x00:
            print(f"LIST Success: {plaintext_resp[1:].decode('utf-8')}")
        else:
            error_code = struct.unpack('>H', plaintext_resp[1:3])[0]
            msg_len = plaintext_resp[3]
            error_msg = plaintext_resp[4:4+msg_len].decode('utf-8')
            print(f"LIST Failed (code {error_code}): {error_msg}")

if __name__ == "__main__":
    asyncio.run(test())