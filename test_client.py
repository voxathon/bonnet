import pytest
import asyncio
import websockets
import struct
import nacl.signing
import nacl.public
import nacl.utils
import nacl.secret
import sys
import os
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "build"))

from core.crypto import Identity, EncryptedSession
from engine.ume import Ume
import pytest


@pytest.mark.asyncio
async def test_anonymous_registration():
    """Test anonymous user registration flow"""
    print("\n=== Testing Anonymous Registration ===")

    # Create temp directory for test
    test_dir = tempfile.mkdtemp(prefix="bonnet_test_")
    try:
        identity_file = os.path.join(test_dir, "client_id")
        identity = Identity.generate()
        with open(identity_file, "wb") as f:
            f.write(identity.private_key)

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
            length = struct.unpack(">I", challenge_frame[:4])[0]
            challenge_data = challenge_frame[4 : 4 + length]
            server_pubkey = challenge_data[:32]
            challenge = challenge_data[32:]
            print(f"Received challenge: {challenge.hex()}")

            # 2. Sign Challenge
            signature = identity.sign(challenge)

            # 3. Send Handshake
            handshake_payload = identity.public_key + signature
            await websocket.send(
                struct.pack(">I", len(handshake_payload)) + handshake_payload
            )

            # 4. Establish Session
            session = EncryptedSession(identity.private_key, server_pubkey)
            print("Session established (anonymous mode)")

            # 5. Send REGISTER command (without password)
            # Format: [0x01][u_len:1][username][r_len:1][registrar]
            username = b"newuser"
            registrar = b"localhost"
            register_cmd = (
                struct.pack(">B", 0x01)
                + struct.pack(">B", len(username))
                + username
                + struct.pack(">B", len(registrar))
                + registrar
            )

            encrypted_cmd = session.encrypt(register_cmd)
            await websocket.send(struct.pack(">I", len(encrypted_cmd)) + encrypted_cmd)
            print("Sent REGISTER command")

            # 6. Read Response
            resp_frame = await websocket.recv()
            length = struct.unpack(">I", resp_frame[:4])[0]
            encrypted_resp = resp_frame[4 : 4 + length]

            plaintext_resp = session.decrypt(encrypted_resp)
            status = plaintext_resp[0]
            if status == 0x00:
                registered_name = plaintext_resp[1:].decode("utf-8")
                print(f"✓ Registration Success: {registered_name}")
            else:
                print(f"✗ Registration Failed: {plaintext_resp}")

            # 7. Connection should be closed by server
            print("Connection closed by server (expected)")

    finally:
        shutil.rmtree(test_dir)


@pytest.mark.asyncio
async def test_registered_user():
    """Test registered user with LIST command"""
    print("\n=== Testing Registered User ===")

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

    # Register the user directly in UME (password optional)
    ume = Ume(os.path.expanduser("~/.config/bonnet/userfile"))
    try:
        ume.put("testuser", "localhost", identity.public_key)
        print("Test user registered in UME.")
    except ValueError:
        print("Test user already exists.")

    uri = "ws://localhost:2272"
    async with websockets.connect(uri) as websocket:
        # 1. Read Challenge
        challenge_frame = await websocket.recv()
        length = struct.unpack(">I", challenge_frame[:4])[0]
        challenge_data = challenge_frame[4 : 4 + length]
        server_pubkey = challenge_data[:32]
        challenge = challenge_data[32:]
        print(f"Received challenge: {challenge.hex()}")

        # 2. Sign Challenge
        signature = identity.sign(challenge)

        # 3. Send Handshake
        handshake_payload = identity.public_key + signature
        await websocket.send(
            struct.pack(">I", len(handshake_payload)) + handshake_payload
        )

        # 4. Establish Session
        session = EncryptedSession(identity.private_key, server_pubkey)
        print("Session established.")

        # 5. Send LIST command
        # LIST: [0x03][offset(4)][limit(4)]
        list_cmd = struct.pack(">BII", 0x03, 0, 100)
        encrypted_cmd = session.encrypt(list_cmd)
        await websocket.send(struct.pack(">I", len(encrypted_cmd)) + encrypted_cmd)

        # 6. Read Response
        resp_frame = await websocket.recv()
        length = struct.unpack(">I", resp_frame[:4])[0]
        encrypted_resp = resp_frame[4 : 4 + length]

        plaintext_resp = session.decrypt(encrypted_resp)
        status = plaintext_resp[0]
        if status == 0x00:
            print(f"✓ LIST Success: {plaintext_resp[1:].decode('utf-8')}")
        else:
            print(f"✗ LIST Failed: {plaintext_resp}")

        # 7. Connection should be closed by server
        print("Connection closed by server (expected)")


async def main():
    await test_anonymous_registration()
    await test_registered_user()


if __name__ == "__main__":
    asyncio.run(main())
