# cython: language_level=3

import asyncio
import websockets
import os
import argparse

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) or '.')
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'build'))

from ume import Ume
from ame import Ame
from conman import Connection, ConnectionError, CommandHandler
from crypto import Identity
from config import Config

import nacl.exceptions

PORT_PRIVILEGED = 272
PORT_STANDARD = 2272

cdef class BonnetServer:
    cdef str userfile_path
    cdef object ume
    cdef object ame
    cdef object server_identity
    cdef object config
    cdef object command_handler
    
    def __init__(self, str userfile_path, str identity_path, object config):
        self.userfile_path = userfile_path
        self.ume = Ume(userfile_path)
        with open(identity_path, 'rb') as f:
            key_bytes = f.read()
        self.server_identity = Identity.from_private_key(key_bytes)
        self.ame = Ame(config.ame_path, origin=config.origin, signing_key=self.server_identity.signing_key, nav_db_path=config.nav_db_path)
        self.config = config
        self.command_handler = CommandHandler(self.ume, self.ame, config, self.server_identity)
    
    async def handle_connection(self, websocket):
        cdef object conn
        
        try:
            async with asyncio.timeout(self.config.timeout_seconds):
                conn = Connection.server(
                    self.server_identity, websocket,
                    self.ume, self.config, ame=self.ame
                )
                await conn.accept()
                plaintext = await conn.recv_request()
                response = self.command_handler.handle(plaintext, conn)
                await conn.send_response(response)
                await conn.close()
                
        except asyncio.TimeoutError:
            pass
        except ConnectionError:
            pass
        except nacl.exceptions.CryptoError:
            pass
        except Exception:
            pass

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
    
    config_dir = '/var/lib/bonnet'
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
        print(f"Server public key: {server.server_identity.public_key.hex()}")
        await asyncio.Future()

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()