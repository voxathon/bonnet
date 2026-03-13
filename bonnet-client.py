#!/usr/bin/env python3
"""Bonnet BBS Client CLI"""

import asyncio
import os
import struct
import sys
from pathlib import Path

import click
from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey, PublicKey, Box
from nacl.utils import random as random_bytes
from nacl.encoding import RawEncoder
from datetime import datetime
import websockets
import websockets.exceptions


IDENTITY_PATH = Path.home() / ".config" / "bonnet" / "client_identity"
KNOWN_SERVERS_PATH = Path.home() / ".config" / "bonnet" / "known_servers"
LOG_PATH = Path.cwd() / "bonnet-client.log"


class Logger:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._file = None
        return cls._instance

    def _ensure_open(self):
        if self._file is None:
            self._file = open(LOG_PATH, "a", buffering=1)

    def log(self, direction: str, msg: str, data: bytes | None = None):
        self._ensure_open()
        ts = datetime.now().isoformat()
        line = f"[{ts}] {direction} {msg}"
        if data is not None:
            line += f"\n    hex: {data.hex()}"
            line += f"\n    len: {len(data)}"
        self._file.write(line + "\n")

    def log_frame(self, direction: str, frame: bytes):
        self._ensure_open()
        ts = datetime.now().isoformat()
        length = struct.unpack(">I", frame[:4])[0] if len(frame) >= 4 else 0
        payload = frame[4 : 4 + length] if len(frame) >= 4 else frame
        self._file.write(f"[{ts}] {direction} FRAME\n")
        self._file.write(f"    raw_hex: {frame.hex()}\n")
        self._file.write(f"    length: {length}\n")
        self._file.write(f"    payload_hex: {payload.hex()}\n")
        self._file.write(f"    payload_len: {len(payload)}\n")

    def log_encrypted(
        self, direction: str, data: bytes, decrypted: bytes | None = None
    ):
        self._ensure_open()
        ts = datetime.now().isoformat()
        self._file.write(f"[{ts}] {direction} ENCRYPTED\n")
        self._file.write(f"    ciphertext_hex: {data.hex()}\n")
        self._file.write(f"    ciphertext_len: {len(data)}\n")
        if decrypted is not None:
            self._file.write(f"    plaintext_hex: {decrypted.hex()}\n")
            self._file.write(f"    plaintext_len: {len(decrypted)}\n")
            try:
                text = decrypted.decode("utf-8", errors="replace")
                self._file.write(f"    plaintext_utf8: {repr(text)}\n")
            except:
                pass

    def close(self):
        if self._file:
            self._file.close()
            self._file = None


def get_logger():
    return Logger()


class KnownServers:
    def __init__(self, base_path: Path = KNOWN_SERVERS_PATH):
        self.base_path = base_path
        self.base_path.mkdir(parents=True, exist_ok=True)

    def get(self, hostname: str) -> bytes | None:
        path = self.base_path / hostname
        if path.exists():
            return path.read_bytes()
        return None

    def save(self, hostname: str, pubkey: bytes):
        path = self.base_path / hostname
        path.write_bytes(pubkey)
        path.chmod(0o600)

    def list(self) -> list[str]:
        if not self.base_path.exists():
            return []
        return [p.name for p in self.base_path.iterdir() if p.is_file()]

    def remove(self, hostname: str) -> bool:
        path = self.base_path / hostname
        if path.exists():
            path.unlink()
            return True
        return False


class ServerUnknownError(Exception):
    def __init__(self, hostname: str):
        self.hostname = hostname
        super().__init__(f"Unknown server: {hostname}")


class NotConfiguredError(Exception):
    pass


def hex_truncate(data: bytes, n: int = 8) -> str:
    h = data.hex()
    if len(h) <= n * 2:
        return h
    return f"{h[:n]}...{h[-n:]}"


def log_verbose(msg: str, verbose: bool = True):
    if verbose:
        click.echo(click.style(f"[{msg}]", dim=True))


class Identity:
    def __init__(self, seed: bytes):
        self._signing_key = SigningKey(seed)
        self._private_key = PrivateKey(seed)

    @property
    def public_key(self) -> bytes:
        return bytes(self._signing_key.verify_key)

    @property
    def private_key(self) -> bytes:
        return bytes(self._signing_key)

    def sign(self, message: bytes) -> bytes:
        return bytes(self._signing_key.sign(message).signature)

    @classmethod
    def generate(cls) -> "Identity":
        seed = random_bytes(32)
        return cls(seed)

    @classmethod
    def load(cls, path: Path) -> "Identity":
        seed = path.read_bytes()
        return cls(seed)

    def save(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bytes(self._signing_key))
        path.chmod(0o600)


class EncryptedSession:
    def __init__(self, our_private: bytes, their_public: bytes):
        our_signing_key = SigningKey(our_private)
        their_verify_key = VerifyKey(their_public)
        our_x25519_private = our_signing_key.to_curve25519_private_key()
        their_x25519_public = their_verify_key.to_curve25519_public_key()
        self._box = Box(our_x25519_private, their_x25519_public)
        self._logger = get_logger()

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = random_bytes(24)
        ciphertext = self._box.encrypt(plaintext, nonce, encoder=RawEncoder)
        self._logger.log_encrypted("→", ciphertext, plaintext)
        return ciphertext

    def decrypt(self, payload: bytes) -> bytes:
        plaintext = self._box.decrypt(payload)
        self._logger.log_encrypted("←", payload, plaintext)
        return plaintext


def encode_string(s: str) -> bytes:
    encoded = s.encode("utf-8")
    if len(encoded) > 255:
        raise ValueError(f"String too long: {len(encoded)} > 255")
    return struct.pack("B", len(encoded)) + encoded


def encode_content(s: str) -> bytes:
    encoded = s.encode("utf-8")
    return struct.pack(">I", len(encoded)) + encoded


def decode_content(data: bytes, offset: int) -> tuple[str, int]:
    length = struct.unpack(">I", data[offset : offset + 4])[0]
    content = data[offset + 4 : offset + 4 + length].decode("utf-8")
    return content, offset + 4 + length


def decode_string(data: bytes, offset: int) -> tuple[str, int]:
    length = data[offset]
    s = data[offset + 1 : offset + 1 + length].decode("utf-8")
    return s, offset + 1 + length


class BonnetClient:
    def __init__(self, identity: Identity, verbose: bool = True):
        self.identity = identity
        self.verbose = verbose
        self.ws = None
        self.session = None
        self.url = None
        self.server_pubkey = None
        self.known_servers = KnownServers()
        self._logger = get_logger()

    async def configure(self, url: str, server_pubkey: bytes | None = None):
        from urllib.parse import urlparse

        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.path

        if server_pubkey is None:
            server_pubkey = self.known_servers.get(hostname)

        if server_pubkey is None:
            raise ServerUnknownError(hostname)

        self.url = url
        self.server_pubkey = server_pubkey
        self.known_servers.save(hostname, server_pubkey)
        click.echo(click.style(f"Configured: {url}", fg="green"))

    def is_configured(self) -> bool:
        return self.url is not None and self.server_pubkey is not None

    async def _connect_for_command(self):
        if not self.is_configured():
            raise NotConfiguredError()
        assert self.url is not None
        assert self.server_pubkey is not None
        self._logger.log("→", f"CONNECT: {self.url}")
        self.ws = await websockets.connect(self.url)
        self._logger.log("→", "CONNECT: websocket established")
        await self._handshake()

    async def _handshake(self):
        assert self.server_pubkey is not None
        self._logger.log("←", "HANDSHAKE: waiting for challenge")
        challenge = await self._recv_frame()
        self._logger.log("←", f"HANDSHAKE: challenge received", challenge)

        signature = self.identity.sign(challenge)
        self._logger.log("→", f"HANDSHAKE: signed challenge", signature)

        handshake = self.identity.public_key + signature
        self._logger.log("→", f"HANDSHAKE: sending pubkey + sig", handshake)
        await self._send_frame(handshake)

        self._logger.log(
            "→", f"SESSION: creating with server_pubkey={self.server_pubkey.hex()}"
        )
        self.session = EncryptedSession(self.identity.private_key, self.server_pubkey)
        self._logger.log("→", "SESSION: established")

        await self._handle_user_selection()

    async def _handle_user_selection(self):
        try:
            frame = await asyncio.wait_for(self.ws.recv(), timeout=0.5)
        except asyncio.TimeoutError:
            self._logger.log("←", "USER_SELECTION: timeout (no selection needed)")
            return
        except Exception:
            return

        if not isinstance(frame, bytes):
            return

        self._logger.log_frame("←", frame)
        length = struct.unpack(">I", frame[:4])[0]
        encrypted = frame[4 : 4 + length]
        decrypted = self.session.decrypt(encrypted)
        self._logger.log("←", "USER_SELECTION: received", decrypted)

        try:
            text = decrypted.decode("utf-8")
            if "," in text and all(c.isprintable() or c in ",\n" for c in text):
                usernames = [u.strip() for u in text.split(",") if u.strip()]
                if usernames:
                    click.echo(f"Multiple identities found for this key:")
                    for i, name in enumerate(usernames):
                        click.echo(f"  [{i + 1}] {name}")
                    choice = click.prompt(
                        "Select identity",
                        type=click.IntRange(1, len(usernames)),
                        show_default=False,
                    )
                    selected = usernames[choice - 1]
                    click.echo(click.style(f"Selected: {selected}", fg="green"))
                    self._logger.log("→", f"USER_SELECTION: sending '{selected}'")
                    payload = selected.encode("utf-8")
                    encrypted_response = self.session.encrypt(payload)
                    await self._send_frame(encrypted_response)
                    return
        except Exception:
            pass

    async def _disconnect_after_command(self):
        if self.ws:
            self._logger.log("→", "DISCONNECT: closing websocket")
            await self.ws.close()
            self.ws = None
            self.session = None

    async def _send_frame(self, data: bytes):
        frame = struct.pack(">I", len(data)) + data
        self._logger.log_frame("→", frame)
        await self.ws.send(frame)

    async def _recv_frame(self) -> bytes:
        frame = await self.ws.recv()
        if isinstance(frame, bytes):
            self._logger.log_frame("←", frame)
            length = struct.unpack(">I", frame[:4])[0]
            return frame[4 : 4 + length]
        raise ValueError("Expected bytes")

    async def _send_request(self, cmd: int, *args: bytes):
        payload = struct.pack("B", cmd) + b"".join(args)
        self._logger.log("→", f"REQUEST cmd=0x{cmd:02x}", payload)
        encrypted = self.session.encrypt(payload)
        await self._send_frame(encrypted)

    async def _recv_response(self) -> tuple[bool, dict]:
        encrypted = await self._recv_frame()
        decrypted = self.session.decrypt(encrypted)
        status = decrypted[0]
        if status == 0x00:
            self._logger.log("←", "RESPONSE OK", decrypted)
            return True, {"data": decrypted[1:]}
        else:
            code = struct.unpack(">H", decrypted[1:3])[0]
            msg_len = decrypted[3]
            msg = decrypted[4 : 4 + msg_len].decode("utf-8")
            self._logger.log("←", f"RESPONSE ERROR code={code} msg={msg}", decrypted)
            return False, {"code": code, "message": msg}

    async def disconnect(self):
        if self.ws:
            self._logger.log("→", "DISCONNECT: closing websocket")
            await self.ws.close()
            self.ws = None
            self.session = None

    async def register(self, username: str, registrar: str) -> dict:
        await self._connect_for_command()
        try:
            await self._send_request(
                0x01, encode_string(username), encode_string(registrar)
            )
            ok, result = await self._recv_response()
            return result if ok else {"error": result}
        finally:
            await self._disconnect_after_command()

    async def get_user(self, username: str) -> dict:
        await self._connect_for_command()
        try:
            await self._send_request(0x02, encode_string(username))
            ok, result = await self._recv_response()
            if ok:
                data = result["data"]
                pubkey = data[:32].hex()
                offset = 32
                registrar, _ = decode_string(data, offset)
                return {"pubkey": pubkey, "registrar": registrar}
            return {"error": result}
        finally:
            await self._disconnect_after_command()

    async def list_users(self, offset: int = 0, limit: int = 100) -> dict:
        await self._connect_for_command()
        try:
            await self._send_request(
                0x03, struct.pack(">I", offset), struct.pack(">I", limit)
            )
            ok, result = await self._recv_response()
            if ok:
                data = result["data"]
                if not data:
                    return {"users": []}
                users = data.decode("utf-8").split(",")
                return {"users": users}
            return {"error": result}
        finally:
            await self._disconnect_after_command()

    async def create_board(self, name: str) -> dict:
        await self._connect_for_command()
        try:
            await self._send_request(0x10, encode_string(name))
            ok, result = await self._recv_response()
            return result if ok else {"error": result}
        finally:
            await self._disconnect_after_command()

    async def close_board(self, name: str) -> dict:
        await self._connect_for_command()
        try:
            await self._send_request(0x17, encode_string(name))
            ok, result = await self._recv_response()
            return result if ok else {"error": result}
        finally:
            await self._disconnect_after_command()

    async def delete_board(self, name: str) -> dict:
        await self._connect_for_command()
        try:
            await self._send_request(0x18, encode_string(name))
            ok, result = await self._recv_response()
            return result if ok else {"error": result}
        finally:
            await self._disconnect_after_command()

    async def list_boards(self) -> dict:
        await self._connect_for_command()
        try:
            await self._send_request(0x11)
            ok, result = await self._recv_response()
            if ok:
                data = result["data"]
                if not data:
                    return {"boards": []}
                boards = []
                for entry in data.decode("utf-8").split(","):
                    if entry.startswith("closed:"):
                        boards.append((entry[7:], True))
                    else:
                        boards.append((entry, False))
                return {"boards": boards}
            return {"error": result}
        finally:
            await self._disconnect_after_command()

    async def create_post(
        self,
        board: str,
        root: int,
        subject: str,
        content: str,
        tags: str = "",
        options: str = "",
    ) -> dict:
        await self._connect_for_command()
        try:
            await self._send_request(
                0x12,
                encode_string(board),
                struct.pack(">Q", root),
                encode_string(subject),
                encode_string(tags),
                encode_string(options),
                encode_content(content),
            )
            ok, result = await self._recv_response()
            if ok:
                data = result["data"]
                offset = 0
                post_num = struct.unpack(">Q", data[offset : offset + 8])[0]
                offset += 8
                creation_date = struct.unpack(">q", data[offset : offset + 8])[0]
                offset += 8
                last_modified = struct.unpack(">q", data[offset : offset + 8])[0]
                offset += 8
                author, offset = decode_string(data, offset)
                tags_resp, offset = decode_string(data, offset)
                subject_resp, offset = decode_string(data, offset)
                options_resp, offset = decode_string(data, offset)
                return {
                    "post_num": post_num,
                    "creation_date": creation_date,
                    "last_modified": last_modified,
                    "author": author,
                    "tags": tags_resp,
                    "subject": subject_resp,
                    "options": options_resp,
                    "content": content,
                }
            return {"error": result}
        finally:
            await self._disconnect_after_command()

    async def get_post(self, board: str, post_num: int) -> dict:
        await self._connect_for_command()
        try:
            await self._send_request(
                0x13, encode_string(board), struct.pack(">Q", post_num)
            )
            ok, result = await self._recv_response()
            if ok:
                data = result["data"]
                offset = 0
                post_num = struct.unpack(">Q", data[offset : offset + 8])[0]
                offset += 8
                last_modified = struct.unpack(">q", data[offset : offset + 8])[0]
                offset += 8
                creation_date = struct.unpack(">q", data[offset : offset + 8])[0]
                offset += 8
                last_bumped = struct.unpack(">q", data[offset : offset + 8])[0]
                offset += 8
                closed = data[offset]
                offset += 1
                sticky = struct.unpack(">i", data[offset : offset + 4])[0]
                offset += 4
                tags, offset = decode_string(data, offset)
                subject, offset = decode_string(data, offset)
                options, offset = decode_string(data, offset)
                root = struct.unpack(">Q", data[offset : offset + 8])[0]
                offset += 8
                author, offset = decode_string(data, offset)
                signature, offset = decode_string(data, offset)
                content, _ = decode_content(data, offset)
                return {
                    "post_num": post_num,
                    "last_modified": last_modified,
                    "creation_date": creation_date,
                    "last_bumped": last_bumped,
                    "closed": bool(closed),
                    "sticky": sticky,
                    "tags": tags,
                    "subject": subject,
                    "options": options,
                    "root": root,
                    "author": author,
                    "signature": signature,
                    "content": content,
                }
            return {"error": result}
        finally:
            await self._disconnect_after_command()

    async def list_posts(self, board: str, offset: int = 0, limit: int = 50) -> dict:
        await self._connect_for_command()
        try:
            await self._send_request(
                0x14,
                encode_string(board),
                struct.pack(">I", offset),
                struct.pack(">I", limit),
            )
            ok, result = await self._recv_response()
            if ok:
                data = result["data"]
                if not data:
                    return {"posts": []}
                posts = []
                off = 0
                while off < len(data):
                    post_num = struct.unpack(">Q", data[off : off + 8])[0]
                    off += 8
                    creation_date = struct.unpack(">Q", data[off : off + 8])[0]
                    off += 8
                    subject, off = decode_string(data, off)
                    author, off = decode_string(data, off)
                    root = struct.unpack(">Q", data[off : off + 8])[0]
                    off += 8
                    posts.append(
                        {
                            "post_num": post_num,
                            "creation_date": creation_date,
                            "subject": subject,
                            "author": author,
                            "root": root,
                        }
                    )
                return {"posts": posts}
            return {"error": result}
        finally:
            await self._disconnect_after_command()

    async def update_post(self, board: str, post_num: int, fields: dict) -> dict:
        await self._connect_for_command()
        try:
            tlv_parts = []
            field_count = 0

            if "content" in fields:
                content_bytes = fields["content"].encode("utf-8")
                tlv_parts.append(bytes([0x01]))
                tlv_parts.append(struct.pack(">I", len(content_bytes)))
                tlv_parts.append(content_bytes)
                field_count += 1

            if "subject" in fields:
                subject_bytes = fields["subject"].encode("utf-8")
                tlv_parts.append(bytes([0x02, len(subject_bytes)]))
                tlv_parts.append(subject_bytes)
                field_count += 1

            if "options" in fields:
                options_bytes = fields["options"].encode("utf-8")
                tlv_parts.append(bytes([0x03, len(options_bytes)]))
                tlv_parts.append(options_bytes)
                field_count += 1

            if "tags" in fields:
                tags_bytes = fields["tags"].encode("utf-8")
                tlv_parts.append(bytes([0x04, len(tags_bytes)]))
                tlv_parts.append(tags_bytes)
                field_count += 1

            if "sticky" in fields:
                tlv_parts.append(bytes([0x05]))
                tlv_parts.append(struct.pack(">i", int(fields["sticky"])))
                field_count += 1

            if "closed" in fields:
                tlv_parts.append(bytes([0x06, 1 if fields["closed"] else 0]))
                field_count += 1

            payload = (
                encode_string(board)
                + struct.pack(">Q", post_num)
                + bytes([field_count])
                + b"".join(tlv_parts)
            )
            await self._send_request(0x15, payload)
            ok, result = await self._recv_response()
            return result if ok else {"error": result}
        finally:
            await self._disconnect_after_command()

    async def delete_post(self, board: str, post_num: int) -> dict:
        await self._connect_for_command()
        try:
            await self._send_request(
                0x16, encode_string(board), struct.pack(">Q", post_num)
            )
            ok, result = await self._recv_response()
            return result if ok else {"error": result}
        finally:
            await self._disconnect_after_command()

    async def query_posts(
        self,
        board: str,
        where: str | None = None,
        values: list | None = None,
        orderby: str | None = None,
        limit: int = 0,
    ) -> dict:
        await self._connect_for_command()
        try:
            board_bytes = encode_string(board)

            if where:
                where_bytes = where.encode("utf-8")
                where_part = struct.pack(">H", len(where_bytes)) + where_bytes
            else:
                where_part = struct.pack(">H", 0)

            value_count = len(values) if values else 0
            value_parts = [bytes([value_count])]

            if values:
                for v in values:
                    if isinstance(v, int):
                        value_parts.append(bytes([0x01]))
                        value_parts.append(struct.pack(">q", v))
                    else:
                        v_bytes = str(v).encode("utf-8")
                        value_parts.append(bytes([0x02, len(v_bytes)]))
                        value_parts.append(v_bytes)

            if orderby:
                orderby_bytes = orderby.encode("utf-8")
                orderby_part = struct.pack(">H", len(orderby_bytes)) + orderby_bytes
            else:
                orderby_part = struct.pack(">H", 0)

            limit_part = struct.pack(">I", limit)

            payload = (
                board_bytes
                + where_part
                + b"".join(value_parts)
                + orderby_part
                + limit_part
            )

            await self._send_request(0x19, payload)
            ok, result = await self._recv_response()

            if ok:
                data = result["data"]
                if not data:
                    return {"posts": []}
                posts = []
                off = 0
                while off < len(data):
                    post_num = struct.unpack(">Q", data[off : off + 8])[0]
                    off += 8
                    last_modified = struct.unpack(">q", data[off : off + 8])[0]
                    off += 8
                    creation_date = struct.unpack(">q", data[off : off + 8])[0]
                    off += 8
                    last_bumped = struct.unpack(">q", data[off : off + 8])[0]
                    off += 8
                    closed = data[off]
                    off += 1
                    sticky = struct.unpack(">i", data[off : off + 4])[0]
                    off += 4
                    tags, off = decode_string(data, off)
                    subject, off = decode_string(data, off)
                    options, off = decode_string(data, off)
                    root = struct.unpack(">Q", data[off : off + 8])[0]
                    off += 8
                    author, off = decode_string(data, off)
                    signature, off = decode_string(data, off)
                    posts.append(
                        {
                            "post_num": post_num,
                            "last_modified": last_modified,
                            "creation_date": creation_date,
                            "last_bumped": last_bumped,
                            "closed": bool(closed),
                            "sticky": sticky,
                            "tags": tags,
                            "subject": subject,
                            "options": options,
                            "root": root,
                            "author": author,
                            "signature": signature,
                        }
                    )
                return {"posts": posts}
            return {"error": result}
        finally:
            await self._disconnect_after_command()

    async def promote_user(self, username: str) -> dict:
        await self._connect_for_command()
        try:
            await self._send_request(0x20, encode_string(username))
            ok, result = await self._recv_response()
            return result if ok else {"error": result}
        finally:
            await self._disconnect_after_command()

    async def demote_user(self, username: str) -> dict:
        await self._connect_for_command()
        try:
            await self._send_request(0x21, encode_string(username))
            ok, result = await self._recv_response()
            return result if ok else {"error": result}
        finally:
            await self._disconnect_after_command()

    def _build_signed_payload(self, post: dict) -> bytes:
        author_bytes = post["author"].encode("utf-8")
        tags_bytes = (post.get("tags") or "").encode("utf-8")
        subject_bytes = (post.get("subject") or "").encode("utf-8")
        options_bytes = (post.get("options") or "").encode("utf-8")
        content_bytes = (post.get("content") or "").encode("utf-8")

        return (
            struct.pack(">Q", post["post_num"])
            + struct.pack(">q", post["creation_date"])
            + struct.pack(">q", post["last_modified"])
            + struct.pack("B", len(author_bytes))
            + author_bytes
            + struct.pack("B", len(tags_bytes))
            + tags_bytes
            + struct.pack("B", len(subject_bytes))
            + subject_bytes
            + struct.pack("B", len(options_bytes))
            + options_bytes
            + struct.pack(">I", len(content_bytes))
            + content_bytes
        )

    async def sign_post(self, board: str, post: dict) -> dict:
        await self._connect_for_command()
        try:
            payload = self._build_signed_payload(post)
            signature = self.identity.sign(payload)
            signature_hex = signature.hex()

            await self._send_request(
                0x22,
                encode_string(board),
                struct.pack(">Q", post["post_num"]),
                encode_string(signature_hex),
            )
            ok, result = await self._recv_response()
            if ok:
                return {"signature": signature_hex}
            return {"error": result}
        finally:
            await self._disconnect_after_command()


def format_timestamp(ts: int) -> str:
    from datetime import datetime

    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def print_post(post: dict, board: str | None = None):
    if board:
        click.echo(f"Post #{post['post_num']} in /{click.style(board, fg='cyan')}")
    else:
        click.echo(f"Post #{post['post_num']}")
    click.echo(f"Subject: {click.style(post['subject'], bold=True)}")
    click.echo(f"Author: {post['author']}")
    click.echo(f"Created: {format_timestamp(post['creation_date'])}")
    if post.get("last_modified") and post["last_modified"] != post["creation_date"]:
        click.echo(f"Modified: {format_timestamp(post['last_modified'])}")
    if post.get("last_bumped"):
        click.echo(f"Bumped: {format_timestamp(post['last_bumped'])}")
    if post.get("root"):
        click.echo(f"Reply to: #{post['root']}")
    if post.get("closed"):
        click.echo(click.style("Status: CLOSED", fg="red"))
    if post.get("sticky"):
        click.echo(click.style(f"Sticky: #{post['sticky']}", fg="yellow"))
    if post.get("tags"):
        click.echo(f"Tags: {post['tags']}")
    if post.get("options"):
        click.echo(f"Options: {post['options']}")
    if post.get("signature"):
        click.echo(f"Signature: {post['signature']}")
    click.echo("─" * 40)
    click.echo(post["content"])


async def repl(client: BonnetClient):
    prompt = click.style("bonnet> ", fg="green", bold=True)
    loop = asyncio.get_event_loop()

    while True:
        try:
            line = await loop.run_in_executor(None, lambda: input(prompt))
        except EOFError:
            click.echo("\nGoodbye!")
            break

        line = line.strip()
        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()

        try:
            if cmd == "/quit" or cmd == "quit":
                click.echo("Goodbye!")
                break

            elif cmd == "/help" or cmd == "help":
                click.echo(
                    """Commands:
  /connect <url> [--pubkey=HEX]
                        Connect to server (e.g., ws://localhost:2272)
  /disconnect           Disconnect from server
  /trust <host> <hex>   Trust server pubkey
  /known                List known servers
  /forget <host>        Remove server from known list
  register <user@reg>   Register new user
  get <username>        Get user info
  list-users [off] [n]  List users
  create-board <name>   Create board (admin)
  close-board <name>    Close board (read-only, admin)
  delete-board <name>   Delete board permanently (admin)
  list-boards           List boards
  create-post <board> [root]
                        Create post (interactive)
  get-post <board> <n>  Get post
  list-posts <board> [off] [n]
                        List posts
  query-posts <board> [--where=...] [--value=...] [--orderby=...] [--limit=N]
                        Query posts by metadata
  update-post <board> <n>
                        Edit post (interactive)
  sign-post <board> <n>
                        Sign a post
  delete-post <board> <n>
                        Delete post
  promote <username>    Promote to moderator (admin)
  demote <username>     Remove moderator (admin)
  whoami                Show identity & connection status
  /help                 Show this help
  /quit                 Exit"""
                )

            elif cmd == "/connect":
                if not len(parts) > 1:
                    click.echo("Usage: /connect <url> [--pubkey=HEX]")
                    continue
                url = parts[1]
                server_pubkey = None

                for p in parts[2:]:
                    if p.startswith("--pubkey="):
                        server_pubkey = bytes.fromhex(p.split("=", 1)[1])

                try:
                    await client.configure(url, server_pubkey)
                except ServerUnknownError as e:
                    click.echo(
                        click.style(f"Unknown server: {e.hostname}", fg="yellow")
                    )
                    click.echo(
                        "Use: /connect <url> --pubkey=<hex>\n"
                        "Or:  /trust <hostname> <pubkey_hex>"
                    )
                except Exception as e:
                    import traceback

                    click.echo(click.style(f"Configuration failed: {e}", fg="red"))
                    if client.verbose:
                        traceback.print_exc()

            elif cmd == "/disconnect":
                client.url = None
                client.server_pubkey = None
                click.echo("Server configuration cleared.")

            elif cmd == "/trust":
                if len(parts) < 3:
                    click.echo("Usage: /trust <hostname> <pubkey_hex>")
                    continue
                hostname = parts[1]
                try:
                    pubkey = bytes.fromhex(parts[2])
                    if len(pubkey) != 32:
                        click.echo("Public key must be 32 bytes (64 hex chars)")
                        continue
                    client.known_servers.save(hostname, pubkey)
                    click.echo(click.style(f"Trusted {hostname}", fg="green"))
                except ValueError:
                    click.echo("Invalid hex pubkey")

            elif cmd == "/known":
                servers = client.known_servers.list()
                if not servers:
                    click.echo("No known servers.")
                else:
                    for s in servers:
                        pubkey = client.known_servers.get(s)
                        click.echo(f"  {s}: {hex_truncate(pubkey) if pubkey else '?'}")

            elif cmd == "/forget":
                if len(parts) < 2:
                    click.echo("Usage: /forget <hostname>")
                    continue
                hostname = parts[1]
                if client.known_servers.remove(hostname):
                    click.echo(click.style(f"Forgot {hostname}", fg="green"))
                else:
                    click.echo(f"Unknown server: {hostname}")

            elif cmd == "whoami":
                pubkey_hex = client.identity.public_key.hex()
                click.echo(f"Identity: {pubkey_hex[:16]}...{pubkey_hex[-8:]}")
                if client.is_configured():
                    click.echo(
                        f"Server: {click.style('yes', fg='green')} ({client.url})"
                    )
                else:
                    click.echo(f"Server: {click.style('not configured', fg='yellow')}")
                    click.echo("Use /connect <url> to configure a server.")

            elif cmd == "register":
                if not len(parts) > 1:
                    click.echo("Usage: register <username@registrar>")
                    continue
                user_reg = parts[1]
                if "@" not in user_reg:
                    click.echo("Format: username@registrar")
                    continue
                username, registrar = user_reg.split("@", 1)
                try:
                    result = await client.register(username, registrar)
                    if "error" in result:
                        err = result["error"]
                        click.echo(
                            click.style(
                                f"Error 0x{err['code']:04x}: {err['message']}",
                                fg="red",
                            )
                        )
                    else:
                        click.echo(click.style("Registered!", fg="green"))
                except NotConfiguredError:
                    click.echo(
                        click.style("Not configured. Use /connect first.", fg="yellow")
                    )

            elif cmd == "get":
                if not len(parts) > 1:
                    click.echo("Usage: get <username>")
                    continue
                username = parts[1]
                try:
                    result = await client.get_user(username)
                    if "error" in result:
                        err = result["error"]
                        click.echo(
                            click.style(
                                f"Error 0x{err['code']:04x}: {err['message']}",
                                fg="red",
                            )
                        )
                    else:
                        click.echo(f"Username: {username}")
                        click.echo(f"Registrar: {result['registrar']}")
                        click.echo(f"Public Key: {result['pubkey']}")
                except NotConfiguredError:
                    click.echo(
                        click.style("Not configured. Use /connect first.", fg="yellow")
                    )

            elif cmd == "list-users":
                if not len(parts) > 1:
                    offset = 0
                    limit = 100
                elif len(parts) == 2:
                    offset = int(parts[1])
                    limit = 100
                else:
                    offset = int(parts[1])
                    limit = int(parts[2])
                try:
                    result = await client.list_users(offset, limit)
                    if "error" in result:
                        err = result["error"]
                        click.echo(
                            click.style(
                                f"Error 0x{err['code']:04x}: {err['message']}",
                                fg="red",
                            )
                        )
                    else:
                        users = result["users"]
                        if not users:
                            click.echo("No users.")
                        else:
                            for u in users:
                                click.echo(f"  {u}")
                except NotConfiguredError:
                    click.echo(
                        click.style("Not configured. Use /connect first.", fg="yellow")
                    )

            elif cmd == "create-board":
                if not len(parts) > 1:
                    click.echo("Usage: create-board <name>")
                    continue
                name = parts[1]
                try:
                    result = await client.create_board(name)
                    if "error" in result:
                        err = result["error"]
                        click.echo(
                            click.style(
                                f"Error 0x{err['code']:04x}: {err['message']}",
                                fg="red",
                            )
                        )
                    else:
                        click.echo(click.style(f"Board '{name}' created.", fg="green"))
                except NotConfiguredError:
                    click.echo(
                        click.style("Not configured. Use /connect first.", fg="yellow")
                    )

            elif cmd == "close-board":
                if not len(parts) > 1:
                    click.echo("Usage: close-board <name>")
                    continue
                name = parts[1]
                try:
                    result = await client.close_board(name)
                    if "error" in result:
                        err = result["error"]
                        click.echo(
                            click.style(
                                f"Error 0x{err['code']:04x}: {err['message']}",
                                fg="red",
                            )
                        )
                    else:
                        click.echo(
                            click.style(
                                f"Board '{name}' closed (read-only).", fg="green"
                            )
                        )
                except NotConfiguredError:
                    click.echo(
                        click.style("Not configured. Use /connect first.", fg="yellow")
                    )

            elif cmd == "delete-board":
                if not len(parts) > 1:
                    click.echo("Usage: delete-board <name>")
                    continue
                name = parts[1]
                if not click.confirm(f"Permanently delete board '{name}'?"):
                    continue
                try:
                    result = await client.delete_board(name)
                    if "error" in result:
                        err = result["error"]
                        click.echo(
                            click.style(
                                f"Error 0x{err['code']:04x}: {err['message']}",
                                fg="red",
                            )
                        )
                    else:
                        click.echo(click.style(f"Board '{name}' deleted.", fg="green"))
                except NotConfiguredError:
                    click.echo(
                        click.style("Not configured. Use /connect first.", fg="yellow")
                    )

            elif cmd == "list-boards":
                try:
                    result = await client.list_boards()
                    if "error" in result:
                        err = result["error"]
                        click.echo(
                            click.style(
                                f"Error 0x{err['code']:04x}: {err['message']}",
                                fg="red",
                            )
                        )
                    else:
                        boards = result["boards"]
                        if not boards:
                            click.echo("No boards.")
                        else:
                            for name, closed in boards:
                                if closed:
                                    click.echo(
                                        f"  [{click.style('closed', fg='yellow')}] /{name}"
                                    )
                                else:
                                    click.echo(f"  /{name}")
                except NotConfiguredError:
                    click.echo(
                        click.style("Not configured. Use /connect first.", fg="yellow")
                    )

            elif cmd == "create-post":
                if len(parts) < 2:
                    click.echo("Usage: create-post <board> [root]")
                    continue
                board = parts[1]
                root = 0
                if len(parts) >= 3:
                    try:
                        root = int(parts[2])
                    except ValueError:
                        pass
                try:
                    subject = await loop.run_in_executor(
                        None, lambda: click.prompt("Subject", type=str)
                    )
                    if not subject.strip():
                        click.echo("Aborted: empty subject.")
                        continue

                    tags = await loop.run_in_executor(
                        None,
                        lambda: click.prompt(
                            "Tags (optional, comma-separated)",
                            default="",
                            show_default=False,
                        ),
                    )
                    options = await loop.run_in_executor(
                        None,
                        lambda: click.prompt(
                            "Options (optional)", default="", show_default=False
                        ),
                    )

                    click.echo("Content (end with '.' or 'END' on its own line):")
                    lines = []
                    try:
                        while True:
                            line = await loop.run_in_executor(None, input)
                            if line.strip() == "." or line.strip().upper() == "END":
                                break
                            lines.append(line)
                    except EOFError:
                        pass
                    content = "\n".join(lines)
                    if not content.strip():
                        click.echo("Aborted: empty content.")
                        continue

                    click.echo("")
                    click.echo(click.style("--- Preview ---", bold=True))
                    click.echo(f"Board: /{click.style(board, fg='cyan')}")
                    if root:
                        click.echo(f"Reply to: #{root}")
                    click.echo(f"Subject: {subject}")
                    if tags.strip():
                        click.echo(f"Tags: {tags}")
                    if options.strip():
                        click.echo(f"Options: {options}")
                    click.echo("Content:")
                    for line in content.split("\n")[:10]:
                        click.echo(f"  {line}")
                    if len(content.split("\n")) > 10:
                        click.echo(
                            f"  ... ({len(content.split('\n')) - 10} more lines)"
                        )
                    click.echo(click.style("-" * 40, dim=True))

                    if not await loop.run_in_executor(
                        None, lambda: click.confirm("Submit?", default=True)
                    ):
                        click.echo("Cancelled.")
                        continue

                    result = await client.create_post(
                        board, root, subject, content, tags, options
                    )
                    if "error" in result:
                        err = result["error"]
                        click.echo(
                            click.style(
                                f"Error 0x{err['code']:04x}: {err['message']}",
                                fg="red",
                            )
                        )
                    else:
                        click.echo(
                            click.style(
                                f"Post #{result['post_num']} created.", fg="green"
                            )
                        )
                        sign_prompt = await loop.run_in_executor(
                            None, lambda: click.confirm("Sign this post?", default=True)
                        )
                        if sign_prompt:
                            sign_result = await client.sign_post(board, result)
                            if "error" in sign_result:
                                err = sign_result["error"]
                                click.echo(
                                    click.style(
                                        f"Error 0x{err['code']:04x}: {err['message']}",
                                        fg="red",
                                    )
                                )
                            else:
                                click.echo(
                                    click.style(
                                        f"Post #{result['post_num']} signed.",
                                        fg="green",
                                    )
                                )
                except NotConfiguredError:
                    click.echo(
                        click.style("Not configured. Use /connect first.", fg="yellow")
                    )

            elif cmd == "get-post":
                if len(parts) < 3:
                    click.echo("Usage: get-post <board> <post_num>")
                    continue
                board = parts[1]
                post_num = int(parts[2])
                try:
                    result = await client.get_post(board, post_num)
                    if "error" in result:
                        err = result["error"]
                        click.echo(
                            click.style(
                                f"Error 0x{err['code']:04x}: {err['message']}",
                                fg="red",
                            )
                        )
                    else:
                        print_post(result, board)
                except NotConfiguredError:
                    click.echo(
                        click.style("Not configured. Use /connect first.", fg="yellow")
                    )

            elif cmd == "list-posts":
                if len(parts) < 2:
                    click.echo("Usage: list-posts <board> [offset] [limit]")
                    continue
                board = parts[1]
                offset = int(parts[2]) if len(parts) > 2 else 0
                limit = int(parts[3]) if len(parts) > 3 else 50
                try:
                    result = await client.list_posts(board, offset, limit)
                    if "error" in result:
                        err = result["error"]
                        click.echo(
                            click.style(
                                f"Error 0x{err['code']:04x}: {err['message']}",
                                fg="red",
                            )
                        )
                    else:
                        posts = result["posts"]
                        if not posts:
                            click.echo("No posts.")
                        else:
                            for p in posts:
                                click.echo(
                                    f"#{p['post_num']:4} | {p['subject'][:30]:30} | {p['author']:20} | {format_timestamp(p['creation_date'])}"
                                )
                except NotConfiguredError:
                    click.echo(
                        click.style("Not configured. Use /connect first.", fg="yellow")
                    )

            elif cmd == "query-posts":
                if len(parts) < 2:
                    click.echo(
                        "Usage: query-posts <board> [--where=...] [--value=...] [--orderby=...] [--limit=N]"
                    )
                    continue
                board = parts[1]
                where = None
                values = []
                orderby = None
                limit = 0
                for p in parts[2:]:
                    if p.startswith("--where="):
                        where = p.split("=", 1)[1]
                    elif p.startswith("--value="):
                        v = p.split("=", 1)[1]
                        try:
                            values.append(int(v))
                        except ValueError:
                            values.append(v)
                    elif p.startswith("--orderby="):
                        orderby = p.split("=", 1)[1]
                    elif p.startswith("--limit="):
                        limit = int(p.split("=", 1)[1])
                try:
                    result = await client.query_posts(
                        board,
                        where=where,
                        values=values if values else None,
                        orderby=orderby,
                        limit=limit,
                    )
                    if "error" in result:
                        err = result["error"]
                        click.echo(
                            click.style(
                                f"Error 0x{err['code']:04x}: {err['message']}",
                                fg="red",
                            )
                        )
                    else:
                        posts = result["posts"]
                        if not posts:
                            click.echo("No posts found.")
                        else:
                            for p in posts:
                                status = ""
                                if p.get("sticky"):
                                    status += click.style(
                                        f" [sticky:{p['sticky']}]", fg="yellow"
                                    )
                                if p.get("closed"):
                                    status += click.style(" [closed]", fg="red")
                                click.echo(
                                    f"#{p['post_num']:4} | {p['subject'][:30]:30} | {p['author']:20} | {format_timestamp(p['creation_date'])}{status}"
                                )
                except NotConfiguredError:
                    click.echo(
                        click.style("Not configured. Use /connect first.", fg="yellow")
                    )

            elif cmd == "update-post":
                if len(parts) < 3:
                    click.echo("Usage: update-post <board> <post_num>")
                    continue
                board = parts[1]
                post_num = int(parts[2])
                try:
                    result = await client.get_post(board, post_num)
                    if "error" in result:
                        err = result["error"]
                        click.echo(
                            click.style(
                                f"Error 0x{err['code']:04x}: {err['message']}", fg="red"
                            )
                        )
                        continue

                    click.echo(
                        click.style(f"--- Current Post #{post_num} ---", bold=True)
                    )
                    click.echo(f"Subject: {result['subject']}")
                    click.echo(f"Tags: {result.get('tags', '')}")
                    click.echo(f"Options: {result.get('options', '')}")
                    click.echo("Content:")
                    for line in result["content"].split("\n")[:5]:
                        click.echo(f"  {line}")
                    if len(result["content"].split("\n")) > 5:
                        click.echo(
                            f"  ... ({len(result['content'].split('\n')) - 5} more lines)"
                        )
                    click.echo(click.style("-" * 40, dim=True))
                    click.echo("")

                    fields = {}

                    new_val = await loop.run_in_executor(
                        None, lambda: input(f"Subject [{result['subject']}]: ")
                    )
                    if new_val.strip():
                        fields["subject"] = new_val.strip()

                    new_val = await loop.run_in_executor(
                        None, lambda: input(f"Tags [{result.get('tags', '')}]: ")
                    )
                    if new_val.strip():
                        fields["tags"] = new_val.strip()

                    new_val = await loop.run_in_executor(
                        None, lambda: input(f"Options [{result.get('options', '')}]: ")
                    )
                    if new_val.strip():
                        fields["options"] = new_val.strip()

                    click.echo(
                        "Content (end with '.' or 'END', or blank to keep current):"
                    )
                    lines = []
                    try:
                        while True:
                            line = await loop.run_in_executor(None, input)
                            if line.strip() == "." or line.strip().upper() == "END":
                                break
                            if not line.strip() and not lines:
                                break
                            lines.append(line)
                    except EOFError:
                        pass
                    if lines:
                        fields["content"] = "\n".join(lines)

                    sticky_current = result.get("sticky", 0)
                    new_val = await loop.run_in_executor(
                        None, lambda: input(f"Sticky order [{sticky_current}]: ")
                    )
                    if new_val.strip():
                        try:
                            fields["sticky"] = int(new_val.strip())
                        except ValueError:
                            click.echo("Invalid sticky value, skipping.")

                    closed_current = "yes" if result.get("closed") else "no"
                    new_val = await loop.run_in_executor(
                        None, lambda: input(f"Closed [{closed_current}] (yes/no): ")
                    )
                    if new_val.strip().lower() in ("yes", "y", "1", "true"):
                        fields["closed"] = True
                    elif new_val.strip().lower() in ("no", "n", "0", "false"):
                        fields["closed"] = False

                    if not fields:
                        click.echo("No changes.")
                        continue

                    click.echo("")
                    click.echo(click.style("--- Preview of Changes ---", bold=True))
                    if "subject" in fields:
                        click.echo(
                            f"Subject: {result['subject']} → {fields['subject']}"
                        )
                    if "tags" in fields:
                        click.echo(f"Tags: {result.get('tags', '')} → {fields['tags']}")
                    if "options" in fields:
                        click.echo(
                            f"Options: {result.get('options', '')} → {fields['options']}"
                        )
                    if "content" in fields:
                        click.echo("Content: (changed)")
                        for line in fields["content"].split("\n")[:5]:
                            click.echo(f"  {line}")
                        if len(fields["content"].split("\n")) > 5:
                            click.echo(
                                f"  ... ({len(fields['content'].split('\n')) - 5} more lines)"
                            )
                    if "sticky" in fields:
                        click.echo(
                            f"Sticky: {result.get('sticky', 0)} → {fields['sticky']}"
                        )
                    if "closed" in fields:
                        click.echo(
                            f"Closed: {result.get('closed', False)} → {fields['closed']}"
                        )
                    click.echo(click.style("-" * 40, dim=True))

                    if not await loop.run_in_executor(
                        None, lambda: click.confirm("Submit changes?", default=True)
                    ):
                        click.echo("Cancelled.")
                        continue

                    update_result = await client.update_post(board, post_num, fields)
                    if "error" in update_result:
                        err = update_result["error"]
                        click.echo(
                            click.style(
                                f"Error 0x{err['code']:04x}: {err['message']}", fg="red"
                            )
                        )
                    else:
                        click.echo(click.style("Post updated.", fg="green"))

                except NotConfiguredError:
                    click.echo(
                        click.style("Not configured. Use /connect first.", fg="yellow")
                    )

            elif cmd == "sign-post":
                if len(parts) < 3:
                    click.echo("Usage: sign-post <board> <post_num>")
                    continue
                board = parts[1]
                post_num = int(parts[2])
                try:
                    result = await client.get_post(board, post_num)
                    if "error" in result:
                        err = result["error"]
                        click.echo(
                            click.style(
                                f"Error 0x{err['code']:04x}: {err['message']}", fg="red"
                            )
                        )
                        continue

                    if result.get("signature"):
                        click.echo(
                            click.style(
                                f"Post already signed: {result['signature'][:32]}...",
                                fg="yellow",
                            )
                        )
                        if not await loop.run_in_executor(
                            None, lambda: click.confirm("Re-sign?", default=False)
                        ):
                            click.echo("Cancelled.")
                            continue

                    click.echo(click.style(f"--- Post #{post_num} ---", bold=True))
                    click.echo(f"Subject: {result['subject']}")
                    click.echo(f"Author: {result['author']}")
                    click.echo(f"Created: {format_timestamp(result['creation_date'])}")
                    click.echo("Content:")
                    for line in result["content"].split("\n")[:5]:
                        click.echo(f"  {line}")
                    if len(result["content"].split("\n")) > 5:
                        click.echo(
                            f"  ... ({len(result['content'].split('\n')) - 5} more lines)"
                        )
                    click.echo(click.style("-" * 40, dim=True))

                    if not await loop.run_in_executor(
                        None, lambda: click.confirm("Sign this post?", default=True)
                    ):
                        click.echo("Cancelled.")
                        continue

                    sign_result = await client.sign_post(board, result)
                    if "error" in sign_result:
                        err = sign_result["error"]
                        click.echo(
                            click.style(
                                f"Error 0x{err['code']:04x}: {err['message']}", fg="red"
                            )
                        )
                    else:
                        click.echo(click.style(f"Post #{post_num} signed.", fg="green"))
                except NotConfiguredError:
                    click.echo(
                        click.style("Not configured. Use /connect first.", fg="yellow")
                    )

            elif cmd == "delete-post":
                if len(parts) < 3:
                    click.echo("Usage: delete-post <board> <post_num>")
                    continue
                board = parts[1]
                post_num = int(parts[2])
                if not click.confirm(f"Delete post #{post_num} in /{board}?"):
                    continue
                try:
                    result = await client.delete_post(board, post_num)
                    if "error" in result:
                        err = result["error"]
                        click.echo(
                            click.style(
                                f"Error 0x{err['code']:04x}: {err['message']}",
                                fg="red",
                            )
                        )
                    else:
                        click.echo(click.style("Post deleted.", fg="green"))
                except NotConfiguredError:
                    click.echo(
                        click.style("Not configured. Use /connect first.", fg="yellow")
                    )

            elif cmd == "promote":
                if not len(parts) > 1:
                    click.echo("Usage: promote <username>")
                    continue
                username = parts[1]
                try:
                    result = await client.promote_user(username)
                    if "error" in result:
                        err = result["error"]
                        click.echo(
                            click.style(
                                f"Error 0x{err['code']:04x}: {err['message']}",
                                fg="red",
                            )
                        )
                    else:
                        click.echo(
                            click.style(
                                f"{username} promoted to moderator.", fg="green"
                            )
                        )
                except NotConfiguredError:
                    click.echo(
                        click.style("Not configured. Use /connect first.", fg="yellow")
                    )

            elif cmd == "demote":
                if not len(parts) > 1:
                    click.echo("Usage: demote <username>")
                    continue
                username = parts[1]
                try:
                    result = await client.demote_user(username)
                    if "error" in result:
                        err = result["error"]
                        click.echo(
                            click.style(
                                f"Error 0x{err['code']:04x}: {err['message']}",
                                fg="red",
                            )
                        )
                    else:
                        click.echo(
                            click.style(
                                f"{username} demoted from moderator.", fg="green"
                            )
                        )
                except NotConfiguredError:
                    click.echo(
                        click.style("Not configured. Use /connect first.", fg="yellow")
                    )

            else:
                click.echo(f"Unknown command: {cmd}. Type /help for commands.")

        except KeyboardInterrupt:
            click.echo("\nInterrupted. Type /quit to exit.")
        except websockets.exceptions.ConnectionClosed as e:
            click.echo(click.style(f"Connection closed: {e.code} {e.reason}", fg="red"))
            await client.disconnect()
        except Exception as e:
            import traceback

            click.echo(click.style(f"Error: {e}", fg="red"))
            if client.verbose:
                traceback.print_exc()
            await client.disconnect()


@click.command()
def main():
    if not IDENTITY_PATH.exists():
        click.echo(f"No identity found at {IDENTITY_PATH}. Generating new identity...")
        identity = Identity.generate()
        identity.save(IDENTITY_PATH)
        click.echo(click.style("Identity generated!", fg="green"))
    else:
        identity = Identity.load(IDENTITY_PATH)

    client = BonnetClient(identity)
    click.echo(f"Bonnet Client CLI. Identity: {identity.public_key.hex()[:16]}...")
    click.echo("Type /help for commands.")

    asyncio.run(repl(client))


if __name__ == "__main__":
    main()
