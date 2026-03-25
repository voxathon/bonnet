import struct
import websockets
from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey, PublicKey, Box
from nacl.exceptions import CryptoError

from .protocol import (
    encode_frame,
    decode_frame,
    parse_response,
    ResponseStatus,
    parse_error_response,
    decode_redirect,
    build_register,
    build_get_user,
    build_list_users,
    build_list_peers,
    build_board_create,
    build_board_list,
    build_board_close,
    build_board_delete,
    build_post_create,
    build_post_get,
    build_post_list,
    build_post_update,
    build_post_delete,
    build_query_posts,
    build_post_sign,
    build_user_promote,
    build_user_demote,
    build_get_pubkey,
    build_rule_create,
    build_rule_get,
    build_rule_get_by_name,
    build_rule_list,
    build_rule_update,
    build_report_create,
    build_report_get,
    build_report_list_by_culprit,
    build_report_sign,
    build_report_list_since,
    build_punishment_create,
    build_punishment_get,
    build_punishment_list_active,
    build_is_banned,
    ProtocolError,
    parse_register_resp,
    parse_list_users_resp,
    parse_list_peers_resp,
    parse_board_list_resp,
    parse_post_create_resp,
    parse_post_get_resp,
    parse_post_list_resp,
    parse_query_posts_resp,
    parse_get_pubkey_resp,
    parse_rule_resp,
    parse_rule_list_resp,
    parse_report_resp,
    parse_report_list_resp,
    parse_punishment_resp,
    parse_punishment_list_resp,
    parse_is_banned_resp,
    encode_tlv_str,
    encode_tlv_i32,
    encode_tlv_u8,
)
from .identity import IdentityStore
from .models import (
    User,
    Board,
    Post,
    PostSummary,
    PostCreateResult,
    Rule,
    Report,
    Punishment,
    BannedStatus,
    Peer,
)


class BonnetError(Exception):
    pass


class EncryptedSession:
    def __init__(self, private_key: bytes, server_pubkey: bytes):
        signing_key = SigningKey(private_key)
        self.x25519_private = signing_key.to_curve25519_private_key()

        verify_key = VerifyKey(server_pubkey)
        self.x25519_public = verify_key.to_curve25519_public_key()

        self.box = Box(self.x25519_private, self.x25519_public)
        self.nonce = 0

    def _next_nonce(self) -> bytes:
        nonce = self.nonce.to_bytes(24, "little")
        self.nonce += 1
        return nonce

    def encrypt(self, plaintext: bytes) -> bytes:
        return self.box.encrypt(plaintext, self._next_nonce())

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.box.decrypt(ciphertext)


class BonnetClient:
    BONNET_URL = "ws://localhost:2272"

    def __init__(self, identity_store: IdentityStore, bonnet_url: str | None = None):
        self.identity_store = identity_store
        self.bonnet_url = bonnet_url or self.BONNET_URL
        self.username: str | None = None
        self.websocket: websockets.WebSocketClientProtocol | None = None
        self.session: EncryptedSession | None = None
        self.server_pubkey: bytes | None = None
        self._private_key: bytes | None = None
        self._public_key: bytes | None = None

    async def connect(self, username: str) -> None:
        self.username = username
        self._private_key, self._public_key = self.identity_store.get_or_create(
            username
        )

        self.websocket = await websockets.connect(self.bonnet_url)

        frame = await self.websocket.recv()
        _, payload = decode_frame(frame)

        server_pubkey = payload[:32]
        challenge = payload[32:]

        self.server_pubkey = server_pubkey
        self.session = EncryptedSession(self._private_key, server_pubkey)

        signing_key = SigningKey(self._private_key)
        signature = signing_key.sign(challenge).signature

        handshake = self._public_key + signature
        await self.websocket.send(encode_frame(handshake))

        if not self.identity_store.is_registered(username):
            await self._register(username)

    async def _register(self, username: str) -> str:
        cmd = build_register(username, "localhost")
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            registered_name = parse_register_resp(payload)
            self.identity_store.mark_registered(username)
            return registered_name
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        else:
            raise BonnetError(f"Unexpected response status: {status}")

    async def _send_command(self, cmd: bytes) -> bytes:
        if not self.session or not self.websocket:
            raise BonnetError("Not connected")

        encrypted = self.session.encrypt(cmd)
        await self.websocket.send(encode_frame(encrypted))

        frame = await self.websocket.recv()
        _, payload = decode_frame(frame)

        return self.session.decrypt(payload)

    async def close(self):
        if self.websocket:
            await self.websocket.close()
            self.websocket = None
            self.session = None

    async def __aenter__(self) -> "BonnetClient":
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def get_user(self, pubkey: bytes) -> User | None:
        cmd = build_get_user(pubkey)
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_list_users_resp(payload)[0] if payload else None
        elif status == ResponseStatus.ERROR:
            return None
        raise BonnetError(f"Unexpected response: {status}")

    async def list_users(self, offset: int = 0, limit: int = 100) -> list[User]:
        cmd = build_list_users(offset, limit)
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_list_users_resp(payload)
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def list_peers(self) -> list[Peer]:
        cmd = build_list_peers()
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_list_peers_resp(payload)
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def board_create(self, name: str) -> Board:
        cmd = build_board_create(name)
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            boards = await self.board_list()
            for b in boards:
                if b.name == name:
                    return b
            raise BonnetError(f"Board {name} not found after creation")
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def board_list(self) -> list[Board]:
        cmd = build_board_list()
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_board_list_resp(payload)
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        elif status == ResponseStatus.REDIRECT:
            raise BonnetError(f"Redirect to: {decode_redirect(payload)}")
        raise BonnetError(f"Unexpected response: {status}")

    async def board_close(self, name: str) -> None:
        cmd = build_board_close(name)
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def board_delete(self, name: str) -> None:
        cmd = build_board_delete(name)
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def post_create(
        self,
        board: str,
        subject: str,
        content: str,
        tags: str = "",
        options: str = "",
        root: int = 0,
    ) -> PostCreateResult:
        cmd = build_post_create(board, root, subject, tags, options, content)
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_post_create_resp(payload)
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        elif status == ResponseStatus.REDIRECT:
            raise BonnetError(f"Redirect to: {decode_redirect(payload)}")
        raise BonnetError(f"Unexpected response: {status}")

    async def post_get(self, board: str, post_num: int) -> Post:
        cmd = build_post_get(board, post_num)
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_post_get_resp(payload)
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        elif status == ResponseStatus.REDIRECT:
            raise BonnetError(f"Redirect to: {decode_redirect(payload)}")
        raise BonnetError(f"Unexpected response: {status}")

    async def post_list(
        self, board: str, offset: int = 0, limit: int = 50
    ) -> list[PostSummary]:
        cmd = build_post_list(board, offset, limit)
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_post_list_resp(payload)
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        elif status == ResponseStatus.REDIRECT:
            raise BonnetError(f"Redirect to: {decode_redirect(payload)}")
        raise BonnetError(f"Unexpected response: {status}")

    async def post_update(
        self,
        board: str,
        post_num: int,
        content: str | None = None,
        subject: str | None = None,
        tags: str | None = None,
        options: str | None = None,
        sticky: int | None = None,
        closed: bool | None = None,
    ) -> None:
        fields = []
        if content is not None:
            fields.append(("content", encode_tlv_str(content)))
        if subject is not None:
            fields.append(("subject", encode_tlv_str(subject)))
        if tags is not None:
            fields.append(("tags", encode_tlv_str(tags)))
        if options is not None:
            fields.append(("options", encode_tlv_str(options)))
        if sticky is not None:
            fields.append(("sticky", encode_tlv_i32(sticky)))
        if closed is not None:
            fields.append(("closed", encode_tlv_u8(1 if closed else 0)))

        if not fields:
            return

        cmd = build_post_update(board, post_num, fields)
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def post_delete(self, board: str, post_num: int) -> None:
        cmd = build_post_delete(board, post_num)
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def query_posts(
        self,
        board: str,
        where: str = "",
        values: list[tuple[int, bytes]] | None = None,
        orderby: str = "last_bumped DESC",
        limit: int = 100,
    ) -> list[PostSummary]:
        cmd = build_query_posts(board, where, values or [], orderby, limit)
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_query_posts_resp(payload)
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        elif status == ResponseStatus.REDIRECT:
            raise BonnetError(f"Redirect to: {decode_redirect(payload)}")
        raise BonnetError(f"Unexpected response: {status}")

    async def post_sign(self, board: str, post_num: int) -> str:
        post = await self.post_get(board, post_num)

        if self._private_key is None:
            raise BonnetError("No identity loaded")

        signing_key = SigningKey(self._private_key)

        from .protocol import encode_string, encode_long_string, struct

        payload = struct.pack(">Q", post.post_num)
        payload += struct.pack(">q", post.creation_date)
        payload += struct.pack(">q", post.last_modified)
        payload += encode_string(post.author)
        payload += encode_string(post.author_registrar)
        payload += encode_string(",".join(post.tags))
        payload += encode_string(post.subject)
        payload += encode_string(post.options)
        payload += encode_long_string(post.content)

        signature = signing_key.sign(payload).signature.hex()

        cmd = build_post_sign(board, post_num, signature)
        resp = await self._send_command(cmd)
        status, resp_payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return signature
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(resp_payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def user_promote(self, username: str) -> None:
        cmd = build_user_promote(username)
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def user_demote(self, username: str) -> None:
        cmd = build_user_demote(username)
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def get_server_pubkey(self) -> str:
        cmd = build_get_pubkey()
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_get_pubkey_resp(payload)
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def rule_create(self, name: str, description: str) -> Rule:
        cmd = build_rule_create(name, description)
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_rule_resp(payload)
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def rule_get(self, rule_num: int) -> Rule:
        cmd = build_rule_get(rule_num)
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_rule_resp(payload)
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def rule_get_by_name(self, name: str) -> Rule:
        cmd = build_rule_get_by_name(name)
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_rule_resp(payload)
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def rule_list(self) -> list[Rule]:
        cmd = build_rule_list()
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_rule_list_resp(payload)
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def rule_update(
        self, rule_num: int, name: str | None = None, description: str | None = None
    ) -> Rule:
        fields = []
        if name is not None:
            from .protocol import encode_string

            fields.append(("name", encode_string(name)))
        if description is not None:
            from .protocol import encode_string

            fields.append(("description", encode_string(description)))

        cmd = build_rule_update(rule_num, fields)
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_rule_resp(payload)
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def report_create(
        self,
        rule_num: int,
        culprit_pubkey: str,
        description: str,
        board: str | None = None,
        post_num: int | None = None,
        origin: str | None = None,
        relay: str | None = None,
    ) -> Report:
        if self._public_key is None:
            raise BonnetError("No identity loaded")

        culprit = bytes.fromhex(culprit_pubkey)
        cmd = build_report_create(
            rule_num,
            culprit,
            self._public_key,
            description,
            board,
            post_num,
            origin,
            relay,
        )
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_report_resp(payload)
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def report_get(self, origin: str, report_num: int) -> Report:
        cmd = build_report_get(origin, report_num)
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_report_resp(payload)
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def report_list_by_culprit(self, pubkey: str) -> list[Report]:
        cmd = build_report_list_by_culprit(bytes.fromhex(pubkey))
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_report_list_resp(payload)
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def report_sign(self, origin: str, report_num: int) -> Report:
        report = await self.report_get(origin, report_num)

        if self._private_key is None:
            raise BonnetError("No identity loaded")

        signing_key = SigningKey(self._private_key)

        from .protocol import encode_string, encode_bytes, struct

        payload = struct.pack(">Q", report.report_num)
        payload += struct.pack(">Q", report.rule_num)
        payload += encode_bytes(bytes.fromhex(report.culprit_pubkey))
        payload += encode_string(report.board or "")
        payload += struct.pack(">Q", report.post_num or 0)
        payload += encode_bytes(bytes.fromhex(report.reporter_pubkey))
        payload += struct.pack(">q", report.report_time)
        payload += encode_string(report.origin)
        payload += encode_string(report.description)

        signature = signing_key.sign(payload).signature.hex()

        cmd = build_report_sign(origin, report_num, signature)
        resp = await self._send_command(cmd)
        status, resp_payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return await self.report_get(origin, report_num)
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(resp_payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def report_list_since(self, since: int) -> list[Report]:
        cmd = build_report_list_since(since)
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_report_list_resp(payload)
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def punishment_create(
        self, pubkey: str, report_ids: list[int], expires_at: int, notes: str = ""
    ) -> Punishment:
        cmd = build_punishment_create(
            bytes.fromhex(pubkey), report_ids, expires_at, notes
        )
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_punishment_resp(payload)
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def punishment_get(self, pubkey: str) -> Punishment | None:
        cmd = build_punishment_get(bytes.fromhex(pubkey))
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_punishment_resp(payload)
        elif status == ResponseStatus.ERROR:
            return None
        raise BonnetError(f"Unexpected response: {status}")

    async def punishment_list_active(self) -> list[Punishment]:
        cmd = build_punishment_list_active()
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_punishment_list_resp(payload)
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")

    async def is_banned(self, pubkey: str) -> BannedStatus:
        cmd = build_is_banned(bytes.fromhex(pubkey))
        resp = await self._send_command(cmd)
        status, payload = parse_response(resp)

        if status == ResponseStatus.SUCCESS:
            return parse_is_banned_resp(payload)
        elif status == ResponseStatus.ERROR:
            raise BonnetError(parse_error_response(payload))
        raise BonnetError(f"Unexpected response: {status}")
