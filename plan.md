iixp

```cython
#!/usr/bin/env python3
"""
iixp.py – IIXP/v1 (Intermediate-layer Identity eXchange Protocol)

Requires: pip install cryptography>=41
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import os
import socket
import struct
from typing import List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

# ═══════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════

MAGIC      = 0x4D50
VERSION    = 0x0001
HEADER_LEN = 26          # 2+2+1+1+8+8+4
AEAD_TAG   = 16

# Frame size limits
HS_MAX_PAYLOAD            = 1024   # handshake frames (plaintext, unauth)
REC_MAX_PLAINTEXT_DEFAULT = 16384  # protected AppData plaintext default
IDENTITY_LEN              = 32     # Ed25519 public key (fixed)

# Handshake frame types
CLIENT_HELLO    = 0x01
SERVER_HELLO    = 0x02
SERVER_AUTH     = 0x03
SERVER_FINISHED = 0x04
CLIENT_FINISHED = 0x05
CLIENT_AUTH     = 0x06

# Protected frame types
APP_DATA = 0x20
CLOSE    = 0x21
PING     = 0x22

# Cipher suites
SUITE_CHACHA20 = 0x0001  # X25519 + Ed25519 + HKDF-SHA256 + ChaCha20-Poly1305
SUITE_AES256   = 0x0002  # X25519 + Ed25519 + HKDF-SHA256 + AES-256-GCM

SIG_ED25519 = 0x0001

# struct: magic(H) version(H) type(B) flags(B) conn_id(Q) seq(Q) payload_len(I)
_HDR = struct.Struct('>HHBBQQI')

# ═══════════════════════════════════════════════════════════════════════════
# Exceptions
# ═══════════════════════════════════════════════════════════════════════════

class IIXPError(Exception):
    """Base protocol error."""

class HandshakeError(IIXPError):
    """Handshake-stage failure (bad magic, unsupported version, etc.)."""

class AuthError(IIXPError):
    """Identity or MAC verification failure."""

class RecordOverflow(IIXPError):
    """Frame or record exceeds protocol size limit."""

class PeerClosed(IIXPError):
    """Remote side sent a Close frame."""
    def __init__(self, code: int, reason: str):
        self.code   = code
        self.reason = reason
        super().__init__(f"peer closed ({code}): {reason}")

# ═══════════════════════════════════════════════════════════════════════════
# Wire-level helpers
# ═══════════════════════════════════════════════════════════════════════════

def _pack_header(ftype: int, flags: int, cid: int, seq: int, plen: int) -> bytes:
    return _HDR.pack(MAGIC, VERSION, ftype, flags, cid, seq, plen)

def _unpack_header(raw: bytes) -> Tuple[int, int, int, int, int]:
    m, v, ft, fl, cid, seq, pl = _HDR.unpack(raw)
    if m != MAGIC:
        raise HandshakeError(f"bad magic 0x{m:04x}")
    if v != VERSION:
        raise HandshakeError(f"unsupported version 0x{v:04x}")
    return ft, fl, cid, seq, pl

def _vb_pack(data: bytes) -> bytes:
    """Encode varbytes: u32 length ‖ data."""
    return struct.pack('>I', len(data)) + data

def _vb_unpack(buf: bytes, off: int) -> Tuple[bytes, int]:
    """Decode varbytes starting at *off*; return (data, new_offset)."""
    (n,) = struct.unpack_from('>I', buf, off)
    start = off + 4
    return buf[start:start + n], start + n

def _expect(got: int, want: int) -> None:
    if got != want:
        raise HandshakeError(f"expected frame 0x{want:02x}, got 0x{got:02x}")

# ═══════════════════════════════════════════════════════════════════════════
# Crypto helpers
# ═══════════════════════════════════════════════════════════════════════════

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract (RFC 5869 §2.2) with SHA-256."""
    return _hmac.new(salt, ikm, hashlib.sha256).digest()

def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869 §2.3) with SHA-256."""
    return HKDFExpand(hashes.SHA256(), length, info).derive(prk)

def _hmac256(key: bytes, msg: bytes) -> bytes:
    return _hmac.new(key, msg, hashlib.sha256).digest()

def _ed_raw(k) -> bytes:
    """Return the 32-byte raw encoding of an Ed25519 public key."""
    pub = k.public_key() if isinstance(k, Ed25519PrivateKey) else k
    return pub.public_bytes(serialization.Encoding.Raw,
                            serialization.PublicFormat.Raw)

def _x_raw(k) -> bytes:
    """Return the 32-byte raw encoding of an X25519 public key."""
    pub = k.public_key() if isinstance(k, X25519PrivateKey) else k
    return pub.public_bytes(serialization.Encoding.Raw,
                            serialization.PublicFormat.Raw)

# ═══════════════════════════════════════════════════════════════════════════
# Transport: read / write full frames over a TCP socket
# ═══════════════════════════════════════════════════════════════════════════

class _Wire:
    """Thin wrapper for reading / writing IIXP frames on a stream socket."""

    __slots__ = ('_sock',)

    def __init__(self, sock: socket.socket):
        self._sock = sock

    # ── private ──────────────────────────────────────────────────────
    def _recvall(self, n: int) -> bytes:
        parts: list[bytes] = []
        left = n
        while left > 0:
            chunk = self._sock.recv(left)
            if not chunk:
                raise ConnectionError("connection closed while reading")
            parts.append(chunk)
            left -= len(chunk)
        return b''.join(parts)

    # ── public API ───────────────────────────────────────────────────
    def read_frame(self, *, max_payload: int = 0) -> Tuple[bytes, int, int, int, int, bytes]:
        """Return (frame_bytes, type, flags, conn_id, seq, payload).

        If *max_payload* > 0 the payload length declared in the header is
        checked **before** any payload bytes are read into memory.  On
        violation the TCP connection is closed immediately and
        ``RecordOverflow`` is raised.
        """
        hdr = self._recvall(HEADER_LEN)
        ftype, flags, cid, seq, plen = _unpack_header(hdr)
        if max_payload > 0 and plen > max_payload:
            self._sock.close()
            raise RecordOverflow(
                f"payload {plen} bytes exceeds limit {max_payload}")
        payload = self._recvall(plen) if plen else b''
        frame = hdr + payload
        return frame, ftype, flags, cid, seq, payload

    def write_frame(self, ftype: int, flags: int, cid: int,
                    seq: int, payload: bytes) -> bytes:
        """Serialize, send, and return the complete frame bytes."""
        hdr   = _pack_header(ftype, flags, cid, seq, len(payload))
        frame = hdr + payload
        self._sock.sendall(frame)
        return frame

# ═══════════════════════════════════════════════════════════════════════════
# AEAD record layer (post-handshake)
# ═══════════════════════════════════════════════════════════════════════════

class _RecordLayer:
    """Encrypts / decrypts protected frames with per-direction keys."""

    def __init__(self, wire: _Wire, conn_id: int, suite: int,
                 write_key: bytes, write_iv: bytes,
                 read_key: bytes,  read_iv: bytes,
                 max_plaintext: int = REC_MAX_PLAINTEXT_DEFAULT):
        self._w   = wire
        self._cid = conn_id
        self._suite = suite
        self._wk, self._wi = write_key, write_iv
        self._rk, self._ri = read_key,  read_iv
        self._wseq = 0          # next send sequence number
        self._rseq = 0          # next expected receive sequence number
        self._max_pt = max_plaintext
        self._max_ct = max_plaintext + AEAD_TAG

    # ── AEAD wrappers ────────────────────────────────────────────────
    def _aead(self, key: bytes):
        if self._suite == SUITE_CHACHA20:
            return ChaCha20Poly1305(key)
        return AESGCM(key)

    @staticmethod
    def _nonce(iv: bytes, seq: int) -> bytes:
        """iv ⊕ (0x00000000 ‖ u64be(seq))"""
        seq96 = b'\x00\x00\x00\x00' + struct.pack('>Q', seq)
        return bytes(a ^ b for a, b in zip(iv, seq96))

    # ── send / recv ──────────────────────────────────────────────────
    def send(self, ftype: int, plaintext: bytes, flags: int = 0) -> None:
        if len(plaintext) > self._max_pt:
            raise RecordOverflow(
                f"plaintext {len(plaintext)} bytes exceeds "
                f"record_plaintext_limit {self._max_pt}")
        seq    = self._wseq
        ct_len = len(plaintext) + AEAD_TAG
        header = _pack_header(ftype, flags, self._cid, seq, ct_len)
        nonce  = self._nonce(self._wi, seq)
        ct     = self._aead(self._wk).encrypt(nonce, plaintext, header)
        self._w._sock.sendall(header + ct)
        self._wseq += 1

    def recv(self) -> Tuple[int, int, bytes]:
        """Return (frame_type, flags, plaintext).

        The ciphertext length is checked against the negotiated limit
        *before* the payload is read from the wire.  After decryption
        the plaintext length is verified again as a belt-and-suspenders
        check; on any violation the connection is terminated.
        """
        raw, ftype, flags, _, seq, payload = self._w.read_frame(
            max_payload=self._max_ct)
        if seq < self._rseq:
            raise IIXPError(f"replay / reorder: seq={seq}, expected>={self._rseq}")
        header = raw[:HEADER_LEN]
        nonce  = self._nonce(self._ri, seq)
        pt     = self._aead(self._rk).decrypt(nonce, payload, header)
        if len(pt) > self._max_pt:
            self._w._sock.close()
            raise RecordOverflow(
                f"decrypted plaintext {len(pt)} bytes exceeds "
                f"record_plaintext_limit {self._max_pt}")
        self._rseq = seq + 1
        return ftype, flags, pt

# ═══════════════════════════════════════════════════════════════════════════
# Session — the public post-handshake API
# ═══════════════════════════════════════════════════════════════════════════

class Session:
    """An established, mutually-authenticated IIXP/v1 session."""

    def __init__(self, rl: _RecordLayer, peer_pub: Ed25519PublicKey,
                 own_pub: Ed25519PublicKey, sock: socket.socket,
                 record_plaintext_limit: int):
        self._rl   = rl
        self._sock = sock
        self.peer_identity: Ed25519PublicKey = peer_pub
        self.own_identity:  Ed25519PublicKey = own_pub
        self.record_plaintext_limit: int = record_plaintext_limit

    # ── application data ─────────────────────────────────────────────
    def send(self, data: bytes) -> None:
        """Send an encrypted AppData record."""
        self._rl.send(APP_DATA, data)

    def recv(self) -> bytes:
        """Block until an AppData record arrives.  Pings are consumed
        silently; a Close frame raises ``PeerClosed``."""
        while True:
            ft, _fl, pt = self._rl.recv()
            if ft == APP_DATA:
                return pt
            if ft == PING:
                continue
            if ft == CLOSE:
                code = struct.unpack_from('>H', pt, 0)[0]
                reason = b''
                if len(pt) > 2:
                    reason, _ = _vb_unpack(pt, 2)
                raise PeerClosed(code, reason.decode('utf-8', errors='replace'))
            raise IIXPError(f"unexpected protected frame 0x{ft:02x}")

    # ── close ────────────────────────────────────────────────────────
    def close(self, code: int = 0, reason: str = '') -> None:
        body = struct.pack('>H', code) + _vb_pack(reason.encode())
        try:
            self._rl.send(CLOSE, body)
        except OSError:
            pass
        self._sock.close()

    # ── context manager ──────────────────────────────────────────────
    def __enter__(self) -> Session:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

# ═══════════════════════════════════════════════════════════════════════════
# Handshake helpers (common to both sides)
# ═══════════════════════════════════════════════════════════════════════════

def _derive_hs_keys(
    client_random: bytes,
    server_random: bytes,
    Z: bytes,
    th_sa: bytes,
) -> Tuple[bytes, bytes, bytes, bytes]:
    """Return (prk, hs_secret, finished_key_server, finished_key_client)."""
    salt0 = hashlib.sha256(b"mp1 salt v1" + client_random + server_random).digest()
    prk   = _hkdf_extract(salt0, Z)
    hs    = _hkdf_expand(prk, b"mp1 hs v1" + th_sa, 32)
    fks   = _hkdf_expand(hs,  b"mp1 fin s v1" + th_sa, 32)
    fkc   = _hkdf_expand(hs,  b"mp1 fin c v1" + th_sa, 32)
    return prk, hs, fks, fkc

def _derive_app_keys(
    prk: bytes,
    th_done: bytes,
) -> Tuple[bytes, bytes, bytes, bytes]:
    """Return (client_write_key, server_write_key,
               client_write_iv,  server_write_iv)."""
    app = _hkdf_expand(prk, b"mp1 app v1" + th_done, 32)
    ck  = _hkdf_expand(app, b"mp1 key c v1" + th_done, 32)
    sk  = _hkdf_expand(app, b"mp1 key s v1" + th_done, 32)
    ci  = _hkdf_expand(app, b"mp1 iv c v1"  + th_done, 12)
    si  = _hkdf_expand(app, b"mp1 iv s v1"  + th_done, 12)
    return ck, sk, ci, si

# ═══════════════════════════════════════════════════════════════════════════
# Client-side handshake
# ═══════════════════════════════════════════════════════════════════════════

def connect(
    sock: socket.socket,
    client_identity: Ed25519PrivateKey,
    server_pinned: Ed25519PublicKey,
    *,
    server_name: str = '',
    suites: Optional[List[int]] = None,
) -> Session:
    """
    Perform a **client-side** IIXP/v1 handshake over *sock* and return an
    established :class:`Session`.

    *client_identity*  – the client's long-term Ed25519 signing key.
    *server_pinned*    – the expected server Ed25519 public key (pinned).
    """
    if suites is None:
        suites = [SUITE_CHACHA20, SUITE_AES256]

    wire = _Wire(sock)
    ctx  = hashlib.sha256()                            # transcript hash

    # ── 1. ClientHello (C → S) ───────────────────────────────────────
    client_random = os.urandom(32)
    eph_priv      = X25519PrivateKey.generate()
    eph_pub       = _x_raw(eph_priv)

    ch_payload = (
        client_random
        + eph_pub
        + struct.pack('>H', len(suites))
        + b''.join(struct.pack('>H', s) for s in suites)
        + _vb_pack(server_name.encode())
        + _vb_pack(b'')                                # extensions (none)
    )
    frame = wire.write_frame(CLIENT_HELLO, 0, 0, 0, ch_payload)
    ctx.update(frame)

    # ── 2. ServerHello (S → C) ───────────────────────────────────────
    frame, ft, _, _, _, body = wire.read_frame(max_payload=HS_MAX_PAYLOAD)
    _expect(ft, SERVER_HELLO)
    ctx.update(frame)

    off = 0
    server_random = body[off:off+32];                  off += 32
    server_eph    = body[off:off+32];                   off += 32
    (suite,)      = struct.unpack_from('>H', body, off); off += 2
    (conn_id,)    = struct.unpack_from('>Q', body, off); off += 8
    (record_plaintext_limit,) = struct.unpack_from('>H', body, off); off += 2
    # remaining: extensions (ignored)

    if suite not in suites:
        raise HandshakeError(f"server selected unsupported suite 0x{suite:04x}")

    # apply default if server sent 0
    if record_plaintext_limit == 0:
        record_plaintext_limit = REC_MAX_PLAINTEXT_DEFAULT

    Z = eph_priv.exchange(X25519PublicKey.from_public_bytes(server_eph))

    th_before_sa = ctx.copy().digest()                 # TH after CH+SH

    # ── 3. ServerAuth (S → C) ────────────────────────────────────────
    frame, ft, _, _, _, body = wire.read_frame(max_payload=HS_MAX_PAYLOAD)
    _expect(ft, SERVER_AUTH)

    off = 0
    srv_id_raw  = body[off:off+IDENTITY_LEN];           off += IDENTITY_LEN
    (sig_scheme,) = struct.unpack_from('>H', body, off); off += 2
    srv_sig       = body[off:off+64];                    off += 64

    if sig_scheme != SIG_ED25519:
        raise HandshakeError(f"unsupported sig scheme 0x{sig_scheme:04x}")
    if srv_id_raw != _ed_raw(server_pinned):
        raise AuthError("server identity does not match pinned key")

    # verify the server's handshake signature
    sa_to_sign = (b"mp1 server auth v1"
                  + th_before_sa
                  + srv_id_raw
                  + struct.pack('>H', sig_scheme))
    try:
        server_pinned.verify(srv_sig, sa_to_sign)
    except InvalidSignature:
        raise AuthError("server auth signature invalid")

    ctx.update(frame)
    th_sa = ctx.copy().digest()                        # TH after CH+SH+SA

    # key schedule ────────────────────────────────────────────────────
    prk, _hs, fk_server, fk_client = _derive_hs_keys(
        client_random, server_random, Z, th_sa
    )

    # ── 4. ServerFinished (S → C) ────────────────────────────────────
    frame, ft, _, _, _, body = wire.read_frame(max_payload=HS_MAX_PAYLOAD)
    _expect(ft, SERVER_FINISHED)

    expected_sf = _hmac256(fk_server, b"mp1 finished s v1" + th_sa)
    if not _hmac.compare_digest(body[:32], expected_sf):
        raise AuthError("ServerFinished MAC verification failed")

    ctx.update(frame)
    th_before_ca = ctx.copy().digest()                 # TH after CH+SH+SA+SF

    # ── 5. ClientAuth (C → S) ────────────────────────────────────────
    cli_id_raw = _ed_raw(client_identity)
    ca_to_sign = (b"mp1 client auth v1"
                  + th_before_ca
                  + cli_id_raw
                  + struct.pack('>H', SIG_ED25519))
    cli_sig = client_identity.sign(ca_to_sign)

    ca_payload = (
        cli_id_raw                                     # opaque[32]
        + struct.pack('>H', SIG_ED25519)
        + cli_sig
    )
    frame = wire.write_frame(CLIENT_AUTH, 0, conn_id, 0, ca_payload)
    ctx.update(frame)
    th_after_ca = ctx.copy().digest()                  # TH after …+CA

    # ── 6. ClientFinished (C → S) ────────────────────────────────────
    cf_mac = _hmac256(fk_client, b"mp1 finished c v1" + th_after_ca)
    frame  = wire.write_frame(CLIENT_FINISHED, 0, conn_id, 0, cf_mac)
    ctx.update(frame)
    th_done = ctx.copy().digest()                      # TH after all 6

    # application traffic keys ────────────────────────────────────────
    ck, sk, ci, si = _derive_app_keys(prk, th_done)

    rl = _RecordLayer(wire, conn_id, suite,
                      write_key=ck, write_iv=ci,       # client writes
                      read_key=sk,  read_iv=si,        # client reads
                      max_plaintext=record_plaintext_limit)
    return Session(rl, server_pinned, client_identity.public_key(), sock,
                   record_plaintext_limit)

# ═══════════════════════════════════════════════════════════════════════════
# Server-side handshake
# ═══════════════════════════════════════════════════════════════════════════

def accept(
    sock: socket.socket,
    server_identity: Ed25519PrivateKey,
    client_pinned: Ed25519PublicKey,
    *,
    suites: Optional[List[int]] = None,
    record_plaintext_limit: int = REC_MAX_PLAINTEXT_DEFAULT,
) -> Session:
    """
    Perform a **server-side** IIXP/v1 handshake over *sock* and return an
    established :class:`Session`.

    *server_identity*        – the server's long-term Ed25519 signing key.
    *client_pinned*          – the expected client Ed25519 public key (pinned).
    *record_plaintext_limit* – max plaintext bytes the client may send per
                               protected record (advertised in ServerHello,
                               default 16 384).
    """
    if suites is None:
        suites = [SUITE_CHACHA20, SUITE_AES256]

    wire = _Wire(sock)
    ctx  = hashlib.sha256()

    # ── 1. ClientHello (C → S) ───────────────────────────────────────
    frame, ft, _, _, _, body = wire.read_frame(max_payload=HS_MAX_PAYLOAD)
    _expect(ft, CLIENT_HELLO)
    ctx.update(frame)

    off = 0
    client_random = body[off:off+32];                    off += 32
    client_eph    = body[off:off+32];                     off += 32
    (n_suites,)   = struct.unpack_from('>H', body, off);  off += 2
    client_suites = []
    for _ in range(n_suites):
        (s,) = struct.unpack_from('>H', body, off); off += 2
        client_suites.append(s)
    _sname, off = _vb_unpack(body, off)                  # server_name (ignored)
    _ext,   off = _vb_unpack(body, off)                  # extensions  (ignored)

    # choose the first server-preferred suite the client also offers
    suite = next((s for s in suites if s in client_suites), None)
    if suite is None:
        raise HandshakeError("no mutually supported cipher suite")

    # ── 2. ServerHello (S → C) ───────────────────────────────────────
    server_random = os.urandom(32)
    eph_priv      = X25519PrivateKey.generate()
    eph_pub       = _x_raw(eph_priv)
    conn_id       = struct.unpack('>Q', os.urandom(8))[0] | 1   # nonzero

    sh_payload = (
        server_random
        + eph_pub
        + struct.pack('>H', suite)
        + struct.pack('>Q', conn_id)
        + struct.pack('>H', record_plaintext_limit)
        + _vb_pack(b'')                                 # extensions (none)
    )
    frame = wire.write_frame(SERVER_HELLO, 0, 0, 0, sh_payload)
    ctx.update(frame)

    Z = eph_priv.exchange(X25519PublicKey.from_public_bytes(client_eph))

    th_before_sa = ctx.copy().digest()                   # TH after CH+SH

    # ── 3. ServerAuth (S → C) ────────────────────────────────────────
    srv_id_raw = _ed_raw(server_identity)
    sa_to_sign = (b"mp1 server auth v1"
                  + th_before_sa
                  + srv_id_raw
                  + struct.pack('>H', SIG_ED25519))
    srv_sig = server_identity.sign(sa_to_sign)

    sa_payload = (
        srv_id_raw                                       # opaque[32]
        + struct.pack('>H', SIG_ED25519)
        + srv_sig
    )
    frame = wire.write_frame(SERVER_AUTH, 0, conn_id, 0, sa_payload)
    ctx.update(frame)
    th_sa = ctx.copy().digest()                          # TH after CH+SH+SA

    # key schedule ────────────────────────────────────────────────────
    prk, _hs, fk_server, fk_client = _derive_hs_keys(
        client_random, server_random, Z, th_sa
    )

    # ── 4. ServerFinished (S → C) ────────────────────────────────────
    sf_mac = _hmac256(fk_server, b"mp1 finished s v1" + th_sa)
    frame  = wire.write_frame(SERVER_FINISHED, 0, conn_id, 0, sf_mac)
    ctx.update(frame)

    th_before_ca = ctx.copy().digest()                   # TH after CH+SH+SA+SF

    # ── 5. ClientAuth (C → S) ────────────────────────────────────────
    frame, ft, _, _, _, body = wire.read_frame(max_payload=HS_MAX_PAYLOAD)
    _expect(ft, CLIENT_AUTH)

    off = 0
    cli_id_raw    = body[off:off+IDENTITY_LEN];          off += IDENTITY_LEN
    (sig_scheme,) = struct.unpack_from('>H', body, off); off += 2
    cli_sig       = body[off:off+64];                    off += 64

    if sig_scheme != SIG_ED25519:
        raise HandshakeError(f"unsupported sig scheme 0x{sig_scheme:04x}")
    if cli_id_raw != _ed_raw(client_pinned):
        raise AuthError("client identity does not match pinned key")

    ca_to_sign = (b"mp1 client auth v1"
                  + th_before_ca
                  + cli_id_raw
                  + struct.pack('>H', sig_scheme))
    try:
        Ed25519PublicKey.from_public_bytes(cli_id_raw).verify(cli_sig, ca_to_sign)
    except InvalidSignature:
        raise AuthError("client auth signature invalid")

    ctx.update(frame)
    th_after_ca = ctx.copy().digest()                    # TH after …+CA

    # ── 6. ClientFinished (C → S) ────────────────────────────────────
    frame, ft, _, _, _, body = wire.read_frame(max_payload=HS_MAX_PAYLOAD)
    _expect(ft, CLIENT_FINISHED)

    expected_cf = _hmac256(fk_client, b"mp1 finished c v1" + th_after_ca)
    if not _hmac.compare_digest(body[:32], expected_cf):
        raise AuthError("ClientFinished MAC verification failed")

    ctx.update(frame)
    th_done = ctx.copy().digest()                        # TH after all 6

    # application traffic keys ────────────────────────────────────────
    ck, sk, ci, si = _derive_app_keys(prk, th_done)

    rl = _RecordLayer(wire, conn_id, suite,
                      write_key=sk, write_iv=si,         # server writes
                      read_key=ck,  read_iv=ci,          # server reads
                      max_plaintext=record_plaintext_limit)

    cli_pub = Ed25519PublicKey.from_public_bytes(cli_id_raw)
    return Session(rl, cli_pub, server_identity.public_key(), sock,
                   record_plaintext_limit)


```
