import struct
import socket
import hashlib
import hmac
import os
import nacl.public
import nacl.signing
import nacl.bindings

MAGIC = 0x4D50
VERSION = 0x0001
HEADER_LEN = 26
AEAD_TAG = 16
HS_MAX_PAYLOAD = 1024
REC_MAX_PLAINTEXT_DEFAULT = 16384
IDENTITY_LEN = 32

FRAME_CLIENT_HELLO = 0x01
FRAME_SERVER_HELLO = 0x02
FRAME_SERVER_AUTH = 0x03
FRAME_SERVER_FINISHED = 0x04
FRAME_CLIENT_FINISHED = 0x05
FRAME_CLIENT_AUTH = 0x06

FRAME_APP_DATA = 0x20
FRAME_CLOSE = 0x21
FRAME_PING = 0x22

SUITE_CHACHA20 = 0x0001
SIG_ED25519 = 0x0001

HANDSHAKE_FRAMES = {FRAME_CLIENT_HELLO, FRAME_SERVER_HELLO, FRAME_SERVER_AUTH,
                    FRAME_SERVER_FINISHED, FRAME_CLIENT_FINISHED, FRAME_CLIENT_AUTH}

def _pack_header(frame_type, flags, conn_id, seq, payload_len):
    return struct.pack('>HHBBQQI', MAGIC, VERSION, frame_type, flags, conn_id, seq, payload_len)

def _unpack_header(data):
    magic, ver, ftype, flags, conn_id, seq, plen = struct.unpack('>HHBBQQI', data)
    return magic, ver, ftype, flags, conn_id, seq, plen

def _xor_nonce(iv, seq):
    seq_bytes = struct.pack('>Q', seq)
    nonce = bytes(a ^ b for a, b in zip(iv, seq_bytes))
    return nonce

def _hkdf_extract(salt, ikm):
    if not salt:
        salt = b'\x00' * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def _hkdf_expand(prk, info, length):
    hash_len = 32
    n = (length + hash_len - 1) // hash_len
    okm = b''
    prev = b''
    for i in range(1, n + 1):
        prev = hmac.new(prk, prev + info + bytes([i]), hashlib.sha256).digest()
        okm += prev
    return okm[:length]

def _hkdf_derive(salt, ikm, info, length):
    prk = _hkdf_extract(salt, ikm)
    return _hkdf_expand(prk, info, length)

cdef class _Wire:
    cdef object sock
    cdef bytes buf

    def __init__(self, sock):
        self.sock = sock
        self.buf = b''

    cpdef bytes recv_n(self, int n):
        while len(self.buf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed")
            self.buf += chunk
        result, self.buf = self.buf[:n], self.buf[n:]
        return result

    cpdef tuple recv_frame(self):
        header = self.recv_n(HEADER_LEN)
        magic, ver, ftype, flags, conn_id, seq, plen = _unpack_header(header)
        if magic != MAGIC:
            raise ValueError(f"Invalid magic: {magic:#x}")
        payload = self.recv_n(plen) if plen > 0 else b''
        return (ftype, flags, conn_id, seq, payload)

    cpdef void send_frame(self, int frame_type, int flags, unsigned long long conn_id,
                          unsigned long long seq, bytes payload):
        header = _pack_header(frame_type, flags, conn_id, seq, len(payload))
        self.sock.sendall(header + payload)

cdef class _RecordLayer:
    cdef bytes key
    cdef bytes iv

    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    cpdef bytes encrypt(self, bytes plaintext, unsigned long long seq):
        nonce = _xor_nonce(self.iv, seq)
        return nacl.bindings.crypto_aead_chacha20poly1305_ietf_encrypt(
            plaintext, None, nonce, self.key
        )

    cpdef bytes decrypt(self, bytes ciphertext, unsigned long long seq):
        nonce = _xor_nonce(self.iv, seq)
        return nacl.bindings.crypto_aead_chacha20poly1305_ietf_decrypt(
            ciphertext, None, nonce, self.key
        )

cdef class Session:
    cdef object sock
    cdef _Wire wire
    cdef _RecordLayer enc_layer
    cdef _RecordLayer dec_layer
    cdef unsigned long long conn_id
    cdef unsigned long long send_seq
    cdef unsigned long long recv_seq
    cdef public bytes client_identity
    cdef int _closed

    def __init__(self, sock, wire, enc_layer, dec_layer, conn_id, client_identity):
        self.sock = sock
        self.wire = wire
        self.enc_layer = enc_layer
        self.dec_layer = dec_layer
        self.conn_id = conn_id
        self.send_seq = 0
        self.recv_seq = 0
        self.client_identity = client_identity
        self._closed = 0

    cpdef bytes recv(self):
        if self._closed:
            raise ConnectionError("Session closed")
        ftype, flags, conn_id, seq, payload = self.wire.recv_frame()
        if ftype == FRAME_CLOSE:
            self._closed = 1
            code = struct.unpack('>H', payload[:2])[0] if len(payload) >= 2 else 0
            reason = payload[2:].decode('utf-8', errors='replace')
            raise ConnectionError(f"Remote closed: {code} {reason}")
        if ftype == FRAME_PING:
            self.send_pong(payload)
            return self.recv()
        if ftype != FRAME_APP_DATA:
            raise ValueError(f"Unexpected frame type: {ftype:#x}")
        plaintext = self.dec_layer.decrypt(payload, seq)
        self.recv_seq += 1
        return plaintext

    cpdef void send(self, bytes data):
        if self._closed:
            raise ConnectionError("Session closed")
        ciphertext = self.enc_layer.encrypt(data, self.send_seq)
        self.wire.send_frame(FRAME_APP_DATA, 0, self.conn_id, self.send_seq, ciphertext)
        self.send_seq += 1

    cdef void send_pong(self, bytes payload):
        self.wire.send_frame(FRAME_PING, 0, self.conn_id, self.send_seq, payload)
        self.send_seq += 1

    cpdef void close(self, int code=0, str reason=""):
        if self._closed:
            return
        payload = struct.pack('>H', code) + reason.encode('utf-8')
        try:
            ciphertext = self.enc_layer.encrypt(payload, self.send_seq)
            self.wire.send_frame(FRAME_CLOSE, 0, self.conn_id, self.send_seq, ciphertext)
        except:
            pass
        self._closed = 1
        try:
            self.sock.close()
        except:
            pass

def _derive_handshake_keys(eph_shared, transcript_hash, is_client):
    prk = _hkdf_extract(b'', eph_shared)
    hs_secret = _hkdf_expand(prk, b'iixp hs', 32)
    finished_key = _hkdf_expand(hs_secret, b'iixp finished', 32)
    
    if is_client:
        client_write_key = _hkdf_expand(hs_secret, b'iixp c key', 32)
        client_write_iv = _hkdf_expand(hs_secret, b'iixp c iv', 12)
        server_write_key = _hkdf_expand(hs_secret, b'iixp s key', 32)
        server_write_iv = _hkdf_expand(hs_secret, b'iixp s iv', 12)
    else:
        server_write_key = _hkdf_expand(hs_secret, b'iixp s key', 32)
        server_write_iv = _hkdf_expand(hs_secret, b'iixp s iv', 12)
        client_write_key = _hkdf_expand(hs_secret, b'iixp c key', 32)
        client_write_iv = _hkdf_expand(hs_secret, b'iixp c iv', 12)
    
    return finished_key, client_write_key, client_write_iv, server_write_key, server_write_iv

def _derive_app_keys(eph_shared, hs_transcript):
    prk = _hkdf_extract(b'', eph_shared)
    app_secret = _hkdf_expand(prk, b'iixp app', 32)
    
    client_write_key = _hkdf_expand(app_secret, b'iixp c app key', 32)
    client_write_iv = _hkdf_expand(app_secret, b'iixp c app iv', 12)
    server_write_key = _hkdf_expand(app_secret, b'iixp s app key', 32)
    server_write_iv = _hkdf_expand(app_secret, b'iixp s app iv', 12)
    
    return client_write_key, client_write_iv, server_write_key, server_write_iv

def connect(sock, client_identity, server_pinned=None, int port=2272):
    wire = _Wire(sock)
    transcript = b''
    conn_id = 0
    
    client_random = os.urandom(32)
    eph_priv = nacl.public.PrivateKey.generate()
    eph_pub = bytes(eph_priv.public_key)
    
    client_hello_payload = client_random + eph_pub + struct.pack('>HH', SUITE_CHACHA20, SIG_ED25519)
    wire.send_frame(FRAME_CLIENT_HELLO, 0, conn_id, 0, client_hello_payload)
    transcript += _pack_header(FRAME_CLIENT_HELLO, 0, conn_id, 0, len(client_hello_payload)) + client_hello_payload
    
    ftype, flags, conn_id, seq, server_hello_payload = wire.recv_frame()
    if ftype != FRAME_SERVER_HELLO:
        raise ValueError(f"Expected SERVER_HELLO, got {ftype:#x}")
    transcript += _pack_header(ftype, flags, conn_id, seq, len(server_hello_payload)) + server_hello_payload
    
    server_random = server_hello_payload[:32]
    server_eph_pub = server_hello_payload[32:64]
    suite, = struct.unpack('>H', server_hello_payload[64:66])
    server_conn_id = struct.unpack('>Q', server_hello_payload[66:74])[0] if len(server_hello_payload) >= 74 else conn_id
    
    conn_id = server_conn_id
    
    ftype, flags, conn_id, seq, server_auth_payload = wire.recv_frame()
    if ftype != FRAME_SERVER_AUTH:
        raise ValueError(f"Expected SERVER_AUTH, got {ftype:#x}")
    transcript += _pack_header(ftype, flags, conn_id, seq, len(server_auth_payload)) + server_auth_payload
    
    server_id = server_auth_payload[:32]
    sig_scheme, = struct.unpack('>H', server_auth_payload[32:34])
    signature = server_auth_payload[34:98]
    
    if server_pinned is not None:
        if server_id != bytes(server_pinned):
            raise ValueError("Server identity mismatch")
    
    server_eph_pub_obj = nacl.public.PublicKey(server_eph_pub)
    eph_shared = nacl.bindings.crypto_scalarmult(bytes(eph_priv), server_eph_pub)
    
    finished_key, c_key, c_iv, s_key, s_iv = _derive_handshake_keys(eph_shared, transcript, True)
    
    ftype, flags, conn_id, seq, server_finished_payload = wire.recv_frame()
    if ftype != FRAME_SERVER_FINISHED:
        raise ValueError(f"Expected SERVER_FINISHED, got {ftype:#x}")
    transcript += _pack_header(ftype, flags, conn_id, seq, len(server_finished_payload)) + server_finished_payload
    
    dec_layer = _RecordLayer(s_key, s_iv)
    enc_layer = _RecordLayer(c_key, c_iv)
    
    mac_data = dec_layer.decrypt(server_finished_payload, seq)
    expected_mac = hashlib.sha256(finished_key + transcript).digest()
    if mac_data != expected_mac:
        raise ValueError("Server MAC verification failed")
    
    client_id = bytes(client_identity.verify_key)
    sig_data = transcript + client_id
    signed = client_identity.sign(sig_data)
    signature = signed.signature
    
    client_auth_payload = client_id + struct.pack('>H', SIG_ED25519) + signature
    transcript += _pack_header(FRAME_CLIENT_AUTH, 0, conn_id, 0, len(client_auth_payload)) + client_auth_payload
    wire.send_frame(FRAME_CLIENT_AUTH, 0, conn_id, 0, client_auth_payload)
    
    client_mac = hashlib.sha256(finished_key + transcript).digest()
    client_finished_payload = enc_layer.encrypt(client_mac, 0)
    transcript += _pack_header(FRAME_CLIENT_FINISHED, 0, conn_id, 1, len(client_finished_payload)) + client_finished_payload
    wire.send_frame(FRAME_CLIENT_FINISHED, 0, conn_id, 1, client_finished_payload)
    
    c_app_key, c_app_iv, s_app_key, s_app_iv = _derive_app_keys(eph_shared, transcript)
    
    enc_layer = _RecordLayer(c_app_key, c_app_iv)
    dec_layer = _RecordLayer(s_app_key, s_app_iv)
    
    session = Session(sock, wire, enc_layer, dec_layer, conn_id, server_id)
    session.send_seq = 1
    session.recv_seq = 0
    return session

def accept(sock, server_identity, client_pinned=None):
    wire = _Wire(sock)
    transcript = b''
    conn_id = 0
    
    ftype, flags, conn_id, seq, client_hello_payload = wire.recv_frame()
    if ftype != FRAME_CLIENT_HELLO:
        raise ValueError(f"Expected CLIENT_HELLO, got {ftype:#x}")
    transcript += _pack_header(ftype, flags, conn_id, seq, len(client_hello_payload)) + client_hello_payload
    
    client_random = client_hello_payload[:32]
    client_eph_pub = client_hello_payload[32:64]
    
    server_random = os.urandom(32)
    eph_priv = nacl.public.PrivateKey.generate()
    eph_pub = bytes(eph_priv.public_key)
    conn_id_bytes = os.urandom(8)
    conn_id_int = struct.unpack('>Q', conn_id_bytes)[0]
    
    server_hello_payload = server_random + eph_pub + struct.pack('>HQ', SUITE_CHACHA20, conn_id_int)
    wire.send_frame(FRAME_SERVER_HELLO, 0, conn_id_int, 0, server_hello_payload)
    transcript += _pack_header(FRAME_SERVER_HELLO, 0, conn_id_int, 0, len(server_hello_payload)) + server_hello_payload
    
    conn_id = conn_id_int
    
    eph_shared = nacl.bindings.crypto_scalarmult(bytes(eph_priv), client_eph_pub)
    
    finished_key, c_key, c_iv, s_key, s_iv = _derive_handshake_keys(eph_shared, transcript, False)
    
    server_id = bytes(server_identity.verify_key)
    sig_data = transcript + server_id
    signed = server_identity.sign(sig_data)
    signature = signed.signature
    
    server_auth_payload = server_id + struct.pack('>H', SIG_ED25519) + signature
    wire.send_frame(FRAME_SERVER_AUTH, 0, conn_id, 0, server_auth_payload)
    transcript += _pack_header(FRAME_SERVER_AUTH, 0, conn_id, 0, len(server_auth_payload)) + server_auth_payload
    
    enc_layer = _RecordLayer(s_key, s_iv)
    dec_layer = _RecordLayer(c_key, c_iv)
    
    server_mac = hashlib.sha256(finished_key + transcript).digest()
    server_finished_payload = enc_layer.encrypt(server_mac, 0)
    wire.send_frame(FRAME_SERVER_FINISHED, 0, conn_id, 0, server_finished_payload)
    transcript += _pack_header(FRAME_SERVER_FINISHED, 0, conn_id, 0, len(server_finished_payload)) + server_finished_payload
    
    ftype, flags, conn_id, seq, client_auth_payload = wire.recv_frame()
    if ftype != FRAME_CLIENT_AUTH:
        raise ValueError(f"Expected CLIENT_AUTH, got {ftype:#x}")
    transcript += _pack_header(ftype, flags, conn_id, seq, len(client_auth_payload)) + client_auth_payload
    
    client_id = client_auth_payload[:32]
    sig_scheme, = struct.unpack('>H', client_auth_payload[32:34])
    signature = client_auth_payload[34:98]
    
    if client_pinned is not None:
        if client_id != bytes(client_pinned):
            enc_layer = _RecordLayer(s_key, s_iv)
            wire.send_frame(FRAME_CLOSE, 0, conn_id, 0, enc_layer.encrypt(struct.pack('>H', 401) + b'Unauthorized', 1))
            raise ValueError("Client identity mismatch")
    
    client_verify_key = nacl.signing.VerifyKey(client_id)
    try:
        client_verify_key.verify(transcript[:-(len(client_auth_payload)+HEADER_LEN)] + client_auth_payload[:32], signature)
    except nacl.exceptions.BadSignature:
        enc_layer = _RecordLayer(s_key, s_iv)
        wire.send_frame(FRAME_CLOSE, 0, conn_id, 0, enc_layer.encrypt(struct.pack('>H', 401) + b'Bad signature', 1))
        raise ValueError("Client signature verification failed")
    
    ftype, flags, conn_id, seq, client_finished_payload = wire.recv_frame()
    if ftype != FRAME_CLIENT_FINISHED:
        raise ValueError(f"Expected CLIENT_FINISHED, got {ftype:#x}")
    transcript += _pack_header(ftype, flags, conn_id, seq, len(client_finished_payload)) + client_finished_payload
    
    client_mac = dec_layer.decrypt(client_finished_payload, seq)
    expected_mac = hashlib.sha256(finished_key + transcript).digest()
    if client_mac != expected_mac:
        raise ValueError("Client MAC verification failed")
    
    c_app_key, c_app_iv, s_app_key, s_app_iv = _derive_app_keys(eph_shared, transcript)
    
    enc_layer = _RecordLayer(s_app_key, s_app_iv)
    dec_layer = _RecordLayer(c_app_key, c_app_iv)
    
    session = Session(sock, wire, enc_layer, dec_layer, conn_id, client_id)
    session.send_seq = 1
    session.recv_seq = 0
    return session