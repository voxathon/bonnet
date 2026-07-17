import nacl.signing
import nacl.public
import nacl.utils
import nacl.secret
import struct


class Identity:
    def __init__(self):
        pass

    @staticmethod
    def generate() -> 'Identity':
        ident = Identity()
        ident._signing_key = nacl.signing.SigningKey.generate()
        ident._private_key = bytes(ident._signing_key)
        ident.public_key = bytes(ident._signing_key.verify_key)
        return ident

    @staticmethod
    def from_private_key(privkey: bytes) -> 'Identity':
        if len(privkey) != 32:
            raise ValueError("Private key must be exactly 32 bytes")
        ident = Identity()
        ident._private_key = privkey
        ident._signing_key = nacl.signing.SigningKey(privkey)
        ident.public_key = bytes(ident._signing_key.verify_key)
        return ident

    def sign(self, message: bytes) -> bytes:
        return self._signing_key.sign(message).signature

    @staticmethod
    def verify(pubkey: bytes, message: bytes, signature: bytes) -> bool:
        try:
            verify_key = nacl.signing.VerifyKey(pubkey)
            verify_key.verify(message, signature)
            return True
        except nacl.exceptions.BadSignatureError:
            return False

    @property
    def private_key(self):
        return self._private_key

    @property
    def signing_key(self):
        return self._signing_key


class EncryptedSession:
    def __init__(self, our_privkey: bytes, their_pubkey: bytes):
        self._our_privkey = our_privkey
        self._peer_pubkey = their_pubkey

        # Convert Ed25519 keys to X25519
        signing_key = nacl.signing.SigningKey(our_privkey)
        verify_key = nacl.signing.VerifyKey(their_pubkey)

        our_private_x25519 = signing_key.to_curve25519_private_key()
        their_public_x25519 = verify_key.to_curve25519_public_key()

        self._box = nacl.public.Box(our_private_x25519, their_public_x25519)

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        # box.encrypt returns an EncryptedMessage object which behaves like bytes
        # its layout is [nonce(24)][ciphertext]
        encrypted = self._box.encrypt(plaintext, nonce)
        return bytes(encrypted)

    def decrypt(self, payload: bytes) -> bytes:
        # decrypt takes the combined message [nonce][ciphertext]
        # or takes them separated
        # we can just pass the whole payload since pynacl handles the nonce extraction if we use the default encrypt output format
        return self._box.decrypt(payload)
