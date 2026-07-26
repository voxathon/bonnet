import nacl.signing
import nacl.utils


class Identity:
    def __init__(self):
        pass

    @staticmethod
    def generate() -> "Identity":
        ident = Identity()
        ident._signing_key = nacl.signing.SigningKey.generate()
        ident._private_key = bytes(ident._signing_key)
        ident.public_key = bytes(ident._signing_key.verify_key)
        return ident

    @staticmethod
    def from_private_key(privkey: bytes) -> "Identity":
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
            if len(pubkey) != 32:
                return False
            if len(signature) != 64:
                return False
            verify_key = nacl.signing.VerifyKey(pubkey)
            verify_key.verify(message, signature)
            return True
        except (nacl.exceptions.BadSignatureError, nacl.exceptions.ValueError, TypeError):
            return False

    @property
    def private_key(self):
        return self._private_key

    @property
    def signing_key(self):
        return self._signing_key
