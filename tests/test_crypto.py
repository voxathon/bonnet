# -*- coding: utf-8 -*-

import pytest
import nacl.exceptions
from crypto import Identity, EncryptedSession


class TestIdentity:
    def test_identity_generate(self):
        ident = Identity.generate()
        assert len(ident.public_key) == 32
        assert len(ident.private_key) == 32

    def test_identity_generate_unique(self):
        ident1 = Identity.generate()
        ident2 = Identity.generate()
        assert ident1.public_key != ident2.public_key
        assert ident1.private_key != ident2.private_key

    def test_identity_from_private_key(self):
        original = Identity.generate()
        restored = Identity.from_private_key(original.private_key)
        assert restored.public_key == original.public_key
        assert restored.private_key == original.private_key

    def test_identity_from_private_key_invalid_length(self):
        with pytest.raises(ValueError, match="Private key must be exactly 32 bytes"):
            Identity.from_private_key(b"short")
        with pytest.raises(ValueError, match="Private key must be exactly 32 bytes"):
            Identity.from_private_key(b"x" * 31)
        with pytest.raises(ValueError, match="Private key must be exactly 32 bytes"):
            Identity.from_private_key(b"x" * 33)

    def test_identity_sign_verify(self):
        ident = Identity.generate()
        message = b"test message"
        signature = ident.sign(message)
        assert len(signature) == 64
        assert Identity.verify(ident.public_key, message, signature) is True

    def test_identity_verify_tampered_message(self):
        ident = Identity.generate()
        message = b"original message"
        signature = ident.sign(message)
        tampered = b"tampered message"
        assert Identity.verify(ident.public_key, tampered, signature) is False

    def test_identity_verify_wrong_pubkey(self):
        ident = Identity.generate()
        other = Identity.generate()
        message = b"test message"
        signature = ident.sign(message)
        assert Identity.verify(other.public_key, message, signature) is False

    def test_identity_verify_wrong_signature(self):
        ident = Identity.generate()
        message = b"test message"
        signature = ident.sign(message)
        wrong_signature = b"x" * 64
        assert Identity.verify(ident.public_key, message, wrong_signature) is False


class TestEncryptedSession:
    def test_encrypted_session_roundtrip(self):
        alice = Identity.generate()
        bob = Identity.generate()
        alice_session = EncryptedSession(alice.private_key, bob.public_key)
        bob_session = EncryptedSession(bob.private_key, alice.public_key)
        plaintext = b"secret message"
        encrypted = alice_session.encrypt(plaintext)
        decrypted = bob_session.decrypt(encrypted)
        assert decrypted == plaintext

    def test_encrypted_session_format(self):
        alice = Identity.generate()
        bob = Identity.generate()
        session = EncryptedSession(alice.private_key, bob.public_key)
        plaintext = b"hello"
        encrypted = session.encrypt(plaintext)
        assert len(encrypted) >= 24 + len(plaintext)
        assert encrypted[:24] != b"\x00" * 24

    def test_encrypted_session_different_parties(self):
        alice = Identity.generate()
        bob = Identity.generate()
        alice_to_bob = EncryptedSession(alice.private_key, bob.public_key)
        bob_to_alice = EncryptedSession(bob.private_key, alice.public_key)
        msg1 = b"alice to bob"
        msg2 = b"bob to alice"
        assert bob_to_alice.decrypt(alice_to_bob.encrypt(msg1)) == msg1
        assert alice_to_bob.decrypt(bob_to_alice.encrypt(msg2)) == msg2

    def test_encrypted_session_multiple_messages(self):
        alice = Identity.generate()
        bob = Identity.generate()
        session = EncryptedSession(alice.private_key, bob.public_key)
        decrypt_session = EncryptedSession(bob.private_key, alice.public_key)
        messages = [b"msg1", b"msg2", b"msg3"]
        for msg in messages:
            encrypted = session.encrypt(msg)
            decrypted = decrypt_session.decrypt(encrypted)
            assert decrypted == msg

    def test_encrypted_session_decrypt_invalid(self):
        alice = Identity.generate()
        bob = Identity.generate()
        session = EncryptedSession(alice.private_key, bob.public_key)
        with pytest.raises(nacl.exceptions.CryptoError):
            session.decrypt(b"invalid ciphertext")
        with pytest.raises(nacl.exceptions.CryptoError):
            session.decrypt(b"x" * 100)

    def test_encrypted_session_decrypt_wrong_session(self):
        alice = Identity.generate()
        bob = Identity.generate()
        charlie = Identity.generate()
        alice_bob = EncryptedSession(alice.private_key, bob.public_key)
        charlie_alice = EncryptedSession(charlie.private_key, alice.public_key)
        encrypted = alice_bob.encrypt(b"secret")
        with pytest.raises(nacl.exceptions.CryptoError):
            charlie_alice.decrypt(encrypted)
