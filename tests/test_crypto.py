# Copyright 2026 The Bonnet Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import pytest

from bonnet.core.crypto import Identity


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
        _signature = ident.sign(message)
        wrong_signature = b"x" * 64
        assert Identity.verify(ident.public_key, message, wrong_signature) is False
