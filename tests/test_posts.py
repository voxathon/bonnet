# -*- coding: utf-8 -*-

import pytest
import struct
from unittest.mock import MagicMock, AsyncMock
from core.crypto import Identity
from engine.ume import User
from engine.ame import Post


class TestPostCreateRequestFormat:
    def test_post_create_with_all_fields(self):
        board = b"general"
        root = 0
        subject = b"Hello World"
        tags = b"greeting,intro"
        options = b""
        content = b"This is my first post!"

        payload = (
            bytes([len(board)])
            + board
            + struct.pack(">Q", root)
            + bytes([len(subject)])
            + subject
            + bytes([len(tags)])
            + tags
            + bytes([len(options)])
            + options
            + struct.pack(">I", len(content))
            + content
        )

        cmd = 0x12
        request = bytes([cmd]) + payload

        idx = 0
        assert request[idx] == 0x12
        idx += 1

        b_len = request[idx]
        idx += 1
        assert request[idx : idx + b_len] == board
        idx += b_len

        parsed_root = struct.unpack(">Q", request[idx : idx + 8])[0]
        assert parsed_root == root
        idx += 8

        s_len = request[idx]
        idx += 1
        assert request[idx : idx + s_len] == subject
        idx += s_len

        t_len = request[idx]
        idx += 1
        assert request[idx : idx + t_len] == tags
        idx += t_len

        o_len = request[idx]
        idx += 1
        assert request[idx : idx + o_len] == options
        idx += o_len

        c_len = struct.unpack(">I", request[idx : idx + 4])[0]
        idx += 4
        assert request[idx : idx + c_len] == content

    def test_post_create_empty_tags_options(self):
        board = b"test"
        root = 0
        subject = b"No tags"
        tags = b""
        options = b""
        content = b"content"

        payload = (
            bytes([len(board)])
            + board
            + struct.pack(">Q", root)
            + bytes([len(subject)])
            + subject
            + bytes([0])
            + bytes([0])
            + struct.pack(">I", len(content))
            + content
        )

        cmd = 0x12
        request = bytes([cmd]) + payload

        idx = 0
        assert request[idx] == 0x12
        idx += 1

        b_len = request[idx]
        idx += 1
        assert request[idx : idx + b_len] == board
        idx += b_len

        parsed_root = struct.unpack(">Q", request[idx : idx + 8])[0]
        assert parsed_root == root
        idx += 8

        s_len = request[idx]
        idx += 1
        assert request[idx : idx + s_len] == subject
        idx += s_len

        t_len = request[idx]
        idx += 1
        assert t_len == 0

        o_len = request[idx + 1]
        assert o_len == 0


class TestPostCreateResponseFormat:
    def test_post_create_response_parsing(self):
        post_num = 42
        creation_date = 1234567890
        last_modified = 1234567890
        author = b"alice"
        author_registrar = b"localhost"
        tags = b"test,intro"
        subject = b"Hello"
        options = b""

        response = (
            bytes([0x00])
            + struct.pack(">Q", post_num)
            + struct.pack(">q", creation_date)
            + struct.pack(">q", last_modified)
            + bytes([len(author)])
            + author
            + bytes([len(author_registrar)])
            + author_registrar
            + bytes([len(tags)])
            + tags
            + bytes([len(subject)])
            + subject
            + bytes([len(options)])
            + options
        )

        idx = 0
        assert response[idx] == 0x00
        idx += 1

        parsed_post_num = struct.unpack(">Q", response[idx : idx + 8])[0]
        assert parsed_post_num == post_num
        idx += 8

        parsed_creation = struct.unpack(">q", response[idx : idx + 8])[0]
        assert parsed_creation == creation_date
        idx += 8

        parsed_modified = struct.unpack(">q", response[idx : idx + 8])[0]
        assert parsed_modified == last_modified
        idx += 8

        a_len = response[idx]
        idx += 1
        assert response[idx : idx + a_len] == author
        idx += a_len

        ar_len = response[idx]
        idx += 1
        assert response[idx : idx + ar_len] == author_registrar
        idx += ar_len

        t_len = response[idx]
        idx += 1
        assert response[idx : idx + t_len] == tags
        idx += t_len

        s_len = response[idx]
        idx += 1
        assert response[idx : idx + s_len] == subject
        idx += s_len

        o_len = response[idx]
        idx += 1
        assert o_len == 0


class TestPostSignRequestFormat:
    def test_post_sign_request_format(self):
        board = b"general"
        post_num = 42
        signature_hex = b"a" * 128

        payload = (
            bytes([len(board)])
            + board
            + struct.pack(">Q", post_num)
            + bytes([len(signature_hex)])
            + signature_hex
        )

        cmd = 0x22
        request = bytes([cmd]) + payload

        idx = 0
        assert request[idx] == 0x22
        idx += 1

        b_len = request[idx]
        idx += 1
        assert request[idx : idx + b_len] == board
        idx += b_len

        parsed_post_num = struct.unpack(">Q", request[idx : idx + 8])[0]
        assert parsed_post_num == post_num
        idx += 8

        sig_len = request[idx]
        idx += 1
        assert sig_len == 128
        assert request[idx : idx + sig_len] == signature_hex


class TestSignedPayloadFormat:
    def test_signed_payload_construction(self):
        post_num = 42
        creation_date = 1234567890
        last_modified = 1234567891
        author = b"alice"
        author_registrar = b"localhost"
        tags = b"test,sign"
        subject = b"Signed Post"
        options = b""
        content = b"This is the content of the post."

        payload = (
            struct.pack(">Q", post_num)
            + struct.pack(">q", creation_date)
            + struct.pack(">q", last_modified)
            + bytes([len(author)])
            + author
            + bytes([len(author_registrar)])
            + author_registrar
            + bytes([len(tags)])
            + tags
            + bytes([len(subject)])
            + subject
            + bytes([len(options)])
            + options
            + struct.pack(">I", len(content))
            + content
        )

        idx = 0
        parsed_post_num = struct.unpack(">Q", payload[idx : idx + 8])[0]
        assert parsed_post_num == post_num
        idx += 8

        parsed_creation = struct.unpack(">q", payload[idx : idx + 8])[0]
        assert parsed_creation == creation_date
        idx += 8

        parsed_modified = struct.unpack(">q", payload[idx : idx + 8])[0]
        assert parsed_modified == last_modified
        idx += 8

        a_len = payload[idx]
        idx += 1
        assert payload[idx : idx + a_len] == author
        idx += a_len

        ar_len = payload[idx]
        idx += 1
        assert payload[idx : idx + ar_len] == author_registrar
        idx += ar_len

        t_len = payload[idx]
        idx += 1
        assert payload[idx : idx + t_len] == tags
        idx += t_len

        s_len = payload[idx]
        idx += 1
        assert payload[idx : idx + s_len] == subject
        idx += s_len

        o_len = payload[idx]
        idx += 1
        assert o_len == 0

        c_len = struct.unpack(">I", payload[idx : idx + 4])[0]
        idx += 4
        assert payload[idx : idx + c_len] == content


class TestPostSignVerification:
    def test_signature_hex_roundtrip(self):
        ident = Identity.generate()
        message = b"test message for signing"
        signature = ident.sign(message)
        signature_hex = signature.hex()
        restored = bytes.fromhex(signature_hex)
        assert restored == signature
        assert len(signature_hex) == 128
        assert Identity.verify(ident.public_key, message, restored) is True

    def test_signature_verify_tampered_payload(self):
        ident = Identity.generate()
        original_payload = b"original content"
        tampered_payload = b"tampered content"
        signature = ident.sign(original_payload)
        assert Identity.verify(ident.public_key, original_payload, signature) is True
        assert Identity.verify(ident.public_key, tampered_payload, signature) is False

    def test_signature_hex_invalid_format(self):
        with pytest.raises(ValueError):
            bytes.fromhex("gg" * 64)

    def test_signature_bytes_length(self):
        ident = Identity.generate()
        message = b"test"
        signature = ident.sign(message)
        assert len(signature) == 64
        assert len(signature.hex()) == 128


class TestTagsValidation:
    def test_tags_max_count(self):
        tags = ",".join([f"tag{i}" for i in range(256)])
        assert len(tags.split(",")) == 256

    def test_tags_max_length_per_tag(self):
        long_tag = "x" * 256
        tags = long_tag
        assert len(tags.split(",")[0]) == 256

    def test_tags_empty(self):
        tags = ""
        tags_list = [t.strip() for t in tags.split(",") if t.strip()]
        assert tags_list == []

    def test_tags_whitespace_trimming(self):
        tags = "  tag1  ,  tag2  ,  tag3  "
        tags_list = [t.strip() for t in tags.split(",") if t.strip()]
        assert tags_list == ["tag1", "tag2", "tag3"]
