Domain Tags and Cryptography
==============================

Prefix every hash and signature with its tag. Read the table before you sign.

Tags
====

Each tag is text plus a trailing zero byte. No tag is the start of another tag. You find the tags in ``src/bonnet/core/record.py``.

.. list-table:: Domain tags
   :header-rows: 1

   * - Name
     - Bytes
   * - DOMAIN_BODY
     - ``b"untp.body.hash.v1\x00"``
   * - DOMAIN_INTENT_SIG
     - ``b"untp.intent.signature.v1\x00"``
   * - DOMAIN_RECORD_SIG
     - ``b"untp.record.signature.v1\x00"``
   * - DOMAIN_EVENT_HASH
     - ``b"untp.event.hash.v1\x00"``
   * - DOMAIN_HEAD_SIG
     - ``b"untp.head.signature.v1\x00"``
   * - DOMAIN_HEAD_HASH
     - ``b"untp.head.hash.v1\x00"``
   * - DOMAIN_WITNESS_SIG
     - ``b"untp.witness.signature.v1\x00"``
   * - DOMAIN_KEY_ROTATION_PROOF
     - ``b"untp.key.rotation.proof.v1\x00"``

1. Hash TAG plus payload for every digest.
2. Sign TAG plus payload for every signature.
3. Never sign a bare payload.
4. If you change a tag, reject all past hashes and signatures.

Keys and signatures
===================

Use Ed25519 only. Use raw 32-byte keys with no wrapping format. Use raw 64-byte signatures. You find the key code in ``src/bonnet/core/crypto.py``.

1. Sign with the key that the field names.
2. Check each signature with the key it names.
3. Treat a failed check as false.
4. Never raise on a bad key or a bad signature.

Hashes
======

Use SHA-256 for all digests.

1. Hash a body as SHA-256 over DOMAIN_BODY plus the body bytes.
2. Hash an event as SHA-256 over DOMAIN_EVENT_HASH plus the signed record bytes.
3. Hash a head as SHA-256 over DOMAIN_HEAD_HASH plus the signed head bytes.
