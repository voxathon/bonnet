Actor Intent
============

Sign the intent before you send it. Encode fields in the order below.

Wire order
==========

An intent is what the author signs. A record is the intent plus chain state. You find the code in ``src/bonnet/core/record.py``.

.. list-table:: Intent fields
   :header-rows: 1

   * - Order
     - Field
     - Type
   * - 1
     - intent_format
     - u8, always 1
   * - 2
     - event_id
     - id32, never zero
   * - 3
     - kind
     - text16, cap 128
   * - 4
     - schema_version
     - u16
   * - 5
     - origin
     - text16, cap 253
   * - 6
     - actor_pubkey
     - key32
   * - 7
     - actor_username
     - text16, cap 4096
   * - 8
     - actor_registrar
     - text16, cap 253
   * - 9
     - board
     - text16, cap 255
   * - 10
     - article_id
     - id32
   * - 11
     - target_origin
     - text16, cap 253
   * - 12
     - target_board
     - text16, cap 255
   * - 13
     - target_article_id
     - id32
   * - 14
     - target_event_id
     - id32
   * - 15
     - metadata
     - blob32 of a metadata map
   * - 16
     - body_hash
     - id32
   * - 17
     - body_size
     - u64

Encode
======

1. Set intent_format to 1.
2. Set event_id to a fresh value.
3. Never encode a zero event_id. Reject a zero event_id on decode.
4. Name the kind from the kind table.
5. Hash the body. Store the digest plus the size.
6. Use an empty board for acts that touch no board.

Sign
====

1. Sign DOMAIN_INTENT_SIG plus the encoded intent.
2. Store the 64-byte output as the actor signature.
3. Check the actor signature with the actor key before you trust the intent.
