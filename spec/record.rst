Origin Record
=============

Chain each record to the last one. Encode fields in the order below.

Wire order
==========

A record is an intent plus chain state plus two signatures. You find the code in ``src/bonnet/core/record.py``.

.. list-table:: Unsigned record fields
   :header-rows: 1

   * - Order
     - Field
     - Type
   * - 1
     - record_format
     - u8, always 1
   * - 2
     - origin
     - text16, cap 253
   * - 3
     - origin_seq
     - u64
   * - 4
     - previous_event_hash
     - id32
   * - 5
     - event_id
     - id32
   * - 6
     - kind
     - text16, cap 128
   * - 7
     - schema_version
     - u16
   * - 8
     - created_at
     - i64
   * - 9
     - actor_pubkey
     - key32
   * - 10
     - actor_username
     - text16, cap 4096
   * - 11
     - actor_registrar
     - text16, cap 253
   * - 12
     - board
     - text16, cap 255
   * - 13
     - article_id
     - id32
   * - 14
     - article_num
     - u64
   * - 15
     - target_origin
     - text16, cap 253
   * - 16
     - target_board
     - text16, cap 255
   * - 17
     - target_article_id
     - id32
   * - 18
     - target_event_id
     - id32
   * - 19
     - metadata
     - blob32 of a metadata map
   * - 20
     - body_hash
     - id32
   * - 21
     - body_size
     - u64
   * - 22
     - actor_signature
     - sig64

Append the 64-byte origin signature after the actor signature. The pair is the signed record.

Encode
======

1. Set record_format to 1.
2. Number origin_seq from 1 with no gaps.
3. Set previous_event_hash to the event hash of the last record.
4. Set previous_event_hash to zero for the first record.
5. Copy intent fields straight from the signed intent.
6. Stamp created_at with the current time.

Sign
====

1. Sign DOMAIN_RECORD_SIG plus the unsigned bytes with the origin key.
2. Check the origin signature with the origin key of the right epoch.
3. Then check the actor signature against the intent that you rebuild.
4. Rebuild the intent with the same field values and no chain state.
5. Drop record_format, origin_seq, previous_event_hash, created_at, article_num, and both signatures in the rebuild.

Decode
======

1. If record_format is not 1, reject the input as an invalid value.
2. Read fields in wire order with reader checks.
3. If you run past the end of bytes, reject the input as truncated.
4. If you find bytes past the last signature, reject the input as trailing.
