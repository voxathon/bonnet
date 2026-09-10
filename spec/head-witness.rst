Head, Witness, and Rotation Proof
====================================

Trust the head key only through rotation records. Witness what you saw yourself.

Head
====

A head is the signed tip of one origin log. You find the code in ``src/bonnet/core/record.py``.

.. list-table:: Head fields
   :header-rows: 1

   * - Order
     - Field
     - Type
   * - 1
     - head_format
     - u8, always 1
   * - 2
     - origin
     - text16, cap 253
   * - 3
     - latest_origin_seq
     - u64
   * - 4
     - latest_event_hash
     - id32
   * - 5
     - event_count
     - u64
   * - 6
     - generated_at
     - i64
   * - 7
     - origin_pubkey
     - key32

Append the 64-byte origin signature after the key. The pair is the signed head.

1. Sign DOMAIN_HEAD_SIG plus the unsigned bytes with the origin key.
2. Check the head signature with the head key before you trust the tip.
3. Hash the signed head for the head hash.
4. If head_format is not 1, reject the input as an invalid value.

Witness
=======

A witness is a signed receipt for one event and one handover.

.. list-table:: Witness fields
   :header-rows: 1

   * - Order
     - Field
     - Type
   * - 1
     - witness_format
     - u8, always 1
   * - 2
     - event_origin
     - text16, cap 253
   * - 3
     - event_id
     - id32
   * - 4
     - event_hash
     - id32
   * - 5
     - relay_pubkey
     - key32
   * - 6
     - relay_hostname
     - text16, cap 253
   * - 7
     - received_from_pubkey
     - key32
   * - 8
     - received_from_hostname
     - text16, cap 253
   * - 9
     - seen_at
     - i64

Append the 64-byte relay signature after seen_at. The pair is the signed witness.

1. Sign DOMAIN_WITNESS_SIG plus the unsigned bytes with the relay key.
2. Name the peer that you spoke to in the received_from fields.
3. Never copy the upstream claim into your own witness.
4. Check the relay signature with the relay key before you keep the witness.
5. If witness_format is not 1, reject the input as an invalid value.

Origin witness
==============

The origin signs the first witness for its own events. That witness is the end of the chain.

1. Set received_from_pubkey to 32 zero bytes.
2. Set received_from_hostname to empty text.
3. Set relay_pubkey to the origin key.
4. A witness with a zero upstream key and an empty upstream name is an origin witness.

Witness set wire shape
======================

Encode a witness set as a u16 count. Then encode each witness as a u16 length plus raw bytes.

1. Keep at most 32 witnesses in one set.
2. If the count tops 32, keep the first 32 in wire order and ignore the rest. Warn on truncation.
3. Order the set for truncation as own witness first, then origin witnesses,
   then newest first, then key order. Wire order is truncation order. Display
   order is the reader's own choice: the gateway re-sorts on read.

Rotation proof
==============

A rotation proof is the move of the origin key from old to new.

1. Encode the payload as text16 origin plus key32 old key plus key32 new key.
2. Sign DOMAIN_KEY_ROTATION_PROOF plus the payload with the new key.
3. Check the proof with the new key before you trust the move.
4. Check the rotate record signature with the old key.
5. Treat epoch hints from a peer as hints only.
6. Carry the proof in the metadata of a rotate record.
