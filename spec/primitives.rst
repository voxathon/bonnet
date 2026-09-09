Primitive Encodings
===================

Encode every integer with the most significant byte first. Reject all bytes that break the rules below.

These encodings are the base of all structures in this spec. You need no other integer forms.

.. list-table:: Primitive forms
   :header-rows: 1

   * - Name
     - Bytes
     - Range
   * - u8
     - 1
     - 0 to 0xFF
   * - u16
     - 2
     - 0 to 0xFFFF
   * - u32
     - 4
     - 0 to 0xFFFFFFFF
   * - u64
     - 8
     - 0 to 2^63-1
   * - i64
     - 8
     - -2^63 to 2^63-1
   * - id32
     - 32
     - raw bytes
   * - key32
     - 32
     - raw key bytes
   * - sig64
     - 64
     - raw signature bytes
   * - text16
     - 2 plus text
     - length as u16, then UTF-8 text
   * - blob32
     - 4 plus data
     - length as u32, then raw data

The top bit of u64 is never set.

Encode
======

1. Encode u8, u16, u32, u64, and i64 with the most significant byte first.
2. Keep u64 at or below 2^63-1.
3. Keep i64 from -2^63 to 2^63-1.
4. Normalize text to Normal Form Composed (NFC). Then encode it as UTF-8.
5. Prefix text16 with its length in bytes as u16.
6. Prefix blob32 with its length in bytes as u32.
7. Encode fixed fields with no length prefix.

Decode
======

1. If bytes end early, reject the input as truncated.
2. If bytes remain after the last field, reject the input as trailing.
3. Reject u64 input with the top bit set.
4. Reject text that fails UTF-8 decoding.
5. Reject text that is not NFC.
6. Enforce the cap of the field you decode.

Caps
====

The default cap for text16 is 0xFFFF bytes. The default cap for blob32 is 0xFFFFFFFF bytes. Each structure has its own lower caps. Enforce the cap of the field you decode.

Faults
======

Map each reject to one fault below.

- truncated input: too few bytes
- trailing input: spare bytes
- length exceeded: past the cap
- noncanonical form: more than one read
- invalid value: past the range
