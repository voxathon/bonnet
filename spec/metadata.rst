Metadata Map
============

Order fields by ID. Reject maps that break the shape below.

Wire shape
==========

Encode a map as a u16 field count. Then encode each field in list order. Use u16 field ID plus u8 value type plus u32 value length plus raw value bytes. You find the map code in ``src/bonnet/core/record.py``.

.. list-table:: Value types
   :header-rows: 1

   * - Code
     - Name
     - Shape
   * - 0x01
     - BYTES
     - raw bytes
   * - 0x02
     - TEXT
     - UTF-8 bytes in Normal Form Composed, at most 4096 bytes
   * - 0x03
     - U64
     - 8 bytes with the most significant byte first, at most 2^63-1
   * - 0x04
     - I64
     - 8 bytes with the most significant byte first, signed
   * - 0x05
     - BOOL
     - one byte, 0x00 or 0x01
   * - 0x06
     - ID_LIST
     - u16 count plus 32-byte items
   * - 0x07
     - TEXT_LIST
     - u16 count plus text16 items in byte sort order with no duplicates

Encode
======

1. Keep at most 256 fields in one map.
2. Order field IDs in strict rise order.
3. Reject a repeat or a fall in order as a noncanonical form.
4. Use only the seven types in the table above.
5. Keep total value bytes at or below 1048576.
6. Sort text lists by encoded bytes before you store them.

Decode
======

1. If the count tops 256, reject the input as length exceeded.
2. If you find a repeat or a fall in field IDs, reject the input as a noncanonical form.
3. If the type code is unknown, reject the input as an invalid value.
4. If you run past the end of bytes, reject the input as truncated.
5. Check each value against its type row before you keep it.
6. If you count past 1048576 value bytes, reject the input as length exceeded.
7. If you find bytes past the last field, reject the input as trailing.

Value checks
============

1. Reject TEXT that fails UTF-8 decoding or misses Normal Form Composed.
2. Reject TEXT past 4096 bytes.
3. Reject U64 of the wrong length or past 2^63-1.
4. Reject I64 of the wrong length.
5. Reject BOOL past one byte or past 0x01.
6. Reject ID_LIST items past 32 bytes or with spare bytes at the end.
7. Reject TEXT_LIST entries past 4096 bytes, past UTF-8 rules, past sort order, or past the ban on duplicates.
