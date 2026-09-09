Projection Encodings
=====================

Treat projections as local views. Parse them in the order below.

Article view
============

A view is one article row with author state. You find the view code in ``src/bonnet/net/firehose_commands.py``.

Encode fields in this order.

View head: u64 number plus u8 length plus article ID plus u8 length plus event ID plus u8 state code plus u8 body code.

View hash: u8 length plus body hash plus u64 body size plus i64 stamp plus u8 length plus author key.

View text: text16 author name plus text16 author registrar plus text16 subject plus text16 tags plus text16 content type.

View links: u8 length plus root ID plus u8 length plus reply ID plus u8 swap flag with a 32-byte ID past a set flag.

View tail: text16 pin state plus text16 thread state plus text16 author check plus u32 length plus body bytes.

1. Read state 0 as live, 1 as cancelled, 2 as superseded.
2. Read body code 0 as at hand, 1 as remote, 2 as purged.
3. Attach the body only when all three are true. The flag is set, the body is at hand, and the size is past zero.
4. Drop the body bytes in list rows.

List and search rows
====================

1. Read list rows as views with no body bytes.
2. Read search rows in two parts.

Search row: u64 number plus u8 length plus article ID plus u8 length plus subject.

Search tail: u8 length plus author key plus i64 stamp plus u8 body flag plus text16 excerpt.
3. Read a u16 row count plus u32 total plus u8 cut flag before search rows.
4. Sort aggregate rows by newest first, then origin, then number.

User rows
=========

1. Read user rows in two parts.

User head: u8 key length plus key bytes plus text16 name.

User tail: u64 flags plus u64 register sequence plus i64 stamp plus u8 revoked flag plus u64 revoke sequence per row, zero when unrevoked.
2. Read a u64 revoke sequence after the flag in single user reads.
3. Read a text16 origin prefix before each row in user lists.

Track applied state per origin: dedup keys are (origin, event ID) pairs, never
bare event IDs. Two origins that mint the same ID project independently.

Board rows
==========

1. Read board rows in one shape.

Board row: text16 name plus u8 shut flag plus u8 owner length plus owner bytes plus text16 display name.
2. Read a text16 origin prefix before each row in aggregate reads.

Report rows
===========

Report head: 32-byte event ID plus text16 origin plus u64 sequence plus 32-byte reporter key plus text16 reporter name.

Report target: 32-byte culprit key plus text16 target origin plus text16 target board plus 32-byte target article plus 32-byte target event.

Report tail: 32-byte body hash plus u32 body size plus u64 stamp.

Punish rows
===========

Read punish rows in two parts.

Punish head: u8 punish type plus i64 expiry plus u32 body size.

Punish tail: 32-byte body hash plus 32-byte event ID plus text16 origin.
