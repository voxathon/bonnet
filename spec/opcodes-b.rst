Application Opcodes
===================

Read boards through these commands. Scope each call to one board.

BOARD_LIST (0x10)
=================

Request: opcode u8 plus text16 origin. An empty origin is a call for all origins.

Response: u16 board count plus rows of text16 name plus u8 shut flag plus u8 owner length plus owner bytes plus text16 display name. Rows from an aggregate call start with a text16 origin prefix.

1. Omit boards that the caller lacks rights to read.
2. Omit origins past the allow list.

ARTICLE_GET (0x11)
==================

Request: opcode u8 plus text16 origin plus text16 board plus u8 selector type plus selector plus u8 body flag. Selector type 0x01 is a u64 article number. Selector type 0x02 is a 32-byte article ID.

Response: one article view. The shape of the view is under Projections.

1. Reject a bad selector type with code 0x0005.
2. Attach the body only when the flag is set and the body is at hand.

ARTICLE_LIST (0x12)
===================

Request: opcode u8 plus text16 origin plus text16 board plus u32 offset plus u16 limit plus u8 flags. Read flags as row switches: 0x01 cancelled, 0x02 superseded, 0x04 purged.

Response: u16 row count plus article views with no body bytes. Aggregate rows start with a text16 origin prefix.

1. Clamp the limit from 1 to 65535.
2. Sort aggregate rows by newest first, then origin, then number.

ARTICLE_SEARCH (0x13)
=====================

Request: opcode u8 plus text16 origin plus text16 board plus text16 field query plus text16 body query plus u32 offset plus u16 limit plus u8 flags. Read the flags as row switches: 0x01 cancelled, 0x02 superseded.

Response: u16 row count plus u32 total plus u8 cut flag plus search rows.

Search row: u64 number plus u8 length plus article ID plus u8 length plus subject.

Search tail: u8 length plus author key plus i64 stamp plus u8 body flag plus text16 excerpt.

ARTICLE_QUERY (0x15)
====================

Request: opcode u8 plus text16 origin plus text16 board plus u8 filter count plus filters plus u32 offset plus u16 limit. Each filter is u8 field ID plus u8 operator plus u8 value type plus u16 value length plus value bytes. Value type 0x01 is raw bytes. Value type 0x02 is UTF-8 text. Value type 0x03 is i64. Value type 0x04 is a bool byte.

Response: u16 row count plus article views with no body bytes.

1. Reject a bad value type with code 0x0006.

ARTICLE_BODY (0x14)
===================

Request: opcode u8 plus text16 origin plus text16 board plus u64 article number.

Response: u32 body length plus body bytes. A remote body is status 0x02 with the origin plus host plus port of its home.

1. Return code 0x0008 past a purged body.
2. Return code 0x0007 past a body that misses its hash.

USER_GET (0x20)
===============

Request: opcode u8 plus text16 origin plus u8 key length plus key bytes.

Response: u8 key length plus key bytes plus text16 name.

Also: u64 flags plus u64 register sequence plus i64 stamp.

Also: u8 revoked flag plus u64 revoke sequence.

1. Return code 0x0001 past a missing user.

USER_LIST (0x21)
================

Request: opcode u8 plus text16 origin plus u8 flags. Read flag 0x01 as revoked users on.

Response: u16 row count plus user rows.

Row start: text16 origin plus u8 key length plus key bytes.

Row mid: text16 name plus u64 flags plus u64 register sequence.

Row end: i64 stamp plus u8 revoked flag. A revoke sequence is past all rows.

BAN_STATUS (0x22)
=================

Request: opcode u8 plus u8 key length plus key bytes. The call has no origin slot.

Response: u8 row count plus punishment rows.

Row head: u8 punish type plus i64 expiry plus u32 body size.

Row tail: 32-byte body hash plus 32-byte event ID plus text16 origin. Type 1 is a warning. Type 2 is a ban. Type 3 is a permaban.

REPORT_LIST (0x23)
==================

Request: opcode u8 plus u8 culprit length plus culprit bytes plus u16 limit plus u16 offset. Empty culprit bytes are a call for all reports.

Response: u16 row count plus report rows.

Report head: 32-byte event ID plus text16 origin plus u64 sequence plus 32-byte reporter key plus text16 reporter name.

Report target: 32-byte culprit key plus text16 target origin plus text16 target board plus 32-byte target article plus 32-byte target event.

Report tail: 32-byte body hash plus u32 body size plus u64 stamp.

1. Omit reports on boards that the caller lacks rights to read.
2. Use a limit of 100 past a zero limit.

EVENT_BODY (0x30)
=================

Request: opcode u8 plus text16 origin plus 32-byte event ID.

Response: u32 body length plus body bytes.
