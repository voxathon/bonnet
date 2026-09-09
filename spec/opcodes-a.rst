Substrate Opcodes
==================

Sync with these six commands. Send no board name in them.

PUBLISH_RECORD (0x01)
=====================

Request: opcode u8 plus u32 intent length plus intent bytes plus 64-byte actor signature plus u32 body length plus body bytes.

Response: u32 record length plus signed record bytes plus u16 witness length plus witness bytes.

1. Sign the intent before you send it.
2. Send the body with the hash that the intent names.
3. Store the record under its origin and sequence.
4. Return the stored record with your witness set.

EVENT_HEAD (0x02)
=================

Request: opcode u8 plus text16 origin.

Response: u16 head length plus signed head bytes.

1. Ask for the origin by its canonical name.
2. Return code 0x0002 past a missing head.

EVENT_RANGE (0x03)
==================

Request: opcode u8 plus text16 origin plus u64 start sequence plus u16 max count plus u32 max bytes.

Response: u16 row count plus rows of u32 record length plus record bytes plus witness set.

1. Order rows by origin sequence from the start sequence up.
2. Return at most max count rows.
3. Treat max bytes of zero as no byte cap.
4. Stop before a record that tops a nonzero byte cap.
5. Count record bytes plus witness bytes toward the cap.

EVENT_GET (0x04)
================

Request: opcode u8 plus text16 origin plus 32-byte event ID.

Response: u32 record length plus record bytes plus witness set.

1. Return code 0x0003 past a missing event.

KEY_EPOCHS (0x05)
=================

Request: opcode u8 plus text16 origin.

Response: u16 epoch count plus rows of u64 start sequence plus u64 end sequence plus 32-byte key.

1. Write zero as the end sequence of the open epoch.
2. Order epochs from sequence 1 with no gaps and no overlap.
3. Return code 0x0002 past missing epochs.
4. Treat the table as hints. Trust each bound only through a rotation record.

PERMISSIONS (0x06)
==================

Request: opcode u8 plus text16 board name. An empty board is a call for board-free rights only.

Response: text16 principal plus text16 role plus text16 board echo plus u16 command count plus text16 commands plus u16 kind count plus text16 kinds.

1. Scope the answer to the board that the call names.
2. Name only the commands and kinds that the caller holds.
