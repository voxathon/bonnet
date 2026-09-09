Command Framing
===============

Prefix each command with one opcode byte. Read status first.

Frames
======

A request is one opcode byte plus opcode fields. A response is one status byte plus a payload. You find the wire code in ``src/bonnet/net/firehose_wire.py``.

.. list-table:: Status bytes
   :header-rows: 1

   * - Byte
     - Name
     - Payload
   * - 0x00
     - success
     - opcode fields
   * - 0x01
     - error
     - u16 code plus u16 length plus UTF-8 text
   * - 0x02
     - body redirect
     - text16 origin plus text16 host plus u16 port

The redirect is body-only. It occurs only on ARTICLE_BODY (0x14) for remote
bodies. It is the address of the body. Other opcodes never send it.

.. list-table:: Opcodes
   :header-rows: 1

   * - Byte
     - Name
     - Access
   * - 0x01
     - PUBLISH_RECORD
     - write
   * - 0x02
     - EVENT_HEAD
     - read
   * - 0x03
     - EVENT_RANGE
     - read
   * - 0x04
     - EVENT_GET
     - read
   * - 0x05
     - KEY_EPOCHS
     - read
   * - 0x06
     - PERMISSIONS
     - read
   * - 0x10
     - BOARD_LIST
     - read
   * - 0x11
     - ARTICLE_GET
     - read
   * - 0x12
     - ARTICLE_LIST
     - read
   * - 0x13
     - ARTICLE_SEARCH
     - read
   * - 0x14
     - ARTICLE_BODY
     - read
   * - 0x15
     - ARTICLE_QUERY
     - read
   * - 0x20
     - USER_GET
     - read
   * - 0x21
     - USER_LIST
     - read
   * - 0x22
     - BAN_STATUS
     - read
   * - 0x23
     - REPORT_LIST
     - read
   * - 0x30
     - EVENT_BODY
     - read

Errors
======

.. list-table:: Error codes
   :header-rows: 1

   * - Code
     - Name
   * - 0x0000
     - fault inside the server
   * - 0x0001
     - user past reach
   * - 0x0002
     - head or epochs past reach
   * - 0x0003
     - target past reach
   * - 0x0004
     - access denied
   * - 0x0005
     - opcode past reach
   * - 0x0006
     - bad bytes or bad values
   * - 0x0007
     - body hash miss
   * - 0x0008
     - body purged
   * - 0x0009
     - state clash
   * - 0x000A
     - punishment gate shut

1. Send code 0x0006 for bytes that miss the shape rules.
2. Send code 0x0004 for calls that miss the access rules.
3. Send code 0x0003 for names that match no stored row.
4. Raise the error code plus the text on the caller side.
