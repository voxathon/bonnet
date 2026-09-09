Record Kinds
============

Name each record with one kind. Give each kind the fields below.

Registry
========

You find the kind strings in ``src/bonnet/core/kinds.py``. You find the field rules in ``src/bonnet/core/kind_validator.py``.

.. list-table:: Kinds
   :header-rows: 1

   * - Kind
     - Use
   * - bonnet.article
     - new article text
   * - bonnet.article.cancel
     - hide an article
   * - bonnet.article.restore
     - show it back
   * - bonnet.article.purge
     - drop its body
   * - bonnet.article.pin
     - pin it with rank
   * - bonnet.article.unpin
     - unpin it
   * - bonnet.thread.close
     - shut a thread
   * - bonnet.thread.reopen
     - open it back
   * - bonnet.board.create
     - open a board
   * - bonnet.board.close
     - shut a board
   * - bonnet.board.reopen
     - open it back
   * - bonnet.user.register
     - add a user
   * - bonnet.user.revoke
     - cut a user off
   * - bonnet.user.key.rotate
     - move a user key
   * - bonnet.rule.publish
     - set a rule
   * - bonnet.rule.revoke
     - drop a rule
   * - bonnet.report
     - flag a culprit
   * - bonnet.punishment.warn
     - warn a key
   * - bonnet.punishment.ban
     - ban a key to a date
   * - bonnet.punishment.permaban
     - ban a key for good
   * - bonnet.punishment.revoke
     - lift a punishment
   * - bonnet.punishment.ack
     - mark it read
   * - bonnet.origin.key.rotate
     - move the origin key

1. Spell kinds in lower case with the dots shown. Treat this as a SHOULD: a peer
   stays conformant when it sends another casing, but the registry holds lower
   case only and validation skips unknown kinds past the printable-ASCII gate.
2. Reject non-printable bytes in a kind name.
3. Skip validation past unknown kinds.

Articles
========

1. Give ``bonnet.article`` a board plus an article ID plus no targets.
2. Give it metadata field 1 as subject text plus field 4 as content-type text.
3. Keep subject non-empty. Keep content-type non-empty with no whitespace, no
   controls, and ASCII only (``0x21`` to ``0x7E``).
4. Give cancel, restore, and purge a full article target plus an empty board.
5. Give pin, unpin, thread close, and thread reopen the same target shape.
6. Give pin metadata field 1 as rank in i64 form.

Boards
======

1. Give board create, close, and reopen a board plus fully empty targets.
   A stray target tuple is refused. It never acts on a remote board.
2. Give board create metadata field 1 as owner key bytes.

Users
=====

1. Give user register an empty board plus fully empty targets.
2. Give it metadata field 1 as name text plus field 2 as key bytes plus field 3 as flags u64.
3. Keep flags inside the low two bits.
4. Give user revoke an event target plus an empty board.
5. Give it metadata field 1 as revoked key bytes.
6. Give user key rotate empty board plus empty targets.
7. Give it metadata field 1 as new key bytes plus field 2 as proof bytes.
8. Keep the new key past the actor key.

Rules and reports
=================

1. Give rule publish a board plus metadata field 1 as rule name text.
2. Give rule revoke and punishment revoke an event target only: empty board plus empty article IDs.
3. Give a report metadata field 1 as culprit key bytes.
4. Point a report at an article tuple, an event target, or no target at all.

Punishments
===========

1. Give warn, ban, and permaban a board plus empty article and event targets.
2. Give them metadata field 1 as punished key bytes.
3. Give ban metadata field 2 as expiry in i64 form past zero.
4. Keep field 2 past warn and permaban records.
5. Store a body with each punish record.
6. Give punishment ack empty board plus empty targets.
7. Give it metadata field 1 as the punished event ID bytes.
8. Map warn to type 1, ban to type 2, and permaban to type 3 on the wire.

Origin rotation
===============

1. Give origin key rotate empty board plus empty targets.
2. Give it metadata field 1 as new origin key bytes plus field 2 as proof bytes.
3. Prove the move with the rotation proof shape. The validator checks presence.
   The store owns the crypto check before it trusts the move.
