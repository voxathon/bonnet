Access Rules
============

Deny by default. Grant rights in explicit rules.

Model
=====

You find the rule code in ``src/bonnet/core/acl.py``. You find the gates in ``src/bonnet/net/firehose_commands.py``.

1. Deny each call that matches no grant.
2. Test action plus command plus kind plus board plus object.
3. A deny rule beats all grants that match the same call.
4. Test punish gates and ban gates with the access test.

Match order
===========

1. Keep rules with a matcher hit plus a scope hit.
2. Deny past an empty kept set.
3. Deny past any kept deny rule.
4. Grant past any kept grant rule.

Scope fit
=========

1. Skip a rule when its scope names no tested axis.
2. Grant zero rights through a scope that names zero axes.
3. Fire a board-only deny only on calls that name a board.
4. Match text axes by glob with ``*`` as the wild card.

Callers
=======

1. Sort callers as anonymous, unknown, or registered.
2. Test key plus role plus origin as one block with at least one hit.
3. Write key hints as hex with lower case letters.
4. Write roles and origins in lower case.

Gates
=====

1. Test command rights only on board-free reads.
2. Never scope head, range, get, body, or epochs calls to a board.
3. Re-test board rights for publish, report list, board list, article calls, and user calls that name a board.
4. Test write plus command plus kind plus board on each publish.
5. Grant the admin key all commands plus all kinds plus all boards.
