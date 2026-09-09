==============================
Bonnet Protocol Specification
==============================

Build the encoder first. Read ``primitives`` before you write code.

Scope
=====

This spec defines the bytes that peers exchange. Two peers interoperate when both produce and accept the same bytes. Parts I and II are strict. A peer MUST match them byte for byte. Part III defines record kinds and the access control list. Projections in Part III are local and informative.

Conformance
===========

Read the key words as RFC 2119 defines them. MUST states a strict rule. MUST NOT states a strict ban. SHOULD states a favored way. A peer stays conformant when it uses another sound way. MAY states a choice with no penalty. Lowercase uses carry no force.

The spec uses MUST for wire rules. It uses SHOULD for sync conduct. It uses MAY for local policy. It never uses SHALL.

Terms
=====

UNTP is the substrate. You implement UNTP when you write the log rules and the sync rules. An origin is one named log. A record is one signed entry in the log. A witness is a signed receipt for a record. The encoder is the sender side. The decoder is the receiver side. The access control list (ACL) is the rule set for keys and commands.

Notation
========

Encode all multi-byte integers with the most significant byte first. Read tables in wire order. Count offsets in bytes from zero. Encode hex text with lower case letters. You find the code in ``src/bonnet/core/record.py`` and ``src/bonnet/net/firehose_wire.py``. Obey this spec when words and code disagree. File a bug when you find a gap.

Document map
============

Part I: the signed log

- primitives: integer and text encodings
- core-tags: domain tags plus keys plus hashes
- metadata: metadata map shapes
- intent: actor intent fields
- record: origin record fields
- head-witness: heads plus witnesses plus rotation proofs
- chains: chain links plus forks plus batches

Part II: the log on the wire

- discovery-auth: manifest plus request signing
- framing: status bytes plus opcodes plus error codes
- opcodes-a: substrate calls
- opcodes-b: board calls
- sync: fetch order plus commit order plus backoff

Part III: the board on top

- kinds: record kinds plus field rules
- acl: access tests plus gates
- projections: view shapes plus row shapes

Add a ``toctree`` here when you add a Sphinx build.

References
==========

- RFC 2119: key words for rules
- RFC 8032: Edwards signatures
- RFC 9421: HTTP message signatures
- UAX15: Unicode normal forms
- UTS46: Unicode host names
