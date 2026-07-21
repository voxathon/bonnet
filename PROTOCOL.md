# Bonnet Firehose Protocol

Status: normative design specification

Protocol identifier: `bonnet-firehose-1`

This document is the sole normative reference for the Bonnet protocol and state
model. Historical renovation, Merkle, and article-feed plans describe discarded
designs and MUST NOT be used to resolve ambiguity in this specification.

## 1. Requirements Language

The words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are to be
interpreted as normative requirements.

## 2. Design Goals

Bonnet has one authoritative metadata history per origin. That history is a
linear, append-only, origin-signed firehose containing every published fact:

- article publication;
- article cancellation, restoration, purge, pinning, and replacement;
- board and thread state;
- board and user lifecycle;
- rules, reports, punishments, and revocations;
- future record kinds unknown to older implementations.

The firehose is optimized for append, verification, replay, and federation. It
is not the normal query database. Ordinary reads use bounded, rebuildable
projections, including one SQLite metadata database per board.

Bodies are external files. Article bodies are stored as flat files under their
board so body search can be bounded to one board and performed with ripgrep.
Non-article event bodies are stored in a flat origin event-body directory.

The protocol deliberately does not provide:

- consensus;
- relay voting or quorum;
- accumulated relay receipts or embedded route paths;
- network-level anonymity;
- migration from historical Bonnet formats;
- filtered firehose synchronization;
- cross-board body deduplication;
- automatic body cache eviction.

## 3. Terminology

**Origin**: The cryptographic authority that accepts a record, assigns its
origin sequence and origin time, and appends it to an origin-global chain.

**Record**: One immutable origin-signed firehose entry.

**Intent**: The actor-signed portion submitted to an origin before origin
sequence, article number, and origin time have been allocated.

**Event ID**: A non-zero random 32-byte identifier selected by the actor. The
origin selects it for origin-generated events. It identifies a record but is
not the record's chain hash.

**Article ID**: A non-zero random 32-byte identifier selected by an article
author. It remains distinct from the publication event ID.

**Article number**: A positive integer assigned by an origin and scoped to one
`(origin, board)` pair. Only article publication consumes an article number.

**Event hash**: The domain-separated hash of the complete origin-signed record.
The next record commits to this hash.

**Kind**: A namespaced ASCII string describing record semantics, such as
`bonnet.article` or `bonnet.article.cancel`.

**Projection**: Disposable query state derived from accepted records.

**Relay witness**: A serving relay's signed statement identifying the event,
the relay itself, its immediate upstream, and the time the relay first saw the
event.

**Hostname**: A transport-level DNS name or IP literal used to dial a relay.
It is not a substitute for the relay public key.

## 4. Cryptographic Primitives

Version 1 uses:

- Ed25519 signatures;
- SHA-256 hashes;
- 32-byte Ed25519 public keys;
- 64-byte Ed25519 signatures;
- 32-byte event IDs, article IDs, body hashes, and event hashes.

All signature and hash domains include the terminating NUL byte shown below:

```text
bonnet-body-1\0
bonnet-intent-signature-1\0
bonnet-origin-signature-1\0
bonnet-event-hash-1\0
bonnet-head-signature-1\0
bonnet-head-hash-1\0
bonnet-relay-witness-signature-1\0
```

Concatenation is written as `||`.

```text
body_hash = SHA256("bonnet-body-1\0" || body_bytes)

actor_signature = Ed25519.Sign(
    actor_private_key,
    "bonnet-intent-signature-1\0" || encoded_intent
)

origin_signature = Ed25519.Sign(
    origin_private_key,
    "bonnet-origin-signature-1\0" || encoded_unsigned_record
)

event_hash = SHA256(
    "bonnet-event-hash-1\0" || encoded_origin_record
)
```

An empty body has size zero and the domain-separated hash of zero body bytes.
Zero is not a valid body hash.

## 5. Primitive Encodings

All integers are big-endian. Decoders MUST reject truncated input, trailing
input, non-canonical encodings, and lengths exceeding the limits below before
allocating the declared amount of memory.

| Name | Encoding |
|---|---|
| `u8` | unsigned 8-bit integer |
| `u16` | unsigned 16-bit integer |
| `u32` | unsigned 32-bit integer |
| `u64` | unsigned 64-bit integer, limited to `2^63 - 1` by SQLite stores |
| `i64` | signed 64-bit integer |
| `id32` | exactly 32 bytes |
| `key32` | exactly 32 bytes |
| `sig64` | exactly 64 bytes |
| `text16` | `u16 byte_length || UTF-8 bytes` |
| `blob32` | `u32 byte_length || bytes` |

Text MUST be valid UTF-8 and normalized to Unicode NFC before signing. Kind
strings MUST be printable ASCII. Origins and hostnames MUST be normalized using
lowercase IDNA ASCII with no scheme, path, port, or trailing dot.

Protocol maxima:

| Field | Maximum encoded bytes |
|---|---:|
| origin or hostname | 253 |
| board | 255 |
| kind | 128 |
| metadata | 1,048,576 |
| metadata field count | 256 |
| username, subject, tag, option, content type | 4,096 each |
| one event range response | 16,777,216 |

An implementation MAY enforce a lower body-size or request-size limit, but it
MUST advertise or return that limit rather than silently truncating data.

## 6. Canonical Metadata Map

Kind-specific metadata uses one canonical typed map rather than a different
top-level record structure for every kind.

```text
metadata-map = field_count:u16 || field[field_count]

field = field_id:u16 || value_type:u8 || value_length:u32 || value_bytes
```

Fields MUST be ordered by strictly increasing `field_id`. Duplicate IDs are
invalid.

Value types:

| Code | Name | Canonical value |
|---:|---|---|
| `0x01` | BYTES | arbitrary bytes |
| `0x02` | TEXT | NFC UTF-8, without another length prefix |
| `0x03` | U64 | exactly 8 bytes |
| `0x04` | I64 | exactly 8 bytes |
| `0x05` | BOOL | exactly one byte, `0x00` or `0x01` |
| `0x06` | ID_LIST | `count:u16 || count * id32` |
| `0x07` | TEXT_LIST | `count:u16 || count * text16` |

ID lists preserve declared order. Text lists used as sets, including article
tags, MUST be sorted by encoded UTF-8 bytes and contain no duplicates.

Unknown metadata fields MUST be preserved. A reducer MAY ignore an unknown
field only when the kind schema does not declare it required.

## 7. Actor Intent

The actor selects `event_id` for every submitted record and `article_id` for an
article publication. Both values MUST be cryptographically random, 32 bytes,
and non-zero.

Canonical actor intent encoding:

```text
 intent_format:u8 = 1
 event_id:id32
 kind:text16
 schema_version:u16
 origin:text16
 actor_pubkey:key32
 actor_username:text16
 actor_registrar:text16
 board:text16
article_id:id32
target_origin:text16
target_board:text16
target_article_id:id32
target_event_id:id32
metadata:blob32
body_hash:id32
body_size:u64
```

Empty optional IDs are 32 zero bytes. Empty optional text is encoded with a
zero length.

The actor signature covers the exact encoded intent. It does not cover fields
allocated by the origin: `origin_seq`, `previous_event_hash`, `created_at`, or
`article_num`.

An origin MUST reject:

- a zero event ID;
- a reused `(origin, event_id)` whose encoded intent differs;
- a reused article ID for a different article publication;
- an intent whose `actor_pubkey` does not match the authenticated request key;
- an origin different from the receiving origin;
- a body whose bytes do not match the signed size and hash;
- malformed or non-canonical kind metadata.

Resubmitting an already accepted, byte-identical signed intent is idempotent and
MUST return the existing record.

## 8. Origin Record

The origin allocates a sequence, timestamp, and, where applicable, article
number after validating the signed intent.

Canonical unsigned origin record encoding:

```text
 record_format:u8 = 1
 origin:text16
 origin_seq:u64
 previous_event_hash:id32
 event_id:id32
 kind:text16
 schema_version:u16
 created_at:i64
 actor_pubkey:key32
 actor_username:text16
 actor_registrar:text16
 board:text16
article_id:id32
article_num:u64
target_origin:text16
target_board:text16
target_article_id:id32
target_event_id:id32
metadata:blob32
body_hash:id32
body_size:u64
actor_signature:sig64
```

Canonical complete origin record encoding is:

```text
encoded_unsigned_record || origin_signature:sig64
```

`encoded_origin_record` means this complete encoding.

The origin signature covers the complete unsigned record. The event hash covers
the complete record including the origin signature.

Verifiers reconstruct the actor intent from the corresponding record fields,
omitting origin-allocated fields exactly as defined in section 7, and verify the
actor signature over that canonical reconstruction.

### 8.1 Origin Sequence

`origin_seq` starts at 1 and has no gaps. Sequence is scoped to an origin, not a
server database or board. The first record uses a zero `previous_event_hash`.
Every later record uses the event hash of `origin_seq - 1`.

Sequence order, not timestamps, determines record order.

### 8.2 Origin Time

`created_at` is Unix time in whole seconds assigned by the accepting origin. It
is an origin claim and is covered by the origin signature. It is not used to
resolve ordering conflicts.

### 8.3 Article Number

Only `bonnet.article` records have a positive `article_num`. Numbers start at 1
and increase without reuse within `(origin, board)`. Every other kind uses zero.

Article-number allocation and origin-sequence allocation MUST occur in the same
origin event-store transaction. Projection updates need not share that
transaction.

## 9. Origin Head

Each origin publishes a signed head:

```text
head_format:u8 = 1
origin:text16
latest_origin_seq:u64
latest_event_hash:id32
event_count:u64
generated_at:i64
origin_pubkey:key32
origin_signature:sig64
```

The signature covers the fields preceding it with the
`bonnet-head-signature-1` domain. The head hash covers the complete signed head
with the `bonnet-head-hash-1` domain.

An empty origin has sequence and event count zero and a zero latest event hash.
For every non-empty origin, `event_count` MUST equal `latest_origin_seq`.
`origin_pubkey` identifies the key epoch that signed the head. The head hash is
retained with observed heads and is the identity used for head-conflict
evidence.

## 10. Relay Witness

A served record is accompanied by exactly one witness made by the serving
server. A witness names only the immediate upstream. It MUST NOT embed upstream
witnesses or an accumulated route.

Canonical unsigned witness encoding:

```text
witness_format:u8 = 1
event_origin:text16
event_id:id32
event_hash:id32
relay_pubkey:key32
relay_hostname:text16
received_from_pubkey:key32
received_from_hostname:text16
seen_at:i64
```

Canonical complete witness encoding appends `relay_signature:sig64`.

The relay signature covers the unsigned witness with the
`bonnet-relay-witness-signature-1` domain.

### 10.1 Witness Rules

- `relay_pubkey` MUST be the key that signed the witness.
- `event_hash` MUST equal the hash of the accompanied origin record.
- `relay_hostname` MUST be the serving server's advertised dial hostname.
- The HTTP response signer MUST equal `relay_pubkey`.
- `received_from_pubkey` and `received_from_hostname` identify the direct peer
  from which this relay first accepted the record.
- `seen_at` is Unix time in whole seconds on the relay's clock when it first
  accepted the record.
- The first accepted upstream pair and `seen_at` are immutable for that relay's
  stored copy.
- An origin witness uses the origin key and hostname as the relay identity and
  an all-zero upstream key with an empty upstream hostname.
- Witness validity does not make an origin record valid. Origin chain and
  signature validation remain mandatory.

### 10.2 Tracing

To trace a record, a client reads the witness, dials
`received_from_hostname`, verifies that discovery returns
`received_from_pubkey` or proves a valid rotation chain from that historical key
to its current key, and requests the same `(event_origin, event_id)` from that
server. The returned record hash MUST equal the witness `event_hash`. The
returned witness identifies the next hop. A witness with an all-zero upstream
key and empty upstream hostname is an origin witness and terminates tracing.
Tracing also ends at an unreachable peer, a key mismatch, a missing record, or
a contradictory signed claim.

There is no route consensus. A false claim is attributable to the key that
signed the witness.

## 11. Record Kinds

Kind names are protocol identifiers, not presentation tags or function names.
Unknown kinds are valid records when their envelope, actor signature, origin
signature, and chain position are valid. Unknown kinds MUST be stored and
relayed verbatim but MUST NOT alter projections.

A local origin MUST reject publication of a kind or schema version it cannot
validate. A relay importing a valid origin record MUST retain an unknown kind
or unsupported version and omit projection effects.

Initial kinds:

| Kind | Purpose |
|---|---|
| `bonnet.article` | publish an article |
| `bonnet.article.cancel` | hide an article from normal views |
| `bonnet.article.restore` | restore article metadata visibility |
| `bonnet.article.purge` | declare origin body removal |
| `bonnet.article.pin` | pin an article |
| `bonnet.article.unpin` | remove a pin |
| `bonnet.thread.close` | close a thread rooted at an article |
| `bonnet.thread.reopen` | reopen a thread |
| `bonnet.board.create` | create a board |
| `bonnet.board.close` | close a board |
| `bonnet.board.reopen` | reopen a board |
| `bonnet.user.register` | register or update a user identity |
| `bonnet.user.revoke` | revoke a registration |
| `bonnet.rule.publish` | publish a moderation rule |
| `bonnet.rule.revoke` | revoke a rule |
| `bonnet.report` | publish a report |
| `bonnet.punishment.issue` | issue a punishment or warning |
| `bonnet.punishment.revoke` | revoke a punishment |
| `bonnet.origin.key.rotate` | rotate the origin signing key |

All initial kinds use `schema_version = 1`.

## 12. Kind Metadata Schemas

Fields not listed as required are optional. Every ID field has type BYTES and
exactly 32 bytes unless it uses ID_LIST.

### 12.1 `bonnet.article`

Envelope requirements:

- non-empty board;
- non-zero article ID;
- positive origin-assigned article number;
- empty target fields.
- an earlier `bonnet.board.create` for the same `(origin, board)`.

Metadata:

| ID | Type | Name | Required |
|---:|---|---|---|
| 1 | TEXT | subject | yes |
| 2 | TEXT_LIST | tags | no |
| 3 | TEXT_LIST | options | no |
| 4 | TEXT | content type | yes |
| 5 | BYTES | root article ID | no |
| 6 | BYTES | reply-to article ID | no |
| 7 | BYTES | superseded article ID | no |

Root, reply, and superseded IDs are scoped to the record's origin and board.
Superseding publishes a new article and does not mutate the old article.

### 12.2 Article Lifecycle Controls

`bonnet.article.cancel`, `bonnet.article.restore`, and
`bonnet.article.purge` require a complete article target tuple in the envelope.
Their metadata map is empty in schema 1. An optional human-readable reason is
the event body.

A complete article target tuple has non-empty `target_origin` and
`target_board`, a non-zero `target_article_id`, and a zero `target_event_id`.

Only a lifecycle control accepted by the target article's origin may alter the
article projection. A foreign origin's record targeting the article remains
valid firehose data but has no lifecycle effect.

### 12.3 Pins and Thread State

Pin, unpin, close, and reopen require a complete article target tuple. For
thread controls, the target MUST be a root article.

`bonnet.article.pin` metadata:

| ID | Type | Name | Required |
|---:|---|---|---|
| 1 | I64 | priority | yes |

Other schema-1 pin and thread controls use an empty metadata map.

Only pin and thread controls accepted by the target article's origin alter its
projection. Foreign-origin controls remain valid firehose records but have no
projection effect.

### 12.4 Board Lifecycle

Board lifecycle records require a non-empty `board` and empty article targets.

`bonnet.board.create` metadata:

| ID | Type | Name | Required |
|---:|---|---|---|
| 1 | BYTES | owner public key | yes |
| 2 | TEXT | display name | no |

Close and reopen use an empty metadata map. Board creation is authoritative in
the firehose; `nav.db` is only a projection.

### 12.5 User Lifecycle

User records use an empty board and empty article targets.

`bonnet.user.register` metadata:

| ID | Type | Name | Required |
|---:|---|---|---|
| 1 | TEXT | username | yes |
| 2 | BYTES | user public key | yes |
| 3 | U64 | flags | yes |

Flag bit `0x01` denotes administrator and `0x02` denotes moderator. All other
bits are reserved and MUST be zero in schema 1. Flags never create implicit ACL
grants.

`bonnet.user.revoke` includes the revoked user public key as field 1. It uses an
event target: non-empty `target_origin`, non-zero `target_event_id`, empty
`target_board`, and zero `target_article_id`.

| ID | Type | Name | Required |
|---:|---|---|---|
| 1 | BYTES | revoked user public key | yes |

### 12.6 Rules

`bonnet.rule.publish` metadata:

| ID | Type | Name | Required |
|---:|---|---|---|
| 1 | TEXT | rule name | yes |

The rule text is the body. `bonnet.rule.revoke` targets the rule event and has
an empty metadata map. It uses an event target: non-empty `target_origin`,
non-zero `target_event_id`, empty `target_board`, and zero
`target_article_id`.

### 12.7 Reports

The report body contains human-readable evidence or explanation.

| ID | Type | Name | Required |
|---:|---|---|---|
| 1 | BYTES | culprit public key | yes |
| 2 | ID_LIST | cited rule event IDs | no |
| 3 | ID_LIST | evidence hashes | no |

A report MAY target an article or event through the envelope target fields. It
MUST use either the complete article target tuple defined in 12.2 or an event
target consisting of non-empty `target_origin`, non-zero `target_event_id`,
empty `target_board`, and zero `target_article_id`. It MUST NOT use both.
Evidence hashes are domain-separated `bonnet-body-1` SHA-256 hashes of evidence
bytes. Evidence transfer is outside this protocol version.

### 12.8 Punishments

`bonnet.punishment.issue` metadata:

| ID | Type | Name | Required |
|---:|---|---|---|
| 1 | BYTES | punished public key | yes |
| 2 | I64 | expiration | yes |
| 3 | ID_LIST | cited report event IDs | no |
| 4 | ID_LIST | cited rule event IDs | no |

Expiration zero is a warning, a negative value is permanent, and a positive
value is an absolute Unix timestamp. The body contains the reason.

`bonnet.punishment.revoke` targets the punishment event and uses an empty
metadata map. It uses an event target: non-empty `target_origin`, non-zero
`target_event_id`, empty `target_board`, and zero `target_article_id`.

### 12.9 Origin Key Rotation

`bonnet.origin.key.rotate` uses an empty board, empty article fields, and empty
targets. Its actor public key MUST equal the origin key valid for the previous
record.

| ID | Type | Name | Required |
|---:|---|---|---|
| 1 | BYTES | new origin public key | yes |
| 2 | BYTES | new-key proof signature | yes |

The new-key proof is an Ed25519 signature by the new key over:

```text
"bonnet-new-origin-key-proof-1\0" ||
origin:text16 || old_pubkey:key32 || new_pubkey:key32
```

The rotation record is signed by the old origin key. If it has origin sequence
`N`, the new key becomes valid at sequence `N + 1`. Rotation does not change the
origin string or reset the chain.

## 13. State Reduction

The firehose is authoritative. Projection writes are idempotent consequences
of accepted records.

### 13.1 Dispatcher

Each origin has a projection checkpoint. A dispatcher processes records in
origin sequence order and routes them using envelope fields:

- article publication to `(origin, board)`;
- article, thread, and pin controls to `(target_origin, target_board)`;
- board lifecycle to the board directory projection;
- user lifecycle to the user projection;
- rules, reports, and punishments to the policy projection.

The origin-level checkpoint in `events.db` is authoritative for dispatch
resumption. Per-projection checkpoints track the last sequence applied to that
projection and MUST NOT exceed the origin-level checkpoint. The dispatcher
advances the origin-level checkpoint only after every applicable projection has
accepted the record. Projection databases MUST record applied event IDs so
replay after a crash is harmless.

All dispatchers writing one projection database MUST use one serialized writer
or an explicit shared lock. Cross-origin projection state is a deterministic
set keyed by origin and event ID; display ordering uses `(origin, origin_seq)`
unless a projection defines another signed ordering key.

### 13.2 Article State

Article projection has independent visibility and body state.

```text
visibility = active | cancelled | superseded
body_state = available | unavailable | purged
pin_state = unpinned | pinned(priority)
thread_state = open | closed
```

Initial visibility is active. Initial body state is available when verified
local bytes exist and unavailable otherwise. Initial pin state is unpinned and
initial thread state is open.

- CANCEL changes active visibility to cancelled.
- RESTORE changes cancelled visibility to active.
- A superseding article changes the old article to superseded and identifies
  the replacement. Superseded visibility is terminal.
- PURGE changes body state to purged. Purged body state is terminal.
- PIN changes pin state to pinned with the signed priority.
- UNPIN changes pin state to unpinned.
- THREAD_CLOSE changes thread state to closed.
- THREAD_REOPEN changes thread state to open.

PURGE may apply to an article in any visibility state. CANCEL and RESTORE may
change visibility after purge, but they never change purged body state. A
control whose transition already holds or cannot apply is an idempotent no-op
recorded in `applied_events`.

Applicable controls are reduced in origin sequence order. Timestamps do not
override sequence order.

### 13.3 Unknown Targets

A cryptographically valid and locally applicable control MUST NOT be rejected
merely because its target is absent from a local projection. It is retained in
a pending-control index keyed by the complete target tuple. When the target
appears, pending controls are replayed in origin sequence order. Foreign-origin
controls that cannot affect the target are recorded as applied no-ops and MUST
NOT enter the pending index.

A target board database is created on first dispatch to that board, even when
the first dispatched record is a pending control rather than board creation or
article publication.

### 13.4 Moderation Policy

Accepting a rule, report, or punishment into the firehose does not imply local
enforcement. Local policy selects trusted origins and applied kinds. A
punishment is effective only when local policy enables it and it is not a
warning, expired, or revoked.

## 14. Storage Model

The paths below are normative for the reference implementation:

```text
data/events.db
data/nav.db
data/users.db
data/policy.db

events/<origin>/bodies/<event-id-hex>

boards/<origin>/<board>/metadata.db
boards/<origin>/<board>/bodies/<article-num>
```

Path components derived from origins and boards MUST use a reversible safe
encoding. The reference implementation uses lowercase hexadecimal encoding of
the normalized UTF-8 bytes. Silently deleting unsupported characters is
forbidden.

Article body filenames are unsigned decimal article numbers with no leading
zeroes. Event body filenames are lowercase hexadecimal event IDs.

### 14.1 Event Store

`events.db` stores all accepted origins but maintains a separate chain and head
for each origin. Its required logical tables are:

```text
events
origin_heads
board_counters
relay_witnesses
event_conflicts
projection_checkpoints
```

The events table MUST have unique constraints for `(origin, origin_seq)` and
`(origin, event_id)`. Article records additionally require a partial unique
constraint on `(origin, board, article_id)` where article ID is non-zero. It
SHOULD extract routing and lookup fields while also retaining the exact encoded
origin record.

When `(origin, origin_seq)` already exists with a different event hash, the new
record is inserted into `event_conflicts`, not `events`. Conflict storage keeps
the encoded candidate, event hash, source, observation time, and reason. A
conflict candidate never advances a head or projection checkpoint.

The local origin appends with `BEGIN IMMEDIATE` and a single writer. Imported
ranges MAY be committed in batches. WAL mode is REQUIRED by the reference
implementation.

### 14.2 Board Projection

Each board metadata database contains at least:

```text
articles
pending_controls
applied_events
projection_checkpoint
```

The articles projection is keyed by article number and uniquely indexed by
article ID. It contains publish metadata, author key, origin time, body hash and
size, local body availability, lifecycle state, replacement, pin state, and
thread state.

Normal article get, list, and metadata search operations MUST use only this
bounded database.

### 14.3 Bodies

`bonnet.article` bodies are stored under the target board. Every other kind's
body is stored under `events/<origin>/bodies/<event-id-hex>`. Both use the same
temporary-write, verification, atomic-rename, corruption, and availability
rules.

For local article publication, the verified body is first staged under its
event ID because the article number has not yet been allocated. After the
firehose transaction allocates the article number and commits the record, the
staged file is atomically moved to its decimal article-number path. Recovery
uses the durable event-ID-to-article-number mapping to finish an interrupted
move. A durable record MUST never describe unverified local bytes as present.

Body writes use a temporary file in the target directory, verify size and hash,
and atomically rename into place. Body reads recheck size and hash before
serving. Corrupt or missing bytes are marked unavailable.

Remote metadata acceptance does not require body download.

On a remote body request, a server MAY fetch from an origin or relay, verify the
signed hash and size, and cache the bytes using the same write procedure. It
MUST NOT proxy or cache bytes that fail verification.

A PURGE record is committed before deleting local article bytes. The origin
MUST remove or mark unavailable its own body after applying purge. Independent
relays MAY retain bytes according to local archive policy but MUST expose the
projected purge state.

### 14.4 Global Projections

`nav.db` contains board lifecycle state keyed by `(origin, board)`. `users.db`
contains current and revoked registrations keyed by `(origin, user_pubkey)` and
username indexes. `policy.db` contains rules, reports, punishments,
revocations, and effective-policy indexes keyed by origin and event ID.

Each global projection database contains applied event IDs and per-origin
checkpoints. Their exact denormalized query indexes are implementation details;
origin records, signatures, and bodies MUST NOT become authoritative there.

## 15. Search

Metadata search queries one board's `metadata.db`. Body search runs ripgrep only
against that board's flat `bodies/` directory.

Metadata and body search MUST enforce bounded time and result counts. A search
that reaches a bound reports truncation.

The canonical body-search flow is:

1. apply identity rate and concurrency limits;
2. invoke ripgrep with a bounded timeout, match count, and result count;
3. parse each matching filename as an article number;
4. batch hydrate matching article rows from `metadata.db`;
5. apply projected visibility and body-state flags, excluding purged articles
   regardless of whether stale bytes remain on disk;
6. return metadata, body availability, and excerpts.

Search MUST NOT scan event bodies or another board unless explicitly requested
by a separate future command. Missing remote bodies make body search incomplete
and MUST NOT be reported as a complete negative result.

## 16. ACL Model

Authorization is explicit, compositional, and default-deny. There are no
implicit administrator, moderator, owner, origin, or root bypasses.

Applicable dimensions are:

- command;
- record kind for publication;
- board for board-scoped operations;
- object class for projection and body reads.

For each applicable dimension:

1. collect rules matching the authenticated principal and requested action;
2. if any matching explicit deny covers the selector, deny;
3. otherwise require at least one matching allow covering the selector;
4. no match means deny.

Every applicable dimension MUST pass. Business invariants and effective-ban
checks are additional conjunctive gates.

Roles and board ownership MAY be ACL matcher attributes, but they grant nothing
without explicit allow rules. The generated operator configuration SHOULD
include explicit full grants for the initial local administrator key.

The reference TOML represents rules as `[[acl]]` entries with `effect` equal to
`allow` or `deny`, a `match` table, actions, and selector lists:

```toml
[[acl]]
effect = "allow"
match.role = "administrator"
actions = ["read", "write"]
commands = ["*"]
kinds = ["*"]
boards = ["*"]
objects = ["*"]
```

Supported principal matchers are public key, role, local origin, anonymous,
unknown, and wildcard. A selector list omitted from a rule does not grant that
dimension. `"*"` explicitly covers every selector in that dimension. Multiple
rules may contribute allows to different dimensions; a matching deny in any
applicable dimension rejects the request.

Record import acceptance and local semantic application are separate. A node
MAY store and relay a valid punishment that it does not enforce.

## 17. Firehose Synchronization

Synchronization transfers every metadata record for a subscribed origin.
There is no board or kind filtering in this protocol version.

### 17.1 Acceptance

A receiver MUST:

1. normalize and match the requested origin;
2. verify the signed origin head against the pinned origin key;
3. verify head event count equals latest origin sequence;
4. reject rollback below its highest accepted origin sequence;
5. treat equal sequence and equal hash as idempotent;
6. retain equal sequence and different hash as equivocation evidence;
7. request the contiguous missing range for a higher head;
8. verify every origin sequence and previous-event-hash link;
9. verify every actor signature and origin signature using the key epoch valid
   for that sequence;
10. validate canonical envelope and metadata-map encoding;
11. reject reuse of an event ID, article ID, or article number for conflicting
   content;
12. accept unknown kinds and unsupported versions of known kinds without
   applying them;
13. verify the final event hash equals the signed head and retain the observed
   head hash;
14. commit the complete accepted range atomically or stage it until complete.

Importing a record does not import its body.

### 17.2 Relay Witness Handling

The response witness MUST identify the directly contacted server. The receiver
verifies that witness but stores its own newly signed witness with the contacted
server as immediate upstream and local acceptance time as `seen_at`.

A relay MUST NOT copy the upstream witness as its own or append it to a path.

### 17.3 Dial Safety

Federation dials MUST retain SSRF protections: reject invalid host syntax and
any hostname resolving to loopback, private, link-local, multicast, reserved,
or otherwise non-global addresses unless explicit development configuration
allows it.

## 18. HTTP Discovery

`GET /.well-known/bonnet` returns signed JSON containing:

```json
{
  "protocol": "bonnet-firehose-1",
  "origin": "bbs.example",
  "hostname": "bbs.example",
  "public_key": "<64 lowercase hex characters>",
  "anonymous_key": "<64 lowercase hex characters>",
  "anonymous_private_key": "<64 lowercase hex characters>",
  "command_endpoint": "/command",
  "capabilities": [
    "global-firehose",
    "generic-record-kinds",
    "relay-hop-witness",
    "per-board-body-search"
  ]
}
```

The anonymous private key is intentionally public and provides attributable
shared anonymous read access. It is not a confidentiality mechanism.

Discovery is a signed HTTP response under the profile in section 19. Its
Content-Digest binds the exact JSON bytes. The hostname/public-key pair is used
for TOFU and relay tracing.

## 19. Command Transport

Commands use RFC 9421 HTTP Message Signatures with Ed25519 and RFC 9530
Content-Digest using SHA-256. Request content type is
`application/vnd.bonnet.command`. The `Bonnet-Protocol` header is
`bonnet-firehose-1`.

Signed command requests MUST cover:

```text
@method
@authority
@target-uri
content-type
content-digest
bonnet-protocol
bonnet-nonce
```

Signed responses MUST cover:

```text
@status
content-type
content-digest
bonnet-protocol
bonnet-origin
bonnet-request-nonce
```

The signature label is `bonnet`, algorithm parameter is `ed25519`, tag is
`bonnet-firehose-1`, and key ID is `ed25519:` followed by the lowercase hex
public key. Request signatures require `created`, `expires`, and `nonce`
parameters. Lifetime MUST NOT exceed 60 seconds; clock skew allowance is 30
seconds. The nonce is unpadded base64url encoding of 32 random bytes and MUST
equal `Bonnet-Nonce`. Servers persist accepted `(public_key, nonce)` pairs until
expiry and reject replay. Responses echo the request nonce in
`Bonnet-Request-Nonce`. Discovery responses use an empty request nonce.

Request body begins with one opcode byte followed by the command payload.

Responses begin with:

```text
status:u8
```

Status zero is success followed by command-specific payload. Status one is:

```text
status:u8 = 1 || error_code:u16 || message:text16
```

Initial commands:

| Opcode | Name | Action |
|---:|---|---|
| `0x01` | `PUBLISH_RECORD` | write |
| `0x02` | `EVENT_HEAD` | read |
| `0x03` | `EVENT_RANGE` | read |
| `0x04` | `EVENT_GET` | read |
| `0x10` | `BOARD_LIST` | read |
| `0x11` | `ARTICLE_GET` | read |
| `0x12` | `ARTICLE_LIST` | read |
| `0x13` | `ARTICLE_SEARCH` | read |
| `0x14` | `ARTICLE_BODY` | read |
| `0x20` | `USER_GET` | read |
| `0x21` | `USER_LIST` | read |
| `0x22` | `BAN_STATUS` | read |
| `0x30` | `EVENT_BODY` | read |

Board and user creation are `PUBLISH_RECORD` operations, not separate protocol
primitives.

### 19.1 Publish Record

Request:

```text
intent_length:u32
encoded_intent
actor_signature:sig64
body_length:u32
body_bytes
```

`body_length` MUST equal the intent body size and fit the server request limit.
For metadata-only retry of an already accepted event, a client MAY send zero
body bytes only when the origin already has and verifies the referenced body.

Success:

```text
record_length:u32
encoded_origin_record
witness_length:u16
encoded_relay_witness
```

### 19.2 Event Head

Request: `origin:text16`.

Success: `head_length:u16 || encoded_origin_head`.

### 19.3 Event Range

Request:

```text
origin:text16
start_origin_seq:u64
max_count:u16
max_bytes:u32
```

Success:

```text
count:u16
repeated count times:
    record_length:u32
    encoded_origin_record
    witness_length:u16
    encoded_relay_witness
```

Records MUST be contiguous and ascending. The response stops before exceeding
either requested limit or the protocol response maximum.

### 19.4 Event Get

Request: `origin:text16 || event_id:id32`.

Success has the same one-record payload as publish success. Clients use this
command recursively for relay tracing.

### 19.5 Projection Commands

Projection commands are convenience reads and never replace firehose
verification.

Article selectors are:

```text
selector_type:u8
0x01 -> article_num:u64
0x02 -> article_id:id32
```

`ARTICLE_GET` supplies origin, board, selector, and an include-body flag.
`ARTICLE_LIST` supplies origin, board, offset, limit, and state flags.
`ARTICLE_SEARCH` supplies origin, board, metadata query, optional body query,
offset, limit, and state flags. `ARTICLE_BODY` supplies an article reference.
`EVENT_BODY` supplies origin and event ID.

Exact projection response models are derived API views. They MUST include the
origin record identity, article ID and number, projected state, body hash and
size, body availability, and latest applicable control IDs.

## 20. Key Rotation

Origin rotation is the `bonnet.origin.key.rotate` record defined in 12.9. It is
not a side-channel command. A receiver that accepts rotation at sequence `N`
stores an epoch ending the old key at `N` and beginning the new key at `N + 1`.
Historical records remain verified against the epoch covering their sequence.

Heads include their signing public key. A head key is valid only when it equals
the key in the receiver's epoch map for the head sequence.

Discovery may expose a new current key before a peer has synchronized the
rotation record. A peer with an older pin enters rotation-recovery mode: it may
fetch only EVENT_RANGE bytes beginning at its last verified sequence, defer
trust in the HTTP response, verify the origin chain through the old-key-signed
rotation record, verify the new-key proof, and then verify subsequent records,
the response signature, discovery, and head with the new key. Failure at any
step leaves the old pin unchanged and discards the response.

The trust store MUST retain key epochs. It MUST NOT overwrite the only copy of
an old key. Relay witnesses carry their signer public key directly and remain
cryptographically verifiable after rotation.

## 21. Failure and Recovery

### 21.1 Event Commit Before Projection

An origin may crash after committing a record but before updating projections.
On restart, the dispatcher resumes from its checkpoint and applies the durable
record. Publication success is defined by durable firehose acceptance, not by
projection completion.

### 21.2 Projection Commit Before Checkpoint

The dispatcher may replay an already applied record. Applied-event uniqueness
and idempotent reducers MUST make replay harmless.

### 21.3 Body Before Event

A failed publication may leave an unreferenced body file. Orphan cleanup is
permitted but is not required for protocol correctness.

### 21.4 Purge Failure

If body deletion fails after purge is committed, the body remains physically
present but MUST NOT be served by the origin. Deletion is retried.

### 21.5 Equivocation

Conflicting records at one `(origin, origin_seq)` or conflicting signed heads
at the same sequence are retained as evidence and MUST stop automatic
advancement for that origin until operator policy resolves the conflict.

If a projection applied a record before its conflict was observed, affected
projection rows are marked conflicted and excluded from normal reads. Operator
resolution selects a branch, after which affected projections are rebuilt from
the selected chain.

## 22. Required Conformance Tests

An implementation is not conformant without tests for:

- canonical intent, record, head, metadata, and witness encoding;
- fixed signature and hash vectors;
- event and article ID collision handling;
- idempotent publication retry;
- origin sequence allocation under concurrency;
- rollback and equivocation rejection;
- unknown-kind storage and relay;
- witness key, hostname, signature, and immediate-hop validation;
- recursive tracing and deliberate lying-relay attribution;
- crash between firehose and projection commits;
- exact metadata and semantic projection rebuild after deleting every
  projection database; local body availability is re-derived from current
  files and is not part of replay equality;
- controls received before their targets;
- cancel, restore, supersede, and purge ordering;
- body corruption detection and purge retry;
- real body-text search through per-board flat files;
- compositional ACL grants and deny precedence;
- complete firehose synchronization through multiple relays;
- SSRF protections on every dial path.

Golden binary vectors MUST be generated and reviewed before database or network
implementation begins. The vector generator is a development tool, not an
alternative encoding specification.

## 23. Implementation Boundary

The rework is complete when:

- this record format is the only authoritative metadata model;
- there is one firehose implementation and no per-board authoritative chain;
- normal board queries use bounded per-board databases;
- body search searches article body text;
- deleting projections and replaying the firehose reproduces metadata and
  semantic state exactly, while body availability reflects current files;
- relay tracing works with one signed immediate-hop witness per server;
- clients and servers expose no historical feed commands or compatibility
  adapters;
- configuration contains no implicit authorization bypass;
- tests and operator documentation refer only to this protocol.

The implementation MUST stop at that boundary. Migration, consensus, relay
quorum, accumulated paths, filtered synchronization, body deduplication,
automatic cache eviction, and unrelated moderation features are separate future
decisions and MUST NOT be added as part of this rework.

## 24. Reference Implementation Sequence

Implementation proceeds in this order. A later phase MUST NOT be used to defer
an unresolved invariant from an earlier phase.

### Phase 0: Freeze Bytes

- Implement a standalone canonical encoder and decoder for metadata, intent,
  origin record, head, and witness.
- Generate fixed binary, hash, and signature vectors.
- Review vectors independently before adding SQLite or network code.

### Phase 1: Firehose Core

- Implement the event store, per-origin sequence allocation, board counters,
  heads, conflicts, key epochs, and range acceptance.
- Test concurrency, rollback, equivocation, collision, retry, and rotation.

### Phase 2: Bodies and Projections

- Implement staged article bodies, flat event bodies, integrity checks, and
  body availability.
- Implement board, navigation, user, and policy projections.
- Implement idempotent dispatch, pending controls, crash replay, and full
  projection rebuild.

### Phase 3: Search and Authorization

- Restore per-board ripgrep body search.
- Replace ACL buckets and implicit bypasses with compositional evaluation.
- Implement kind-specific validation and business rules.

### Phase 4: Server and Federation

- Replace command handlers and discovery.
- Implement global head/range synchronization, signed hop witnesses, tracing,
  rotation recovery, and body retrieval.

### Phase 5: Client Surface

- Replace protocol builders, parsers, models, high-level client methods, tools,
  and local operator commands.

### Phase 6: Removal

- Remove every old feed, mutable-post, global-CAS, compatibility, and dead
  configuration path.
- Replace historical tests rather than adapting the new implementation to pass
  obsolete behavior.
- Update README and operator documentation to point only to this document.

## 25. Current Code Cutover Map

The following map guides replacement of the repository as it exists when this
specification was written.

### Retain and Adapt

- `src/core/crypto.py`: Ed25519 primitives.
- `src/core/trust.py`: TOFU storage, rewritten to retain origin key epochs.
- `src/net/http_auth.py`: RFC 9421 and RFC 9530 implementation, updated to the
  firehose header and tag profile.
- `src/net/replay.py`: persistent nonce replay protection.
- `src/net/rate_limiter.py` and `src/net/search_limiter.py`.
- TLS and ASGI plumbing in `src/net/http_server.py`.

### Replace

- `src/core/article_feed.py`: split into canonical record codec, event store,
  relay witness, board projection, and body storage responsibilities.
- `src/engine/ame.py`: remove mutable posts while retaining board projection
  and bounded file-search responsibilities.
- `src/engine/article_service.py` and `src/engine/moderation_service.py`.
- `src/engine/facade.py` authorization integration.
- `src/net/commands.py` and `src/net/sync.py`.
- Discovery construction in `src/net/http_server.py`.
- `src/client/protocol.py`, `src/client/http.py`, `src/client/models.py`,
  `src/client/simple.py`, and `src/client/tools.py`.
- Application wiring in `src/app/server.py`.
- `src/core/config.py` ACL, firehose subscription, storage, and sync sections.

### Remove at Completion

- The mutable per-board `posts` table and update/delete post APIs.
- Per-board authoritative feed sequences and heads.
- The global content-addressed article body store.
- Fixed numeric event-type dispatch as the semantic extension mechanism.
- Dedicated moderation-board discovery and per-board feed subscriptions.
- Implicit administrator, moderator, and owner authorization bypasses.
- Historical protocol compatibility branches and migration adapters.
- Historical implementation plans as normative documentation.
