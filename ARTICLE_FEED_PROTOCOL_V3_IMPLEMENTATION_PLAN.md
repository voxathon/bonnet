# Immutable Article Feeds and Control Messages: Protocol v3 Implementation Plan

## 1. Purpose

This document is an implementation handoff for replacing Bonnet's mutable post
model and its separate report/punishment federation systems with one immutable,
origin-signed article feed protocol.

The target implementer is another engineering agent. Treat the product and
protocol decisions in this document as frozen unless they are impossible to
implement or directly contradict the current code. If that happens, stop and
document the contradiction before inventing an alternative architecture.

The redesign has four primary goals:

1. Make every board an append-only, peerable stream of signed metadata events.
2. Make article bodies content-addressed and fetchable independently of metadata.
3. Represent edits, cancellations, moderation, reports, punishments, rules, and
   revocations as typed immutable events rather than mutable rows or separate
   object registries.
4. Remove the report and punishment Merkle registries, their protocol commands,
   their synchronization paths, and their duplicate persistence machinery.

This is intentionally a protocol-v3 cutover. Do not preserve protocol-v2 opcode
semantics behind compatibility branches. Persisted user content, moderation
history, identities, and trust pins require migration; old network clients do
not require transparent compatibility.

## 2. Executive Summary

Bonnet currently has three different federation models:

- Board metadata is origin-signed and copied through relays.
- Posts are mutable, stored only on their origin, and accessed through redirects.
- Users, reports, and punishments are copied through separate Merkle registries.

Protocol v3 replaces the post/report/punishment split with one board feed model:

```text
board feed
  event 1: article
  event 2: article
  event 3: cancel event targeting event/article 1
  event 4: report event targeting article 2
  event 5: punishment event targeting a public key
  event 6: punishment-revoke event targeting event 5
```

Each feed belongs to one `(origin, board)` pair. Each event has a monotonically
increasing feed sequence, commits to the previous event hash, carries a stable
message ID, and is countersigned by the board origin. User-authored events also
carry a durable author signature. Relays copy the exact signed event bytes.

Synchronization is metadata-first:

1. Fetch the signed feed head.
2. Fetch a contiguous event range after the receiver's accepted sequence.
3. Verify sequence continuity, previous-hash linkage, event hashes, and origin
   signatures.
4. Commit the complete range atomically.
5. Fetch bodies lazily by content hash.

There is no article Merkle tree. A linear signed hash chain is sufficient for
ordered board streams and avoids reproducing the complexity being removed.
The user identity registry remains Merkle-based and is not redesigned here.

Cancellation changes the projected visibility of an article; it does not erase
the article or its body. Normal lists and searches omit canceled articles by
default. Direct retrieval by stable message ID or `(origin, board, article_num)`
returns the retained article and its cancellation state. Physical body removal
is a distinct purge event and remains observable in metadata.

## 3. Current Baseline

The implementation agent must inspect the current code before editing it. The
most relevant files are:

- `src/engine/ame.py`: board navigation, mutable posts, body files, search.
- `src/engine/keibatsu.py`: rules, reports, punishments, effective bans.
- `src/core/merkle_registry.py`: generic user/report/punishment registry store.
- `src/core/user_registry.py`: identity registry that remains in v3.
- `src/core/report_registry.py`: remove after migration.
- `src/core/punishment_registry.py`: remove after migration.
- `src/core/commands.py`: canonical opcode and action metadata.
- `src/core/config.py`: command, object, and board ACLs; import allowlists.
- `src/core/trust.py`: TOFU origin pins and key rotation.
- `src/net/commands.py`: command dispatch and all existing handlers.
- `src/net/sync.py`: pull-based federation and relay synchronization.
- `src/net/http_server.py`: protocol discovery and HTTP command transport.
- `src/client/protocol.py`: binary builders and parsers.
- `src/client/http.py`: signed HTTP client.
- `src/client/models.py`, `tools.py`, `resources.py`: public client/MCP surface.
- `src/app/server.py`: storage and registry service wiring.

Important current behavior:

- Board entries are stored in `nav.db` with `origin`, `relay`, an origin
  signature, owner key, and closed flag.
- Each local board has `metadata.db` containing a mutable `posts` table.
- Post bodies are flat files named by `post_num` inside the board directory.
- `POST_UPDATE` overwrites metadata and possibly the body file.
- `POST_DELETE` removes both the row and body file.
- `POST_SIGN` is optional, occurs after creation, and signs a payload that does
  not include the board or origin.
- Post numbers are local to a board.
- Remote post reads/writes redirect to the board origin; posts are not copied.
- Report and punishment history is append-only in Keibatsu tables and is copied
  through separate Merkle registry databases.
- Effective bans are evaluated across all accepted punishment origins and are
  used by the command dispatch write gate.
- Federation is queue-driven rather than periodically scheduled.
- Trust is pinned by origin/peer using `TrustStore`; relays cannot replace
  origin signatures.

## 4. Frozen Product Decisions

### 4.1 Protocol cutover

- This is protocol version 3.
- Discovery advertises `[3]`, not `[2, 3]`, after cutover.
- The command endpoint becomes `/v3/command`.
- There is no automatic v2 fallback.
- Existing binary HTTP framing, RFC 9421 request/response authentication,
  replay protection, TLS rules, and signed discovery remain conceptually
  unchanged except for the protocol version and command table.
- Remove v2-only opcodes after the v3 implementation and migration tests pass.

### 4.2 One federation abstraction for board content

- Every board has an append-only event feed.
- Ordinary articles and control messages share the same event envelope and
  synchronization protocol.
- Each `(origin, board)` feed has independent sequence and hash-chain state.
- There is no aggregate tree across boards or origins.
- A relay stores and exports exact origin-signed events for many origins.
- A relay never republishes a remote event as locally originated.

### 4.3 Immutability and visibility

- Accepted events are immutable.
- Article metadata and body bytes are never changed in place.
- An edit creates a replacement article that supersedes the old article.
- A cancellation is an event referencing an article; it does not delete the
  article or its body.
- Canceled and superseded articles are omitted from normal list/search results.
- Direct retrieval continues to expose retained content and lifecycle status.
- A purge is a separate privileged event declaring physical body removal.
- Purge does not remove the signed article metadata or content hash.
- Independent peers may retain bodies after an origin declares a purge. The
  protocol records the declaration; it cannot force third-party erasure.

### 4.4 Signatures and authority

- Every accepted event is signed by its origin server.
- User-authored events also have a durable author signature over their canonical
  payload before the origin accepts them.
- The origin signature countersigns the complete event, including author
  signature, feed sequence, previous event hash, board, and origin.
- The origin signature means: "this origin accepted this exact event into this
  board at this sequence."
- An author signature proves authorship but does not prove board authorization.
- Relays verify and preserve origin signatures. Their HTTP response signature
  authenticates only the directly contacted relay.
- Downstream peers do not reconstruct historical ACL state. They rely on the
  origin countersignature as proof that the origin authorized publication.

### 4.5 Moderation as typed events

- Reports, rules, punishments, punishment revocations, cancellations, restores,
  and purges are typed events.
- They are not separate Merkle registry records.
- Distinct events have distinct message IDs. There is no rollover field.
- Corrections and conflicts are represented explicitly through references such
  as `supersedes_message_id` or `target_message_id`.
- Punishment expiration is derived from the signed punishment payload.
- A punishment revocation is explicit and does not delete the punishment event.
- Effective bans remain a local materialized policy result, not an intrinsic
  global property of a public key.

### 4.6 Import and enforcement policy

- Import policy is feed-based, keyed by exact origin and board.
- Importing metadata and enforcing controls are separate decisions.
- A server may archive a punishment feed without applying its punishments.
- A server may apply only selected event types from a feed.
- Board export authorization remains independent of import policy.
- Import configuration must never filter what an authorized caller may export.

### 4.7 Merkle scope

- Keep the user identity Merkle registry.
- Delete report and punishment Merkle registry bindings and databases after
  migration.
- Do not add an article Merkle registry.
- Do not extend `MerkleRegistryStore` with board instances.
- Feed continuity uses a linear hash chain plus signed heads.

## 5. Terminology

- **Article:** A user-visible immutable content event.
- **Control event:** A typed immutable event that changes projected state or
  moderation policy without mutating its target.
- **Feed:** The ordered event stream for one `(origin, board)`.
- **Feed sequence:** Origin-assigned contiguous integer beginning at 1.
- **Article number:** Human-friendly per-board number assigned only to article
  events. It remains stable and preserves migrated `post_num` values.
- **Message ID:** Stable globally scoped identifier for one event.
- **Event hash:** Domain-separated hash of the complete encoded signed event.
- **Feed head:** Origin-signed commitment to the latest sequence and event hash.
- **Projection:** Locally derived current state used by list/search/ban queries.
- **Body:** Content bytes committed by `body_hash` and stored separately.
- **Origin:** Cryptographic authority that accepted and sequenced the event.
- **Relay:** Server carrying exact origin-signed metadata or bodies for another
  origin.

## 6. Event Types

Define one-byte event type values:

```text
0x01 ARTICLE
0x02 CANCEL
0x03 RESTORE
0x04 PURGE
0x05 RULE
0x06 RULE_REVOKE
0x07 REPORT
0x08 PUNISHMENT
0x09 PUNISHMENT_REVOKE
0x0A BOARD_CLOSE
0x0B BOARD_REOPEN
0x0C ARTICLE_PIN
0x0D ARTICLE_UNPIN
0x0E THREAD_CLOSE
0x0F THREAD_REOPEN
```

Reserve `0x10-0x1F` for future standardized controls. Reject unknown types on
local publication. Remote synchronization may store unknown future types only
when their envelope version is supported and policy explicitly permits opaque
events; protocol v3 defaults to rejecting them.

### 6.1 ARTICLE

An article event contains:

- `article_num`: per-board positive integer.
- `root_message_id`: zero/empty for a top-level post, otherwise the thread root.
- `reply_to_message_id`: zero/empty or direct parent.
- `supersedes_message_id`: zero/empty or the article this replaces.
- `subject`, `tags`, and `options`.
- Body hash and body size.
- Author identity and signature.

If `supersedes_message_id` is present, the origin must verify that the actor may
edit the target under current author/moderator rules. The replacement receives
a new message ID and article number. The target remains directly retrievable.
The target must belong to the same `(origin, board)` feed.

### 6.2 CANCEL

A cancel event references exactly one article message ID and provides an
optional reason body.

- Authors may request cancellation of their own article.
- Moderators/administrators may cancel according to existing board moderation
  rules.
- The origin validates authorization before countersigning.
- The target must belong to the same `(origin, board)` feed.
- Projection hides the target from default list/search results.
- Direct retrieval returns the target with `cancelled=true` and the applicable
  cancel event IDs.
- A cancel never deletes body bytes.

### 6.3 RESTORE

A restore event references a canceled or superseded article.

- The origin applies current board authorization rules.
- Projection makes the target visible again unless a later applicable control
  event changes its state.
- Restore does not invalidate or delete prior control events.
- Event order determines current state.
- The target must belong to the same `(origin, board)` feed. Cross-origin and
  cross-board restore is invalid.

### 6.4 PURGE

A purge event references an article and includes a reason.

- Only a moderator/administrator or equivalent local privileged principal may
  publish a purge.
- The origin may delete its local body bytes after atomically committing the
  purge event.
- The article envelope, body hash, body size, and purge event remain exportable.
- Receiving peers record the purge declaration but are not required to delete a
  body they already possess.
- Direct retrieval reports body availability separately from projected state.
- The target must belong to the same `(origin, board)` feed.

### 6.5 RULE and RULE_REVOKE

Rules become signed controls on a configured moderation board.

RULE payload:

- Stable rule message ID.
- Human-readable name.
- Description body.
- Optional superseded rule message ID.

RULE_REVOKE references a rule message ID. Reports and punishments reference rule
message IDs rather than receiver-local numeric IDs.

RULE_REVOKE is valid only when it is in the same `(origin, board)` feed as the
target rule. One origin cannot revoke another origin's rule event.

### 6.6 REPORT

REPORT payload:

- Target public key.
- Optional target origin, board, and article message ID.
- Zero or more rule message IDs.
- Reporter public key from the event actor.
- Description/evidence body.
- Optional content hashes for external evidence.

The report event is author-signed and origin-countersigned. A report is an audit
record; importing it does not automatically punish anyone.

### 6.7 PUNISHMENT

PUNISHMENT payload:

- Punished public key.
- Ordered report message IDs.
- Ordered rule message IDs.
- `expires_at`: `0` for warning, `-1` for permanent, positive Unix timestamp for
  temporary punishment.
- Notes body.
- Issuer public key from the event actor.
- `created_at` from the event timestamp.

The board's write ACL and handler-level moderator/administrator check determine
who may publish punishment events. An ACL grant alone must not create a
moderator.

### 6.8 PUNISHMENT_REVOKE

References one punishment message ID and includes a reason. It is authorized
like punishment publication. Effective-ban materialization ignores a punishment
after its latest applicable revocation, but retains both events for audit.
The revocation must be in the same `(origin, board)` feed as its target. A
different feed may publish a contradictory policy statement, but it cannot
rewrite or revoke the original feed's event.

### 6.9 BOARD_CLOSE and BOARD_REOPEN

These controls replace mutable close state for local authoritative boards.
Board navigation may keep a derived `closed` column for efficient reads. A
closed board rejects new article and user-authored control publication, while
privileged reopen/purge operations remain possible.

Board deletion is not a normal feed event in v3. Physical board storage removal
is an operator maintenance action and must retain the signed feed metadata or an
exported archive. Remove network-level destructive `BOARD_DELETE` behavior.

### 6.10 Pin and thread controls

ARTICLE_PIN/ARTICLE_UNPIN reference a top-level article and alter default list
ordering without mutating it. ARTICLE_PIN headers contain a signed `priority:i32`.
THREAD_CLOSE/THREAD_REOPEN reference a thread root and control whether new
replies are accepted. These controls require current moderator/administrator
authority, must target the same feed, and remain fully auditable.

## 7. Canonical Identifiers

### 7.1 Origin and board

- Origin is a canonical ASCII network identity. Add one shared
  `normalize_origin()` helper and use it in config, trust storage, nav storage,
  feed storage, discovery comparison, and protocol parsing.
- DNS origins are IDNA-encoded, lowercased, and stored without a trailing dot.
- IP literals are stored in `ipaddress.ip_address(value).compressed` form,
  without IPv6 brackets.
- Reject whitespace, URL schemes, paths, ports, empty labels, and values that do
  not round-trip through the canonicalizer.
- Migrate existing origin strings and trust pins transactionally. Detect and
  stop on collisions where two stored spellings canonicalize to one origin with
  different keys or records.
- Board is a UTF-8 string with explicit byte-length bounds and retains current
  case-sensitive name semantics.
- Board names retain current validation unless the implementation introduces a
  stricter versioned grammar.
- The tuple `(origin, board)` is the feed identity.

### 7.2 Feed sequence

- `feed_seq` is an unsigned 64-bit integer.
- Sequence starts at 1.
- No gaps are valid in an authoritative feed.
- Allocation and insertion occur in one `BEGIN IMMEDIATE` SQLite transaction or
  under an equivalent per-feed lock.
- Timestamps never establish ordering.

### 7.3 Article number

- `article_num` is an unsigned 64-bit integer scoped to `(origin, board)`.
- Only ARTICLE events allocate article numbers.
- Existing `post_num` values are preserved during migration.
- New allocation uses `MAX(article_num)+1` under the same transaction as the
  event sequence allocation.
- Control events do not consume article numbers.

### 7.4 Message ID

Use a 32-byte value represented externally as lowercase hexadecimal.

For new events, the publishing client generates 32 random bytes before signing.
The origin rejects all-zero IDs and duplicate message IDs. Random IDs let the
author signature bind the final identifier before the origin assigns a sequence.

Message IDs are globally keyed in storage. A duplicate ID with identical event
bytes is idempotent. A duplicate ID with different bytes is rejected and logged
as an attempted collision/equivocation.

Migrated records derive deterministic IDs using domain-separated SHA-256 over
their legacy identity and canonical preserved bytes.

### 7.5 Event hash

```text
event_hash = SHA-256(
    "bonnet-feed-event-hash-v1" || encoded_complete_event
)
```

`encoded_complete_event` includes both signatures. `previous_event_hash` is the
event hash of sequence `feed_seq - 1`, or 32 zero bytes for sequence 1.

## 8. Canonical Event Encoding

Do not use JSON for signed bytes. Define one strict binary encoding and publish
fixed vectors.

Common event fields, in order:

```text
format_version:          u8 = 1
event_type:              u8
origin:                  u16 length + UTF-8
board:                   u16 length + UTF-8
feed_seq:                u64be
previous_event_hash:     32 bytes
message_id:              32 bytes
article_num:             u64be (0 for non-ARTICLE)
created_at:              i64be
actor_pubkey:            32 bytes
actor_username:          u16 length + UTF-8 (may be empty)
actor_registrar:         u16 length + UTF-8 (may be empty)
root_message_id:         32 bytes (zero when absent)
reply_to_message_id:     32 bytes (zero when absent)
supersedes_message_id:   32 bytes (zero when absent)
target_message_id:       32 bytes (zero when absent)
headers:                 u32 length + canonical type-specific bytes
extensions:              u32 length + canonical extension block
body_hash:               32 bytes
body_size:               u64be
author_signature_scheme: u8
author_signature:        u16 length + bytes
origin_signature:        64 bytes
```

Bounds are mandatory:

- Origin: maximum 255 UTF-8 bytes.
- Board: maximum 255 UTF-8 bytes.
- Actor username/registrar: maximum 255 bytes each.
- Headers: maximum 64 KiB.
- Extensions: maximum 256 KiB and empty for all non-migration publication.
- Body size: bounded by a new configurable article-body maximum.
- Signature scheme and length must agree.
- Decoders reject trailing bytes.

### 8.1 Type-specific headers

Use deterministic field order and fixed integer sizes. Do not use maps whose
ordering can differ between implementations.

ARTICLE headers:

```text
subject: u16 UTF-8
tags:    u16 UTF-8
options: u16 UTF-8
```

CANCEL, RESTORE, PURGE, RULE_REVOKE, and PUNISHMENT_REVOKE use
`target_message_id` and may have empty headers. Their human explanation is the
body.

RULE headers:

```text
rule_name: u16 UTF-8
```

REPORT headers:

```text
culprit_pubkey:      32 bytes
target_origin:       u16 UTF-8
target_board:        u16 UTF-8
target_article_id:   32 bytes
rule_count:          u16
rule_message_ids:    32 bytes * count
evidence_hash_count: u16
evidence_hashes:     32 bytes * count
```

PUNISHMENT headers:

```text
punished_pubkey:  32 bytes
expires_at:       i64be
report_count:     u16
report_ids:       32 bytes * count
rule_count:       u16
rule_ids:         32 bytes * count
```

ARTICLE_PIN headers are exactly `priority:i32be`. ARTICLE_UNPIN, THREAD_CLOSE,
and THREAD_REOPEN have empty headers. All four put the referenced top-level
article/thread-root message ID in `target_message_id`; `root_message_id` remains
zero for the control event itself.

### 8.2 Migration extensions

The common `extensions` field is a signed extension block:

```text
extension_count:u16
repeated entries in strictly ascending type order:
  extension_type:u16
  value_len:u32
  value:bytes
```

Duplicate, unknown, out-of-order, or trailing entries are rejected in v3.
Normal network publication must encode exactly `extension_count=0`; only the
trusted local migration path may create non-empty extensions.

Frozen migration extension types:

```text
0x0001 LEGACY_DESCRIPTOR
       source_protocol:u8 + source_object_type:u8 + legacy_identity:u32 bytes
0x0002 LEGACY_AUTHOR_SIGNED_PAYLOAD
       exact historical bytes verified by the migration
0x0003 LEGACY_AUTHOR_SIGNATURE
       exact historical signature bytes/text representation
0x0004 LEGACY_ORIGIN_SIGNED_PAYLOAD
       exact historical origin-signed payload bytes
0x0005 LEGACY_ORIGIN_SIGNATURE
       exact historical origin signature bytes/text representation
0x0006 LEGACY_UNRESOLVED_REFERENCES
       type-specific canonical numeric/string references
```

Legacy source object type values and descriptor identities:

```text
0x01 POST:       legacy_identity = post_num:u64be
0x02 RULE:       legacy_identity = rule_num:u64be
0x03 REPORT:     legacy_identity = report_num:u64be + rollover:u64be
0x04 PUNISHMENT: legacy_identity = punishment_id:u64be + rollover:u64be
```

LEGACY_UNRESOLVED_REFERENCES values are frozen:

```text
source_object_type=REPORT (0x03):
  0x03 + legacy_rule_num:u64be + legacy_culprit_board:u16 UTF-8 +
  legacy_culprit_post_num:u64be

source_object_type=PUNISHMENT (0x04):
  0x04 + legacy_report_count:u16 + legacy_report_nums:(u64be * count)
```

Presence of LEGACY_DESCRIPTOR is the migration flag. These extensions are part
of the complete event and therefore covered by the v3 origin signature and event
hash. They are not covered by a historical author signature unless they were
part of that historical payload.

### 8.3 Body hash

```text
body_hash = SHA-256("bonnet-article-body-v1" || body_bytes)
```

The empty body has a real domain-separated hash; do not represent it with zero
bytes. `body_size` must match the exact received body length.

### 8.4 Author signature

New user-authored events use scheme `1`:

```text
author_payload =
    "bonnet-feed-author-signature-v1" || encoded_submission
```

`encoded_submission` is defined once in section 13.4. Do not maintain a second
field-order implementation in signature code.

Signature scheme assignments are frozen:

```text
0 = no durable author signature; migration-only
1 = protocol-v3 author signature
2 = preserved and successfully verified protocol-v2 POST_SIGN signature
```

Scheme 2 retains the original v2 signature and exact legacy signed payload in
migration extensions. It does not claim that the author signed the v3 origin,
board, message ID, or content-hash envelope.

The author does not sign `feed_seq`, `previous_event_hash`, or `article_num`
because those are allocated by the origin after submission. The origin signature
binds the author's signed intent to the assigned feed position.

Required author signatures:

- ARTICLE
- CANCEL when initiated by a user
- RESTORE when initiated by a user
- REPORT
- PUNISHMENT and PUNISHMENT_REVOKE when initiated by a moderator identity
- RULE and RULE_REVOKE when initiated by an administrator identity
- BOARD_CLOSE and BOARD_REOPEN when initiated by an administrator identity
- ARTICLE_PIN, ARTICLE_UNPIN, THREAD_CLOSE, and THREAD_REOPEN when initiated by
  a moderator/administrator identity

Local server-generated migration events use scheme 0 or 2 plus the canonical
migration extensions. Never forge an author signature.

### 8.5 Origin signature

```text
origin_payload =
    "bonnet-feed-origin-signature-v1" ||
    every encoded event field except origin_signature
```

The origin signs only after:

1. HTTP authentication and replay checks pass.
2. Command and board ACL checks pass.
3. Event-specific role/ownership checks pass.
4. The event `actor_pubkey` equals the authenticated request key, and supplied
   username/registrar fields match the selected UME principal where applicable.
5. Author signature verifies where required.
6. Referenced local targets and invariants validate.
7. Feed sequence, article number, and previous hash are allocated atomically.
8. The event origin equals canonical `config.origin`. The local signing key must
   never countersign an event claiming a different origin.

Remote peers verify both the origin signature and supported author signature.
The origin signature is mandatory for all federated events.

## 9. Signed Feed Head

Define a compact head independent of `MerkleRegistryStore`:

```text
format_version:       u8 = 1
origin:               u16 UTF-8
board:                u16 UTF-8
latest_feed_seq:      u64be
latest_event_hash:    32 bytes
article_count:        u64be
event_count:          u64be
snapshot_timestamp:   i64be
signature:            64 bytes
```

For an empty feed, sequence and counts are zero and the event hash is 32 zero
bytes.

Head signature payload:

```text
"bonnet-feed-head-signature-v1" || every field except signature
```

Head hash:

```text
SHA-256("bonnet-feed-head-hash-v1" || encoded_head)
```

The authoritative origin writes a new signed head in the same transaction as
each accepted event. Store all observed heads, not only the latest one, so a
same-sequence different-hash head is durable equivocation evidence.

`BOARD_CREATE` creates and stores the signed empty head before making the board
visible in `nav.db` or `BOARD_LIST`. Because nav and feed data are currently
separate databases, use an explicit creation state/reconciliation routine:

1. Create feed state and empty head.
2. Create the nav/board entry.
3. Mark board creation complete.
4. On startup, remove an unadvertised empty feed left by failure, or finish a
   nav entry whose signed feed exists and whose creation marker is complete.

`FEED_HEADS` includes readable empty feeds.

## 10. Feed Acceptance Rules

For each `(origin, board)`:

1. Reject a head whose origin or board differs from the requested feed.
2. Verify the head against the pinned origin key.
3. Reject `incoming_seq < highest_accepted_seq` as rollback.
4. For equal sequence:
   - Same head hash: idempotent success.
   - Different head hash: equivocation; retain evidence and reject activation.
5. For a higher sequence, request exactly the missing range.
6. The first event must be `highest_accepted_seq + 1`.
7. Every subsequent event sequence must be contiguous.
8. The first event's previous hash must match the locally accepted tip hash.
9. Every later previous hash must match the preceding event hash.
10. Every event origin and board must match the feed.
11. Verify origin and supported author signatures.
12. The final event hash must equal the incoming head tip hash.
13. The number of events must agree with the head.
14. Commit events, head, feed state, and projections atomically.

Missing ranges may exceed one `FEED_EVENTS` response. In that case:

1. Verify the candidate signed head first.
2. Fetch bounded contiguous pages.
3. Verify each page against the preceding accepted or staged event hash.
4. Store pages in `feed_staging`, keyed by candidate head hash.
5. Do not expose staged events to projections, queries, exports, or enforcement.
6. After the final staged event matches the candidate head tip and total count,
   promote the complete staged range into `feed_events`, update projections,
   store the head, and advance `feed_state` in one SQLite transaction.
7. Delete stale/incomplete staging rows in bounded startup and periodic cleanup.

Never hold a SQLite transaction open across network requests. Never advance
accepted feed state for a partial range.

On first sync, a receiver downloads metadata from sequence 1. This is an
intentional tradeoff. Do not add snapshots or a Merkle tree in v3 solely to
optimize first sync.

A relay can withhold a suffix or refuse to complete a range, but that produces
an incomplete sync, never a falsely accepted complete history. No distributed
protocol can prove freshness when every source withholds a newer signed head.
Peers should retain and compare observed signed heads; active gossip is a future
extension.

## 11. Availability and Projection Semantics

Do not store a single mutable signed `state` field in an event. Compute current
state by replaying applicable control events in feed order.

Projected article states:

```text
active
cancelled
superseded
purged
```

RESTORE returns a canceled or superseded article to active unless a later purge
exists. A purge is terminal for origin body availability in v3; a later restore
may restore visibility of metadata but cannot reconstruct missing bytes.

Response semantics:

| Metadata | Applicable cancel | Local body | Meaning |
|---|---:|---:|---|
| absent | no | no | unknown article |
| present | no | yes | active/retained article |
| present | yes | yes | canceled but locally retained |
| present | yes | no | cancellation plus unavailable body |
| present | no | no | unexplained or policy-driven unavailability |
| peer has signed metadata but origin denies it | any | any | provable inconsistency |

Normal `ARTICLE_LIST` and `ARTICLE_SEARCH`:

- Exclude canceled, superseded, and purged articles by default.
- Support explicit audit flags for callers with board read permission.
- Never remove control events from federation export ranges.

`ARTICLE_GET`:

- Unknown message/article number: command error 404.
- Known metadata with available body: success, including lifecycle state.
- Known metadata with unavailable body: success with `body_available=false`,
  unless a dedicated body request is used and returns 410.
- Canceled content remains retrievable when retained and the caller has normal
  board read permission. Do not introduce a hidden audit ACL in v3.
- Purged/unavailable content returns metadata and controls, not a false 404.

## 12. Persistence Design

Create `src/core/article_feed.py` for canonical encoders, decoders, hashes,
signature helpers, and the SQLite store. Keep projection/business logic in AME
or a small dedicated service; do not put protocol command handling in the store.

Use one database under `data_dir`, for example `article_feeds.db`.

### 12.1 Feed events

```sql
CREATE TABLE feed_events (
    origin                TEXT NOT NULL,
    board                 TEXT NOT NULL,
    feed_seq              INTEGER NOT NULL,
    event_hash            BLOB NOT NULL,
    previous_event_hash   BLOB NOT NULL,
    message_id            BLOB NOT NULL,
    event_type            INTEGER NOT NULL,
    article_num           INTEGER NOT NULL DEFAULT 0,
    created_at            INTEGER NOT NULL,
    actor_pubkey          BLOB NOT NULL,
    body_hash             BLOB NOT NULL,
    body_size             INTEGER NOT NULL,
    encoded_event         BLOB NOT NULL,
    source_relay          TEXT NOT NULL,
    accepted_at           INTEGER NOT NULL,
    is_authoritative      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (origin, board, feed_seq),
    UNIQUE (message_id)
);

CREATE UNIQUE INDEX feed_events_hash
    ON feed_events(origin, board, event_hash);

CREATE INDEX feed_events_article
    ON feed_events(origin, board, article_num);

CREATE INDEX feed_events_actor
    ON feed_events(actor_pubkey, event_type, created_at);
```

### 12.2 Feed heads and state

```sql
CREATE TABLE feed_heads (
    origin              TEXT NOT NULL,
    board               TEXT NOT NULL,
    latest_feed_seq     INTEGER NOT NULL,
    head_hash           BLOB NOT NULL,
    latest_event_hash   BLOB NOT NULL,
    encoded_head        BLOB NOT NULL,
    is_authoritative    INTEGER NOT NULL DEFAULT 0,
    accepted_at         INTEGER NOT NULL,
    PRIMARY KEY (origin, board, latest_feed_seq, head_hash)
);

CREATE TABLE feed_state (
    origin                    TEXT NOT NULL,
    board                     TEXT NOT NULL,
    highest_accepted_seq      INTEGER NOT NULL,
    current_head_hash         BLOB NOT NULL,
    current_event_hash        BLOB NOT NULL,
    current_article_count     INTEGER NOT NULL,
    current_event_count       INTEGER NOT NULL,
    PRIMARY KEY (origin, board)
);

CREATE TABLE feed_conflicts (
    origin              TEXT NOT NULL,
    board               TEXT NOT NULL,
    feed_seq            INTEGER NOT NULL,
    candidate_hash      BLOB NOT NULL,
    encoded_candidate   BLOB NOT NULL,
    source_relay        TEXT NOT NULL,
    observed_at         INTEGER NOT NULL,
    reason              TEXT NOT NULL,
    PRIMARY KEY (origin, board, feed_seq, candidate_hash)
);

CREATE TABLE feed_staging (
    candidate_head_hash   BLOB NOT NULL,
    origin                TEXT NOT NULL,
    board                 TEXT NOT NULL,
    feed_seq              INTEGER NOT NULL,
    event_hash            BLOB NOT NULL,
    encoded_event         BLOB NOT NULL,
    staged_at             INTEGER NOT NULL,
    PRIMARY KEY (candidate_head_hash, feed_seq)
);
```

Do not overwrite conflicting heads. Store them for audit while refusing to move
`feed_state` to an equivocated branch. Store rejected conflicting event/head
bytes in `feed_conflicts`; never force them into the accepted `feed_events`
primary key.

`source_relay=config.origin` and `is_authoritative=1` mean the event/head was
created and signed by this server for its local origin. Imported events use the
directly contacted relay hostname and `is_authoritative=0`. No other meaning is
attached to this flag.

### 12.3 Article projection

```sql
CREATE TABLE article_projection (
    origin                  TEXT NOT NULL,
    board                   TEXT NOT NULL,
    article_num             INTEGER NOT NULL,
    message_id              BLOB NOT NULL,
    current_state           TEXT NOT NULL,
    root_message_id         BLOB NOT NULL,
    reply_to_message_id     BLOB NOT NULL,
    replacement_message_id  BLOB,
    subject                 TEXT NOT NULL,
    tags                    TEXT NOT NULL,
    options                 TEXT NOT NULL,
    author_pubkey           BLOB NOT NULL,
    author_username         TEXT NOT NULL,
    created_at              INTEGER NOT NULL,
    body_hash               BLOB NOT NULL,
    body_size               INTEGER NOT NULL,
    latest_control_seq      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (origin, board, article_num),
    UNIQUE (message_id)
);
```

This is disposable derived state. Provide a deterministic rebuild command/test
that truncates and reconstructs projections from accepted events.

### 12.4 Control projections

Maintain indexed materialized tables for current rules, reports, punishments,
and revocations. These are also rebuildable from events.

At minimum:

```sql
CREATE TABLE punishment_projection (
    message_id          BLOB PRIMARY KEY,
    origin              TEXT NOT NULL,
    board               TEXT NOT NULL,
    feed_seq            INTEGER NOT NULL,
    punished_pubkey     BLOB NOT NULL,
    expires_at          INTEGER NOT NULL,
    created_at          INTEGER NOT NULL,
    issuer_pubkey       BLOB NOT NULL,
    body_hash           BLOB NOT NULL,
    revoked_by          BLOB
);
```

Enforceability is computed at query/materialization time from current feed
subscription policy, temporal filters, expiry, and revocations. Do not persist
an `enforceable` boolean that becomes stale when configuration changes.

Do not make projections the source of signature truth. The encoded event is the
source of truth.

### 12.5 Body store

Store bodies by hash, not article number:

```text
<data_dir>/article_bodies/<first-two-hex>/<remaining-hex>
```

Requirements:

- Write to a temporary file in the target directory.
- Verify byte count and hash before atomic rename.
- Deduplicate identical bodies.
- Never trust a filename without rechecking the requested hash on read when the
  file may have been externally modified.
- Track body presence and reference counts in SQLite for purge/GC safety.
- Track body-to-event references in SQLite. This is mandatory because identical
  body bytes may be referenced by several articles. Purging one article must not
  remove a shared blob still referenced by another locally retained article.
- v3 has no automatic cache eviction. Body garbage collection is a follow-up.

Use explicit tables:

```sql
CREATE TABLE article_bodies (
    body_hash       BLOB PRIMARY KEY,
    body_size       INTEGER NOT NULL,
    present         INTEGER NOT NULL,
    verified_at     INTEGER,
    relative_path  TEXT NOT NULL
);

CREATE TABLE article_body_refs (
    body_hash    BLOB NOT NULL,
    message_id   BLOB NOT NULL,
    origin       TEXT NOT NULL,
    board        TEXT NOT NULL,
    retained     INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (body_hash, message_id),
    FOREIGN KEY (body_hash) REFERENCES article_bodies(body_hash)
);
```

A purge sets the target reference's `retained=0`. Remove a local blob only when
no retained reference remains and local archive policy permits removal.

## 13. Protocol v3 Command Surface

Keep the one-byte command framing but substantially reduce the table.

### 13.1 Retained commands

Retain, after verifying their current client/server formats agree:

```text
0x01 REGISTER
0x02 GET_USERS_BY_PUBKEY
0x03 LIST_USERS
0x04 LIST_PEERS
0x05 USER_REGISTRY_HEAD
0x06 USER_REGISTRY_NODES
0x07 USER_REGISTRY_RECORDS
0x08 USER_REGISTRY_HEADS
0x09 USER_REGISTRY_HEAD_CHAIN
0x10 BOARD_CREATE
0x11 BOARD_LIST
0x20 USER_PROMOTE
0x21 USER_DEMOTE
0x30 GET_PUBKEY
0x70 PEER_KEY_ROTATE
0x71 PEER_KEY_LIST
```

`GET_USERS_BY_PUBKEY` takes exactly one 32-byte public key and returns a bounded
count followed by every matching user record. This intentionally follows the
current client's pubkey lookup intent and replaces the contradictory server
username parser. User records use the same canonical fields as `LIST_USERS`.

### 13.2 New compact article/feed commands

Reuse the old post range under protocol v3:

```text
0x12 ARTICLE_PUBLISH       write
0x13 ARTICLE_GET           read
0x14 ARTICLE_LIST          read
0x15 FEED_HEAD             read, object="articles"
0x16 FEED_EVENTS           read, object="articles"
0x17 ARTICLE_BODY          read, object="articles"
0x18 FEED_HEADS            read, object="articles"
0x19 ARTICLE_SEARCH        read
0x1A BOARD_SET_STATE       write
0x1B BAN_STATUS            read
```

`ARTICLE_PUBLISH` publishes ARTICLE or any supported control event. There are no
separate network write opcodes for report, punishment, cancel, or rule creation.
Event-specific handler validation dispatches by event type after common parsing.

`ARTICLE_GET`, `ARTICLE_LIST`, and `ARTICLE_SEARCH` are user-facing board views.
They require command ACL plus board read ACL.

`FEED_HEAD`, `FEED_EVENTS`, `ARTICLE_BODY`, and `FEED_HEADS` are federation/audit
exports. They require command read ACL, `articles` object read ACL, and board read
ACL for each requested feed. Multi-feed `FEED_HEADS` must omit feeds the caller
cannot read; this is export ACL filtering, not import allowlist filtering.

`BOARD_SET_STATE` publishes BOARD_CLOSE or BOARD_REOPEN through the local feed.
It is a separate wire command in v3 to keep privileged board-state changes out
of generic user publication parsing. It still creates a normal signed control
event internally; there is no second mutable state-change path.

`BAN_STATUS` returns this server's local effective policy result for one public
key. Keep this compact query because effective status depends on private feed
subscription/enforcement configuration and cannot be inferred reliably from
public article search results. It replaces old `IS_BANNED` semantics without
retaining the rest of the punishment command family.

### 13.3 Removed commands

Remove these protocol-v2 commands and all builders/parsers/handlers/tests that
exist only for them:

```text
0x15 POST_UPDATE
0x16 POST_DELETE
0x17 BOARD_CLOSE (old mutable form)
0x18 BOARD_DELETE
0x19 QUERY_POSTS (old SQL-like protocol)
0x1A POST_CONTENT_SEARCH (old format)
0x22 POST_SIGN

0x40 RULE_CREATE
0x41 RULE_GET
0x42 RULE_GET_BY_NAME
0x43 RULE_LIST
0x44 RULE_UPDATE

0x50 REPORT_CREATE
0x51 REPORT_GET
0x52 REPORT_LIST_BY_CULPRIT
0x53 REPORT_SIGN
0x54 REPORT_LIST_SINCE
0x55 REPORT_REGISTRY_HEAD
0x56 REPORT_REGISTRY_NODES
0x57 REPORT_REGISTRY_RECORDS
0x58 REPORT_REGISTRY_HEADS
0x59 REPORT_REGISTRY_HEAD_CHAIN

0x60 PUNISHMENT_CREATE
0x61 PUNISHMENT_GET
0x62 PUNISHMENT_LIST_ACTIVE
0x63 IS_BANNED
0x64 PUNISHMENT_LIST_BY_PUBKEY
0x65 PUNISHMENT_REGISTRY_HEAD
0x66 PUNISHMENT_REGISTRY_NODES
0x67 PUNISHMENT_REGISTRY_RECORDS
0x68 PUNISHMENT_REGISTRY_HEADS
0x69 PUNISHMENT_REGISTRY_HEAD_CHAIN
```

High-level client convenience methods may remain if they are thin wrappers over
generic article publication/query. They must not retain private wire commands.

### 13.4 Wire formats

All strings in new commands use `u16 length + UTF-8 bytes` unless they are
bodies, which use `u32` lengths. Stop introducing new `u8` string lengths.

Frozen enums and flags:

```text
selector_type:
  0x01 article_num (u64)
  0x02 message_id (32 bytes)

projected_state:
  0x01 active
  0x02 cancelled
  0x03 superseded
  0x04 purged

body_status:
  0x00 not requested
  0x01 included in this response
  0x02 available but not included
  0x03 known but unavailable

article query flags:
  0x0001 include_cancelled
  0x0002 include_superseded
  0x0004 include_purged
  0x0008 include_controls
  0x0010 include_bodies

event_type_mask:
  bit (event_type - 1) selects event types 0x01 through 0x20
```

#### Client submission encoding

`ARTICLE_PUBLISH` carries one canonical client submission. It is not a partial
complete-event encoding.

```text
submission_version:       u8 = 1
event_type:              u8
origin:                  u16 UTF-8
board:                   u16 UTF-8
message_id:              32 bytes
created_at:              i64be
actor_pubkey:            32 bytes
actor_username:          u16 UTF-8
actor_registrar:         u16 UTF-8
root_message_id:         32 bytes
reply_to_message_id:     32 bytes
supersedes_message_id:   32 bytes
target_message_id:       32 bytes
headers:                 u32 length + type-specific canonical bytes
body_hash:               32 bytes
body_size:               u64be
```

The scheme-1 author payload is exactly:

```text
"bonnet-feed-author-signature-v1" || encoded_submission
```

The server verifies the submission, allocates `feed_seq`,
`previous_event_hash`, and `article_num`, then constructs the complete event
encoding from section 8. This removes any duplicate field-order definition.

`ARTICLE_PUBLISH` request:

```text
opcode:                   u8
submission_len:           u32
encoded_submission:       bytes
body_len:                 u32
body:                     bytes
author_signature_scheme:  u8
author_signature_len:     u16
author_signature:         bytes
```

The submission origin must equal canonical local origin; empty origin is not
accepted because it is part of the author signature. The submission body hash
and size must match the supplied body. The server rejects any trailing bytes.

Success response:

```text
event_len:u32 + encoded_complete_event + head_len:u16 + encoded_feed_head
```

An idempotent duplicate message ID with identical submission/body returns the
original complete event plus the current feed head. A duplicate message ID with
different bytes returns command error 409.

`ARTICLE_GET` request supports exactly one selector:

```text
origin + board + selector_type:u8 +
  (article_num:u64 | message_id:32) + include_body:u8
```

Success response:

```text
event_len:u32 + encoded_event + projected_state:u8 +
control_count:u16 + control_message_ids:(32 * count) +
body_status:u8 + body_len:u32 + body_bytes
```

`body_len` is zero unless `body_status=0x01`. Unknown selectors return command
error 404 after board ACL evaluation.

`ARTICLE_LIST` request:

```text
origin + board + offset:u32 + limit:u16 + flags:u16
```

Flags include `include_cancelled`, `include_superseded`, `include_purged`, and
`include_controls`. Apply strict maximum limits.

Success response:

```text
count:u16 + repeated {
  event_len:u32 + encoded_event + projected_state:u8 +
  control_count:u16 + control_message_ids:(32 * count) + body_status:u8 +
  body_len:u32 + optional_body
}
```

If `include_bodies` is unset, each retained body reports status `0x02` and has
zero body length.

`FEED_HEAD` request:

```text
origin + board
```

Success response is `head_len:u16 + encoded_feed_head`.

`FEED_EVENTS` request:

```text
origin + board + start_seq:u64 + max_count:u16
```

Success response is `count:u16` followed by `event_len:u32 + encoded_event` for
each event. It never includes bodies. Require contiguous ascending events. Bound
response bytes in addition to event count. Returning fewer than `max_count`
because of the byte limit is valid and the caller continues at the next sequence.

`ARTICLE_BODY` request:

```text
origin + board + message_id:32 + body_hash:32
```

The server evaluates command/object/board ACLs using the supplied canonical feed
identity before revealing whether the message exists. It then verifies that the
message belongs to that feed and commits to the requested hash. A raw content
hash must never become a cross-board ACL bypass. Unknown association/hash returns
command error 404. Known but unavailable returns command error 410. Success is
`body_len:u32 + body_bytes`. The caller verifies the returned bytes against the
requested hash.

`FEED_HEADS` request:

```text
offset:u32 + limit:u16
```

Success response is `count:u16` followed by:

```text
origin:u16 UTF-8 + board:u16 UTF-8 + head_len:u16 + encoded_signed_head
```

There is no optional body-cache summary in v3. The advertised head is only a
candidate until verified against the origin pin.

`ARTICLE_SEARCH` uses bounded structured filters, not caller-supplied SQL:

```text
origin + board + event_type_mask:u32 + actor_pubkey_or_zero:32 +
subject_pubkey_or_zero:32 + target_message_id_or_zero:32 +
created_after:i64 + created_before:i64 + text_query:u16-length UTF-8 +
offset:u32 + limit:u16 + flags:u16
```

`subject_pubkey` matches typed fields such as report culprit or punished key.
Text search only covers metadata and locally available bodies. The response must
state when body search was incomplete because bodies were not cached. Success
starts with `body_search_complete:u8` and then uses the same entry list encoding
as `ARTICLE_LIST`.

`BAN_STATUS` request is one 32-byte public key. Success response:

```text
banned:u8 + reason:u16 UTF-8 + punishment_message_id:32 +
source_origin:u16 UTF-8 + source_board:u16 UTF-8 + expires_at:i64
```

When not banned, message ID is zero, source strings are empty, and expiry is 0.
It reveals only this server's materialized policy result and is independently
ACL-controlled.

`BOARD_SET_STATE` uses the same request and success framing as ARTICLE_PUBLISH,
but accepts only BOARD_CLOSE or BOARD_REOPEN submissions and applies the
privileged board-state handler. The submitted event remains author-signed.

## 14. Authorization

Authorization remains conjunctive:

```text
valid HTTP signature
AND command ACL
AND articles object ACL for federation/audit exports
AND board ACL
AND event-specific ownership/role checks
AND effective-ban write gate
```

### 14.1 Publication

- Unknown and anonymous principals cannot publish articles by default.
- Known users need `ARTICLE_PUBLISH` command write permission and board write
  permission.
- Banned known users are denied all publication, including cancel/restore.
- A user may supersede/cancel their own article.
- Moderators/administrators retain existing moderation authority.
- PUNISHMENT, PUNISHMENT_REVOKE, RULE, RULE_REVOKE, PURGE, BOARD_CLOSE, and
  BOARD_REOPEN require explicit role checks in addition to ACLs.
- Admin bypass may retain its existing effect on board ACLs but must not bypass
  command or object ACLs.

Closed-board publication rules are explicit:

- Reject ARTICLE (including superseding replacements), CANCEL, RESTORE, REPORT,
  RULE, PUNISHMENT, ARTICLE_PIN, ARTICLE_UNPIN, and THREAD_CLOSE/REOPEN.
- Permit BOARD_REOPEN for an authorized administrator.
- Permit PURGE, RULE_REVOKE, and PUNISHMENT_REVOKE for authorized privileged
  actors so a closed moderation board can still retract dangerous policy.
- Reject BOARD_CLOSE when already closed and BOARD_REOPEN when already open as
  idempotent conflict errors unless the identical message ID was already
  accepted.

### 14.2 Export

- `FEED_*` and `ARTICLE_BODY` require `objects=["articles"]` read permission.
- They also require board read permission for the referenced feed.
- `FEED_HEADS` must evaluate board read permission per entry.
- Import subscriptions never affect export visibility.
- Anonymous/unknown peer export behavior is configured explicitly, not hardcoded.

### 14.3 Canceled content

- Canceled retained bodies use the same board read ACL as active content.
- Do not add an audit-only permission in v3.
- Purged/unavailable metadata remains readable wherever the article metadata is
  readable.

## 15. Configuration

Replace report/punishment import allowlists with feed subscriptions. Keep the
user identity allowlist and board discovery policy as needed.

Recommended shape:

```toml
[[feed_subscription]]
origin = "community.example"
boards = ["general", "moderation.reports", "moderation.actions"]
relays = ["community.example", "cache.example.net"]
body_policy = "on-demand" # none | on-demand | eager

[[feed_subscription]]
origin = "archive.example"
boards = ["*"]
relays = ["archive.example"]
body_policy = "on-demand"

[[control_policy]]
origin = "community.example"
board = "moderation.actions"
apply = ["punishment", "punishment-revoke"]
```

Rules:

- No matching subscription means no import.
- Matching is against event origin and board, never relay hostname.
- `relays` are dial candidates, not trusted content origins. Every dial still
  passes SSRF checks and every event still verifies against the event origin.
- `body_policy=none` imports metadata only.
- `body_policy=on-demand` fetches bodies when locally requested or required for
  a configured materializer.
- `body_policy=eager` fetches bodies after metadata acceptance, with bounded
  concurrency and size limits.
- Removing a subscription stops future sync; it does not silently delete or
  deactivate already accepted events.
- `control_policy` is evaluated only over already accepted events and is
  independent of whether a feed is still subscribed for future imports.
- Unknown event names in `control_policy.apply` fail configuration loading.
- Changing/removing a control policy atomically rebuilds effective policy at
  startup or through the operator command below. This may intentionally activate
  or deactivate already accepted punishments.

Generated ACL defaults must explicitly cover all v3 commands. Remove report and
punishment object ACL examples. Add the `articles` object.

Configure the local moderation board names explicitly:

```toml
[moderation_boards]
rules = "moderation.rules"
reports = "moderation.reports"
punishments = "moderation.actions"
```

These defaults are frozen for generated configurations. Each board has normal
board ACLs, allowing report publication to be broader than punishment or rule
publication. Migration creates a missing local moderation board only after
checking that its configured name does not already identify a remote board.

Implement enforcement rebuild as a local operator CLI command, not a remotely
reachable protocol opcode:

```text
bonnet policy rebuild [--origin ORIGIN] [--board BOARD] [--dry-run]
```

It recomputes materialized moderation state from accepted events under current
control policies, prints additions/removals, and commits atomically unless
`--dry-run` is used.

## 16. Federation and Relay Flow

### 16.1 Sync orchestration

Replace the current report/punishment registry calls in `_do_sync_from_peer`
with article-feed synchronization:

1. After signed discovery, require protocol version 3 and capability
   `immutable-article-feed-v1`. If absent, record an unsupported-peer result and
   stop without issuing v3 commands. Capability mismatch must not alter pins or
   accepted data. Identity/pin mismatch remains a hard failure and never
   triggers downgrade.
2. Sync board directory metadata.
3. Sync the direct peer's user identity registry.
4. Fetch `FEED_HEADS` from the peer.
5. For each advertised `(origin, board)`:
   - Skip local authoritative feeds.
   - Check feed subscription.
   - Require an existing pinned origin key.
   - Verify the signed head.
   - Compare with local feed state.
   - Fetch a contiguous missing range with `FEED_EVENTS`.
   - Validate and atomically accept it.
   - Apply configured materializers.
6. Fetch bodies according to body policy.

Do not require the advertised origin to equal the directly contacted peer. That
would disable relaying. Do require the origin key to be independently pinned.

### 16.2 Sync triggering

The current worker is event-driven and only syncs peers queued by remote-board
operations. That is insufficient for moderation enforcement.

Add a bounded periodic scheduler:

- Enumerate configured feed relay candidates and known board relays.
- Queue each peer at a configurable interval with jitter.
- Keep existing inflight deduplication.
- Apply exponential backoff per peer.
- Preserve manual/on-demand queueing for stale reads.
- Shutdown cleanly with the server lifecycle.

Do not let one failing peer block the queue permanently. Record per-peer last
success, last failure, and next retry.

### 16.3 SSRF and trust

- Preserve `_is_dialable_host` before resolution.
- Preserve `_resolves_to_global_only` immediately before every dial.
- Do not follow redirects.
- Preserve TLS configuration and signed HTTP responses.
- TOFU the directly contacted peer for transport response verification.
- Verify each feed head and event against the claimed origin's pinned key.
- A relay advertisement never creates an origin pin.
- Key rotation remains old-key-authorized through `TrustStore`.

### 16.4 Relay storage

- Cache exact encoded event and head bytes.
- Set `source_relay` to the directly contacted hostname locally; it is not part
  of signed event bytes.
- Export cached remote feeds subject only to caller ACLs.
- A relay may serve any retained matching body by hash.
- Body absence must be represented honestly; never return empty bytes as though
  they matched a non-empty hash.

## 17. Materialized Moderation Policy

Retain Keibatsu temporarily as the effective policy interface, but make article
events its source rather than report/punishment tables.

### 17.1 Effective punishment rules

An effective punishment must:

- Come from an accepted event matched by a control policy whose `apply` includes
  `punishment`.
- Have a valid origin/event chain already accepted.
- Not be a warning (`expires_at == 0`).
- Be permanent (`expires_at < 0`) or unexpired.
- Not have an applicable later PUNISHMENT_REVOKE event.
- Pass the existing per-origin temporal filter using event origin and
  `created_at`. Preserve this filter in v3; do not silently broaden enforcement
  to records the current policy excludes.

Deterministic ordering for the displayed effective reason:

```text
created_at DESC, origin ASC, board ASC, feed_seq DESC, message_id ASC
```

This intentionally replaces legacy `(punishment_id, rollover)` tie-breaking.
Migration order is deterministic, but the displayed reason may change when
multiple active legacy punishments have identical creation timestamps. Ban
truth remains "any applicable active punishment" and is unaffected by which
reason is displayed.

Any effective punishment blocks writes for the known target user. Reads remain
subject to normal ACLs.

### 17.2 Queries

Replace dedicated wire commands with local projection methods used by client
wrappers and MCP resources:

- Reports by culprit public key.
- Punishments by public key.
- Active/effective punishments.
- Ban status and reason.
- Rules by name/message ID.

These may use internal SQL projection queries. They must not require private
report/punishment list opcodes. A remote client can query typed articles through
ARTICLE_LIST or ARTICLE_SEARCH; local effective ban status uses `BAN_STATUS`.

### 17.3 UME compatibility flag

The UME `is_banned` flag remains compatibility-only during migration. The
event-derived evaluator is authoritative. Never clear the flag while any
effective event-derived punishment remains. Remove the flag in a later storage
renovation only after all callers stop relying on it.

One reconciliation function owns compatibility-flag writes. It evaluates the
union of active legacy-transition and v3 punishments, then sets/clears UME state.
Legacy Keibatsu creation/expiry code must not independently race this function
after v3 materialization is enabled.

## 18. Migration

Migration must preserve data without pretending legacy records possess
signatures they never had.

### 18.1 General strategy

- Back up all board directories, nav DB, Keibatsu DBs, registry DBs, userfile,
  and trust stores before migration.
- Use explicit schema/version markers.
- Migrate authoritative local data; do not transform cached remote data into
  locally originated events.
- Remote origins are responsible for publishing their own authoritative
  backfill after upgrading.
- Preserve old databases as read-only archives for at least one release.
- Do not dual-write indefinitely. Use a bounded migration release and then cut
  reads/writes to v3.

### 18.2 Existing local posts

For each locally originated board, under a board/feed transaction:

1. Read all surviving rows ordered by `post_num` and each available body.
2. Compute body hashes and the canonical legacy metadata below for every row.
3. Derive every deterministic message ID and build a complete
   `post_num -> message_id` map before signing or inserting any event.
4. In a second pass, create one migrated ARTICLE event per row with final root
   message IDs already populated.
5. Preserve `post_num` as `article_num`.
6. Derive deterministic message ID from:

```text
SHA-256("bonnet-legacy-post-message-id-v1" ||
       origin || board || post_num || canonical_legacy_metadata || body_hash)
```

`canonical_legacy_metadata` is exactly:

```text
post_num:u64be
last_modified:i64be
creation_date:i64be
last_bumped:i64be
closed:u8
sticky:i32be
tags:u32-length UTF-8
subject:u32-length UTF-8
options:u32-length UTF-8
root:u64be
author:u16-length UTF-8
author_registrar:u16-length UTF-8
legacy_signature_text:u16-length UTF-8
```

No locale-dependent conversion, SQLite row serialization, or filesystem path
enters this encoding.

7. Set `root_message_id` from the precomputed map when legacy `root != 0`.
   Legacy data has no direct-parent or supersede identity, so set
   `reply_to_message_id` and `supersedes_message_id` to zero.
8. Preserve the old post signature bytes and signature payload version in
   canonical migration extensions.
9. Verify an old signature when present and record whether it validated.
10. Do not create an author signature when none existed.
11. Set `author_signature_scheme=0` for unsigned/unverifiable legacy posts and
    scheme `2` for successfully verified protocol-v2 signatures.
    For scheme 2, put the exact old signed payload in extension `0x0002`; the
    event's `author_signature` contains the old signature bytes.
12. Origin-countersign the complete migrated event with LEGACY_DESCRIPTOR.
13. Chain ARTICLE events in ascending legacy post-number order.
14. After all ARTICLE events, append origin-signed migration controls for every
    nonzero legacy `sticky` value and every closed legacy thread. These controls
    use ARTICLE_PIN and THREAD_CLOSE and preserve the observed final state
    without pretending the author signed that moderation state.

Deleted legacy posts cannot be reconstructed because current code removed both
row and body. Do not fabricate tombstones without evidence. Document this as an
unrecoverable pre-v3 history limitation.

Current mutable fields require explicit treatment:

- Subject/tags/options/content migrate as their final observed state.
- `creation_date` becomes event creation time.
- `last_modified` is retained in legacy headers but does not imply a known edit
  history.
- `last_bumped` is projection metadata only.
- `sticky` and `closed` migrate through the generated origin controls above,
  never through a forged author payload.

### 18.3 Existing local rules

Migrate existing rules to the configured local `moderation.rules` board ordered
by `rule_num ASC`:

- Encode the legacy rule record exactly as:

```text
rule_num:u64be + rule_name:u16-length UTF-8 +
description_hash:SHA-256("bonnet-legacy-rule-description-v1" || description_utf8)
```

- Derive its message ID as
  `SHA-256("bonnet-legacy-rule-message-id-v1" || canonical_origin || encoded_legacy_rule)`.
- Store the description as the event body.
- Preserve the numeric rule ID in LEGACY_DESCRIPTOR for report mapping.
- Use scheme 0 because legacy rules have no author signature.
- Origin-countersign each migrated RULE event.
- Build a complete `rule_num -> rule_message_id` map before migrating reports.

### 18.4 Existing local reports

For rows whose `origin == config.origin`:

- Publish into the configured local `moderation.reports` feed ordered by
  `report_num ASC, rollover ASC`.
- Convert every rollover row into a distinct REPORT event.
- Preserve the original canonical report bytes and both old signatures in
  canonical migration extensions.
- Define `legacy_report_record` as the exact current
  `report_registry.encode_report_record(...)` output including origin/reporter
  signatures. Define `legacy_report_hash` as
  `SHA-256("bonnet-legacy-report-record-v1" || legacy_report_record)`.
- Derive message ID as
  `SHA-256("bonnet-legacy-report-message-id-v1" || canonical_origin || report_num:u64be || rollover:u64be || legacy_report_hash)`.
- Map culprit board/post number to a migrated article message ID when possible.
- Preserve unresolved legacy numeric references explicitly.
- Put the old reporter-signed payload/signature in extensions `0x0002/0x0003`
  when present and valid. Put the old origin-signed payload/signature in
  extensions `0x0004/0x0005`. Put numeric target/rule references in `0x0006`.
- Store report description as the event body and map known rule numbers through
  the precomputed rule message-ID map.
- Origin-countersign each migrated event.
- Do not collapse rollovers; they are distinct historical records.

### 18.5 Existing local punishments

For rows whose `origin == config.origin`:

- Publish into the configured local `moderation.actions` feed ordered by
  `punishment_id ASC, rollover ASC`.
- Convert each `(punishment_id, rollover)` row into a distinct PUNISHMENT event.
- Preserve original canonical bytes and origin signature in extensions
  `0x0004/0x0005` and legacy report-number references in `0x0006`.
- Define `legacy_punishment_record` as the exact current
  `punishment_registry.encode_punishment_record(...)` output including the old
  origin signature. Define `legacy_punishment_hash` as
  `SHA-256("bonnet-legacy-punishment-record-v1" || legacy_punishment_record)`.
- Derive message ID as
  `SHA-256("bonnet-legacy-punishment-message-id-v1" || canonical_origin || punishment_id:u64be || rollover:u64be || legacy_punishment_hash)`.
- Map local report IDs to migrated REPORT message IDs when unambiguous.
- Preserve unresolved references as legacy IDs.
- Store punishment notes as the event body.
- Origin-countersign each migrated event.
- Preserve `expires_at`, `issued_by`, `created_at`, and notes exactly.

### 18.6 Remote cached moderation data

- Keep it in read-only legacy Keibatsu tables for audit during the transition.
- Do not insert it into a local authoritative feed.
- Do not sign it with the local server key.
- Rebuild remote feed caches by syncing upgraded authoritative origins or their
  relays.
- During the migration release only, effective-ban evaluation may union legacy
  accepted remote punishments with v3 materialized punishments to avoid a
  security gap.
- Remove the legacy union only after configured enforcement origins have been
  successfully synchronized over v3 or the operator explicitly accepts removal.

Track this per enforcement feed in a local migration table with states
`legacy-required`, `v3-synchronized`, and `operator-waived`. Do not use a global
build flag or an implicit release-version check. The evaluator includes legacy
rows while any applicable feed remains `legacy-required`.

### 18.7 Registry databases

- Keep `user_registry.db` and user registry behavior.
- Stop constructing report/punishment registry services after v3 migration.
- Retain old report/punishment registry DB files as read-only operator archives.
- Provide an explicit cleanup command or documented manual step; do not delete
  them automatically on first startup.

### 18.8 Transaction and restart safety

- Store migration progress per board and moderation source.
- A completed unit is idempotent on restart.
- Verify event count, sequence continuity, body hashes, signatures, and article
  number mapping before marking a unit complete.
- Do not rename/delete old storage until verification succeeds.
- Add failure-injection tests between body write, event insert, head insert,
  projection update, and migration marker update.

## 19. File-Level Change Map

### 19.1 New files

- `src/core/article_feed.py`
  - Event/head dataclasses.
  - Strict canonical encoders/decoders.
  - Domain-separated hashes and signatures.
  - SQLite feed store.
  - Atomic local append and remote range acceptance.
- `src/engine/article_projection.py` if keeping projection logic in AME would
  make `ame.py` substantially harder to understand.
- `tests/test_article_feed.py`
- `tests/test_article_federation.py`
- `tests/fixtures/protocol_v3/`
- A migration module if the migration cannot remain small and testable inside
  the store initialization path.

### 19.2 Major edits

- `src/engine/ame.py`
  - Replace mutable post CRUD with feed append/projection reads.
  - Remove hard deletion.
  - Preserve board/nav responsibilities.
- `src/engine/keibatsu.py`
  - Consume typed event projections.
  - Retain effective-ban interface during migration.
  - Remove report/punishment authoritative mutation paths after cutover.
- `src/core/commands.py`
  - Replace opcode table with compact v3 table.
- `src/core/config.py`
  - Add feed subscriptions and `articles` object ACL.
  - Remove report/punishment import allowlists and default ACL entries.
- `src/net/commands.py`
  - Add generic article/feed handlers.
  - Delete mutable post and dedicated moderation handlers.
- `src/net/sync.py`
  - Add feed head/range/body sync.
  - Remove report/punishment registry sync.
  - Add periodic scheduling/backoff.
- `src/net/http_server.py`, `src/net/http_auth.py`
  - Update protocol version/capabilities while preserving signature profile.
- `src/client/protocol.py`
  - Add v3 builders/parsers and fixed vectors.
  - Delete old command codecs.
- `src/client/http.py`
  - Add generic publish/get/list/search methods.
  - Retarget convenience moderation methods.
- `src/client/models.py`
  - Add event, feed-head, lifecycle, and body-availability models.
- `src/client/tools.py`, `src/client/resources.py`
  - Present article/control semantics without exposing removed opcodes.
- `src/app/server.py`
  - Construct feed store/service.
  - Remove report/punishment registry services and dirty callbacks.

### 19.3 Delete after replacement tests pass

- `src/core/report_registry.py`
- `src/core/punishment_registry.py`
- Report/punishment registry imports and exports.
- Registry-specific command handlers/builders/parsers.
- Registry-specific sync methods.
- Registry dirty callbacks in Keibatsu and app wiring.
- Tests whose only purpose is the removed report/punishment Merkle protocol.

Do not delete `src/core/merkle_registry.py`; the user identity registry uses it.

## 20. Client and MCP Design

Keep useful user-facing operations while consolidating the wire protocol.

Recommended high-level client methods:

- `publish_article(...)`
- `cancel_article(...)`
- `restore_article(...)`
- `supersede_article(...)`
- `get_article(...)`
- `list_articles(...)`
- `search_articles(...)`
- `publish_report(...)`
- `publish_punishment(...)`
- `revoke_punishment(...)`
- `list_reports_by_culprit(...)`
- `list_punishments_by_pubkey(...)`
- `is_banned(...)`

The report/punishment query helpers use typed article queries or local projection
resources. They must not require dedicated server commands.

Models must expose:

- Origin, board, feed sequence, article number, message ID.
- Event type and target IDs.
- Actor identity.
- Both signature schemes/signatures where relevant.
- Body hash, size, and availability.
- Projected lifecycle state.
- Applicable control event IDs.
- Relay/source metadata clearly marked as local and unsigned.

## 21. Discovery Capabilities

Replace:

```text
report-registry-merkle-v1
punishment-registry-merkle-v1
```

with:

```text
immutable-article-feed-v1
article-control-messages-v1
article-body-by-hash-v1
user-registry-merkle-v1
command-object-acl-v1
```

Do not advertise removed capabilities after v3 cutover. Sync must check for the
article capability and fail cleanly when contacting a v2 peer; it must not
downgrade after a v3 identity/trust failure.

Discovery also publishes the configured local moderation board names so clients
can implement high-level report/rule/punishment helpers without guessing:

```json
{
  "moderation_boards": {
    "rules": "moderation.rules",
    "reports": "moderation.reports",
    "punishments": "moderation.actions"
  }
}
```

These names are informational routing metadata inside the origin-signed
discovery response. They do not grant write permission or replace board ACLs.

## 22. Security Invariants

Implementation is blocked unless all of these hold:

1. A remote event is never activated before origin signature, feed identity,
   sequence, and previous-hash linkage verify.
2. A relay response signature never substitutes for an origin event signature.
3. A relay cannot introduce trust in an unpinned origin.
4. Feed import subscriptions check origin and board, not relay hostname.
5. Event ordering uses feed sequence and hash linkage, never timestamps.
6. Same-sequence different-head or different-event data is retained as evidence
   and rejected from active state.
7. Event acceptance and projection updates are atomic.
8. Bodies are accepted only after size and content hash verification.
9. Cancel/supersede never remove signed metadata or body bytes.
10. Purge never removes signed metadata or content hash.
11. Normal list filtering never affects federation event export.
12. Command, object, board, role, and ban checks remain conjunctive.
13. Board ACL authorization is proven downstream by the origin countersignature,
    not by trusting an author's claim.
14. Cached remote events are never signed or exported as local events.
15. SSRF checks remain before every federation dial.
16. Existing trust keys, trust modes, and timestamps survive canonical-origin
    migration; spelling changes are collision-checked and transactional.
17. Parser bounds are enforced before allocation or iteration.
18. Migration never forges author signatures.
19. Legacy remote punishments are not silently dropped before v3 enforcement
    sources are synchronized or explicitly waived.
20. Private keys, article bodies, and raw signatures are not logged by default.
21. The local origin key signs only events whose canonical origin equals
    canonical `config.origin`.
22. Board-nav omission/deletion never deletes accepted feed events, heads, or
    retained bodies.

## 23. Testing Plan

Use `uv run` for all Python and pytest commands.

### 23.1 Canonical encoding vectors

- Fixed ARTICLE vector.
- Fixed CANCEL vector.
- Fixed REPORT/PUNISHMENT vectors.
- Empty and maximum-length fields.
- Author and origin signature vectors.
- Body hash vector.
- Event hash and head hash vectors.
- Cross-domain signature replay fails.
- Decoder rejects truncation, overflow, invalid UTF-8, and trailing bytes.

### 23.2 Local append tests

- First event gets sequence 1 and zero previous hash.
- Concurrent publication allocates unique contiguous sequences.
- Article numbers are contiguous among ARTICLE events only.
- Duplicate message ID with identical request is idempotent.
- Duplicate message ID with different content is rejected.
- Invalid author signature is rejected before allocation.
- Origin signature covers allocated sequence and previous hash.
- Transaction rollback leaves no body, event, head, or projection orphan.

### 23.3 Lifecycle tests

- Author cancellation hides from default list but direct get returns body.
- Moderator cancellation behaves likewise.
- Unauthorized cancellation fails.
- Supersede creates a new article and retains old content.
- Restore makes the target visible again.
- Purge retains metadata/hash and removes only local body after event commit.
- A peer retaining a purged body can still prove it matches the original hash.
- Search/list audit flags include canceled/superseded/purged records.
- Unknown target controls are rejected locally.

### 23.4 Feed acceptance tests

- Contiguous range advances state.
- Missing sequence rejects the complete range.
- Wrong previous hash rejects.
- Wrong origin or board rejects.
- Invalid origin signature rejects.
- Invalid event hash rejects.
- Lower head sequence rejects rollback.
- Same sequence/same hash is idempotent.
- Same sequence/different hash is equivocation and retained for evidence.
- Final event must match head tip.
- Partial range never advances head state.
- Unknown future event types follow configured behavior.
- Multi-page ranges remain invisible in staging until final atomic promotion.
- Stale staging data is cleaned without affecting accepted state.

### 23.5 Body tests

- Body fetched from origin verifies.
- Body fetched through relay verifies.
- Substituted body rejects.
- Truncated body rejects.
- Oversized body rejects before buffering beyond limit.
- Known metadata with missing body is represented honestly.
- Identical bodies deduplicate.
- Externally modified CAS files fail hash verification on read and are marked
  unavailable/corrupt rather than served.

### 23.6 ACL tests

- ARTICLE_PUBLISH requires command write plus board write.
- FEED commands require command read plus articles-object read plus board read.
- Admin does not bypass command/object ACL.
- Existing intended board admin bypass behavior remains.
- Anonymous and unknown export grants can differ.
- Banned known user cannot publish any event.
- Banned user can read authorized canceled content.
- Punishment publication still requires moderator/admin role after ACL grant.
- Import subscription never changes export results.

### 23.7 Moderation materialization tests

- REPORT is queryable by culprit.
- PUNISHMENT warning does not ban.
- Temporary unexpired punishment bans.
- Expired punishment does not ban.
- Permanent punishment bans.
- Revocation removes effective ban but preserves audit rows.
- Multiple enforcement feeds: any active applicable punishment blocks writes.
- Archive-only feed does not affect bans.
- Per-origin temporal filter is applied consistently.
- UME flag disagreement does not override event-derived state.

### 23.8 Relay integration tests

At least four nodes:

- Origin A publishes article, cancel, report, and punishment events.
- Relay B imports A and caches metadata and selected bodies.
- Node C imports A through B, verifies A's signatures, and applies A's
  punishment feed.
- Archive D imports metadata but applies no controls.
- C blocks writes by the punished user and permits authorized reads.
- D never blocks that user.
- B cannot advertise origin E into C without E already being pinned and
  subscribed.
- A deletes a body after purge; B can still show signed metadata and may retain
  the old body.
- A deletes a body without purge; peers classify it as unexplained
  unavailability rather than rewriting history.
- A equivocates at one sequence; peers retaining conflicting signed heads can
  demonstrate the conflict.

### 23.9 Migration tests

- Existing post numbers are preserved.
- Existing root relationships map to message IDs.
- Existing bodies hash correctly.
- Unsigned legacy posts remain honestly marked unsigned.
- Valid old post signatures remain preserved and verifiable under legacy scheme.
- Reports/punishments preserve every rollover as a distinct event.
- Existing origin signatures remain stored.
- Remote cached records are not re-signed locally.
- Interrupted migration resumes idempotently.
- Old databases remain untouched until verification completes.
- Effective bans remain continuous across the transition union.

### 23.10 Full verification

Run focused tests after each phase, then:

```text
uv run pytest -x -q
```

Also run package/frozen build verification because new modules and data paths
must be included in `bonnet.spec`.

Audit logging tests must prove command dispatch does not hex-log complete v3
request bodies, article bodies, or author/origin signatures. Log only request
IDs, opcode/event type, bounded identifiers, hashes, and failure categories.

## 24. Implementation Phases

### Phase 0: Freeze v2 and migration fixtures

- Capture existing post/report/punishment DB fixtures.
- Capture current post signature fixtures.
- Capture remote enforcement integration behavior.
- Record v2 discovery and command fixtures for archival reference.

Exit gate: all data that must survive has a deterministic fixture.

### Phase 1: Article feed primitives

- Implement event/head models, encoders, hashes, and signature verification.
- Implement feed SQLite schema and body CAS.
- Implement atomic local append and remote range acceptance.
- Add canonical vectors and adversarial parser tests.

Exit gate: no network integration; all primitive/store tests pass.

### Phase 2: Immutable local articles

- Add article projections.
- Implement ARTICLE publication/get/list/search locally.
- Implement cancel, supersede, restore, and purge projection semantics.
- Stop hard-deleting or mutating newly created v3 articles.
- Keep direct internal reads of the old databases/files available only to the
  migration code. Do not keep v2 wire handlers once the v3 opcode table is
  activated.

Exit gate: local board behavior and immutability tests pass.

### Phase 3: Protocol v3 and clients

- Freeze compact command table.
- Update discovery and HTTP protocol version.
- Add builders/parsers/client models.
- Retarget MCP post tools.
- Publish deterministic v3 wire fixtures.

Exit gate: every retained/new command round-trips through HTTP.

### Phase 4: Feed federation

- Implement FEED_HEAD/EVENTS/HEADS and ARTICLE_BODY exports.
- Implement direct and relayed feed sync.
- Add subscriptions, body policies, scheduler, and backoff.
- Preserve SSRF, TOFU, rotation, and response verification.

Exit gate: multi-node ordinary article/cancel propagation passes.

### Phase 5: Moderation controls

- Implement RULE, REPORT, PUNISHMENT, and revocation event validators.
- Build materialized query/effective-ban projections.
- Retarget high-level client/MCP moderation methods.
- Keep legacy remote punishment union during transition.

Exit gate: four-node enforcement/archive tests pass.

### Phase 6: Authoritative migration

- Migrate local posts and moderation history.
- Verify counts, signatures, references, and bodies.
- Rebuild remote caches from v3 origins.
- Provide operator migration/status reporting.

Exit gate: migration fixtures pass and configured enforcement origins are
accounted for.

### Phase 7: Remove old protocol and registries

- Delete old mutable handlers and codecs.
- Delete report/punishment registry services, sync paths, and files.
- Remove obsolete config and capabilities.
- Stop constructing old stores.
- Preserve archive files without runtime use.

Exit gate: no production import or opcode references removed systems; full test
suite and packaging pass.

### Phase 8: Hardening and documentation

- Fuzz event/head parsers.
- Load-test first sync and body fetch limits.
- Document operator backup, migration, feed subscription, and purge semantics.
- Document that cancellation is not erasure and origin signatures do not prove
  current body availability.

Exit gate: security invariants reviewed and no unresolved critical findings.

## 25. Explicit Non-Goals

- Replacing the user identity Merkle registry.
- Building an article Merkle tree.
- Guaranteeing that any server retains article bodies forever.
- Forcing independent peers to honor purge requests.
- Proving freshness when every reachable peer withholds newer signed heads.
- Implementing global consensus over moderation policy.
- Making all imported punishment feeds automatically enforceable.
- Federated author-key rotation.
- Body cache eviction/garbage collection beyond explicit local purge.
- Full-text search across bodies not locally cached.
- Reconstructing already hard-deleted pre-v3 posts without evidence.
- Preserving v2 wire compatibility.
- Redesigning UME storage.

## 26. Definition of Done

The redesign is complete when:

1. New articles are immutable origin-signed feed events.
2. User-authored events carry valid durable author signatures.
3. Every board has a contiguous signed metadata feed.
4. Relays can cache/export multi-origin feed metadata and bodies without gaining
   origin authority.
5. Cancellations hide content from default views without deleting retained data.
6. Direct retrieval distinguishes unknown, canceled, purged, and unavailable.
7. Edits use superseding articles rather than mutation.
8. Rules, reports, punishments, and revocations are typed feed events.
9. Effective bans derive from configured enforcement feeds and block writes.
10. The report and punishment Merkle registries and their ten commands are gone.
11. The user identity Merkle registry continues to work unchanged.
12. Import policy is feed-specific and separate from enforcement and export ACLs.
13. Existing authoritative posts and moderation history migrate without forged
    signatures or lost known bodies.
14. Remote cached legacy data is never re-originated locally.
15. Protocol v3 clients, server, sync, and MCP surfaces use the compact command
    set.
16. All security invariants and integration scenarios pass.
17. `uv run pytest -x -q` and packaging complete successfully.
