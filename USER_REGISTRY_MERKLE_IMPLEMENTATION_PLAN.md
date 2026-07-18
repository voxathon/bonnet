# Authenticated User Registry Peering Implementation Plan

## 1. Purpose

This document is an implementation handoff for replacing the currently broken,
unattested `LIST_USERS` federation path with authenticated, partial user-registry
synchronization.

The design keeps the existing fixed-width userfile record unchanged. The userfile
record is 1079 bytes, not 832 bytes:

```text
4 * 255-byte strings = 1020
public key           =   32
sequence number      =    8
flags                =    3
creation timestamp   =    8
relay timestamp      =    8
total                = 1079 bytes
```

The origin commits exact 1079-byte records to a per-origin Merkle registry. It
signs registry heads when a snapshot is constructed. Relays cache and forward
the signed head, original attested record bytes, and proofs without needing to
add signatures to the userfile itself.

This plan also repairs the HTTP authorization and parser defects that currently
prevent federation from completing.

## 2. Current State and Confirmed Defects

### 2.1 User sync crashes

`src/net/sync.py:317-369` stores the command response in `payload`, but reads an
undefined variable named `response` throughout `_sync_users`. Any non-empty user
response raises `NameError` before a record is ingested.

The same defect exists in `_sync_reports` at `src/net/sync.py:371-454`.

### 2.2 Sync requests are rejected before command dispatch

`SyncManager._do_sync_from_peer` signs requests with `server_identity`, as the
federation design in `PROTOCOL_RENOVATION_PLAN.md` requires. However,
`src/net/http_server.py:320-326` rejects every unknown signed key except for the
`REGISTER` command.

This prevents an unregistered peer server from executing public commands such as
`BOARD_LIST`, `LIST_USERS`, and `REPORT_LIST_SINCE`.

The correct behavior is:

* Verify the request signature normally.
* Resolve a registered UME user when one exists.
* Permit an unknown but valid signer to execute commands in
  `config.public_commands` as an unregistered principal.
* Continue rejecting unknown signers for non-public commands other than
  `REGISTER`.

Do not switch federation to the shared anonymous private key. Federation should
remain signed by each server's identity.

### 2.3 `REPORT_LIST_SINCE` contradicts public-command configuration

Command `0x54` is in the default `public_commands` set at
`src/core/config.py:90-92`, but `_cmd_report_list_since` requires
`ctx.is_registered` at `src/net/commands.py:1480-1483`.

Remove that handler-level registration requirement or introduce a clearly
defined peer principal. The minimal consistent fix is to rely on the public
command gate and remove the contradictory check.

### 2.4 User records are currently unauthenticated

`LIST_USERS` carries only:

* `username`
* `registrar`
* `record_origin`
* `relay`
* `publickey`

It carries no origin signature, signed registry head, timestamps, flags, or
proof. A relay can therefore claim unsigned records for an arbitrary
`record_origin`.

### 2.5 User sequence numbers are local

`User.seq_numbr` is assigned by the receiving UME and is used as a local record
identifier. `upsert_remote_user` assigns `self._next_seq` on insertion and
preserves the receiver's existing sequence number on update.

Do not reinterpret this field as the federated registry version. This design
introduces a separate `registry_seq` for signed registry heads.

### 2.6 There is no user-sync test coverage

`tests/test_sync.py` covers SSRF controls and board signature verification but
does not execute a non-empty `_sync_users` or `_sync_reports` response. Existing
UME tests exercise `upsert_remote_user` directly and therefore do not expose the
federation parser failure.

## 3. Goals

The implementation must provide all of the following:

1. Keep the existing 1079-byte userfile record layout unchanged.
2. Authenticate user records with the authoritative origin's Ed25519 key.
3. Allow relays to forward origin records without becoming their authority.
4. Support partial synchronization by comparing Merkle subtrees.
5. Support standalone inclusion and non-inclusion proofs.
6. Detect malformed records, tampered records, invalid roots, and invalid proofs.
7. Detect rollback relative to the highest registry sequence already accepted.
8. Detect signed equivocation when the same origin signs different roots for the
   same `registry_seq`.
9. Preserve local UME sequence allocation and local moderation flags.
10. Include creation timestamps in signed registry transfer and legacy text
    export.
11. Preserve existing userfiles without an in-place migration.
12. Add real two-server federation tests.

## 4. Non-Goals

The first implementation does not need to provide:

* Global consensus about the newest registry head.
* A blockchain or proof-of-work mechanism.
* Transfer of administrator, moderator, or banned status between origins.
* A changed userfile record size.
* Trust in a relay's signature as a replacement for the origin signature.
* Arbitrarily deep relay-of-relay trust chains.
* Append-only user history forever.

An origin is allowed to update or remove its own current user records. Signed
heads authenticate snapshots; they are not automatically an append-only
transparency log.

## 5. Trust and Authority Model

### 5.1 Origin authority

Only an origin may authoritatively publish records whose decoded
`record_origin` equals that origin.

When building the local authoritative registry for `config.origin`, include only
non-zero records satisfying:

```python
user.record_origin == config.origin
```

Never place relayed records into the local origin's signed registry.

### 5.2 Relay role

A relay may cache and serve:

* the origin-signed registry head;
* exact attested record bytes;
* Merkle nodes and proofs needed to verify those bytes.

The relay signs the HTTP response envelope with its own server identity. The
consumer must still verify the registry head with the pinned key for the record
origin.

### 5.3 Key pinning

Use `TrustStore` from `src/core/trust.py` to resolve the origin key. A registry
head is acceptable only when:

* the origin key is pinned or accepted through the existing TOFU policy;
* the head signature verifies with that key;
* the origin in the signed payload matches the requested origin;
* the registry sequence is not a rollback;
* the same sequence has not already been seen with a different signed head.

Key rotation continues to use the existing old-key-authorized rotation process.

### 5.4 Freshness limitation

A signed sequence prevents rollback only after a client has observed a newer
sequence. A first-contact client cannot know that a relay is serving the newest
valid head unless it compares heads from additional peers or contacts the origin.

Document this limitation. Later gossip can exchange `(origin, registry_seq,
head_hash)` tuples to improve stale-head detection.

## 6. Raw Record Semantics

### 6.1 Commit exact bytes

The origin leaf value commits the exact 1079 bytes currently stored in its
userfile. Snapshot construction must scan raw fixed-width slots rather than
decode and re-encode every user. Decode only for validation and authority
filtering.

This avoids accidental canonicalization changes caused by UTF-8 replacement,
truncation, padding, or future decoder behavior.

### 6.2 Fields authenticated by the origin

Hashing the complete record authenticates:

* username;
* registrar;
* record origin;
* origin-local record sequence;
* public key;
* origin's relay field at snapshot time;
* origin's flags at snapshot time;
* creation time;
* relay time.

The receiver must not blindly persist all those values into its local UME.

### 6.3 Receiver normalization

After proof verification, parse the attested bytes and insert/update the local
UME using these rules:

| Attested field | Receiver behavior |
|---|---|
| `username` | Preserve |
| `registrar` | Preserve |
| `record_origin` | Preserve; must equal signed-head origin |
| `publickey` | Preserve; must be exactly 32 bytes |
| `creation_time` | Correct to origin's attested value on insert and update; bounds-checked |
| `seq_numbr` | Ignore; allocate/preserve receiver-local sequence |
| `relay` | Replace with the directly contacted peer hostname |
| `relay_time` | Set to receiver ingestion/update time |
| `is_administrator` | Do not federate; set false for new remote users |
| `is_moderator` | Do not federate; set false for new remote users |
| `is_banned` | Do not federate; preserve local punishment state |

The original 1079 attested bytes must be retained in the registry sidecar so the
receiver can relay the origin proof later. The normalized local UME record will
not hash to the origin root because its local sequence, relay metadata, and flags
are intentionally different.

### 6.4 UME API change

Extend `Ume.upsert_remote_user` with an optional origin creation timestamp:

```python
def upsert_remote_user(
    self,
    username: str,
    registrar: str,
    publickey: bytes,
    record_origin: str,
    relay: str,
    creation_time: int | None = None,
) -> int:
```

On insert, use the supplied `creation_time`. On update (same username, same
origin), overwrite the local `creation_time` with the origin's latest attested
value — this is a correction policy, not first-seen immutable. Apply bounds
checking: reject timestamps in the future relative to receiver wall-clock plus
clock-skew tolerance, and reject corrections that exceed a configurable
threshold (`max_creation_time_correction`). Never overwrite local moderation
flags during remote updates.

## 7. Merkle Structure

### 7.1 Recommended structure

Use a 256-bit compressed sparse Merkle tree (CSMT) per origin.

Logically, the tree has a fixed depth of 256. Physically, store only non-default
nodes. Proofs encode a 256-bit bitmap and only the non-default sibling hashes,
which keeps typical proofs near a few hundred bytes rather than the 8192 bytes
required by an uncompressed 256-level proof.

This structure provides:

* deterministic roots independent of insertion order;
* localized insert, update, and delete operations;
* inclusion and non-inclusion proofs;
* efficient subtree comparison;
* no index shifts when users are added or removed;
* constructive physical expansion as new key paths are populated.

### 7.2 Hash algorithm

Use SHA-256 initially. Domain-separate every hash type.

Define constants in the new registry module rather than scattering literal
prefixes through the code.

```text
EMPTY_LEAF = SHA256("bonnet-user-registry-empty-v1")

key = SHA256(
    "bonnet-user-registry-key-v1" ||
    uint16_be(len(origin_utf8)) || origin_utf8 ||
    uint16_be(len(username_utf8)) || username_utf8
)

value_hash = SHA256(
    "bonnet-user-registry-record-v1" || raw_1079_byte_record
)

leaf_hash = SHA256(
    "bonnet-user-registry-leaf-v1" || key || value_hash
)

node_hash = SHA256(
    "bonnet-user-registry-node-v1" ||
    uint16_be(level) || left_hash || right_hash
)
```

Including the level prevents structurally different nodes from sharing the same
preimage semantics.

### 7.3 Default hashes

Precompute default hashes from depth 256 to root:

```text
default[256] = EMPTY_LEAF
default[level] = node_hash(level, default[level + 1], default[level + 1])
```

Do not duplicate the final real leaf to fill a tree. Sparse-tree defaults are
unambiguous.

### 7.4 Key uniqueness

The current UME enforces username uniqueness. Registry construction must also
reject duplicate keys rather than silently allowing the last record to win.

The origin is included in the key derivation so identical usernames at different
origins occupy unrelated paths in relay aggregate tooling.

### 7.5 Proof format

An inclusion or non-inclusion proof contains:

```text
key                  32 bytes
value_hash           32 bytes for inclusion; omitted for non-inclusion
non_default_bitmap   32 bytes, one bit per tree level
sibling_count         2 bytes, big-endian
sibling_hashes       sibling_count * 32 bytes
```

Sibling hashes are ordered from leaf level toward the root. The verifier uses
the bitmap to substitute precomputed defaults at omitted levels.

Reject proofs when:

* the bitmap popcount does not equal `sibling_count`;
* a sibling count exceeds 256;
* proof bytes contain trailing or truncated data;
* the reconstructed root differs from the signed head;
* the record-derived key differs from the requested key;
* record length is not exactly 1079 bytes.

### 7.6 Omission detection

An inclusion proof proves that one supplied record belongs to the signed root.
It does not prove that a relay supplied every record.

Complete and partial synchronization must therefore traverse or compare the
authenticated tree:

1. Start with the verified signed root.
2. Compare the local cached origin root to the remote root.
3. Request child hashes for differing non-default prefixes.
4. Recurse only into differing branches.
5. Request records at differing leaves.
6. Verify every child relationship and final leaf against the expected root.
7. Finish only when every differing non-default branch has been resolved.

A relay that omits a branch cannot produce child hashes matching the signed
root. A relay may refuse to finish the sync, but that is detectable as an
incomplete sync rather than accepted as a complete registry.

The signed `leaf_count` provides an additional completion invariant.

## 8. Signed Registry Head

### 8.1 Head fields

Each signed head contains:

| Field | Encoding |
|---|---|
| format version | `uint8`, initially `1` |
| hash algorithm | `uint8`, initially `1` for SHA-256 |
| origin | `uint16 length + UTF-8 bytes` |
| registry sequence | `uint64_be` |
| snapshot timestamp | `int64_be` Unix seconds |
| leaf count | `uint64_be` |
| Merkle root | 32 bytes |
| previous head hash | 32 bytes; all zero for sequence 1 |
| signature | 64-byte Ed25519 signature |

### 8.2 Signature payload

Sign exactly:

```text
"bonnet-user-registry-head-v1" ||
format_version ||
hash_algorithm ||
uint16_be(len(origin_utf8)) || origin_utf8 ||
uint64_be(registry_seq) ||
int64_be(snapshot_timestamp) ||
uint64_be(leaf_count) ||
merkle_root ||
previous_head_hash
```

Use `Identity.sign` and `Identity.verify` from `src/core/crypto.py`.

### 8.3 Sequence rules

`registry_seq` is a per-origin, persistent, monotonically increasing snapshot
version. It is unrelated to `User.seq_numbr`.

Rules:

* First generated head uses sequence 1.
* Increment only when the authoritative registry root changes.
* Repeated requests with no mutation return the same head.
* Store the sequence before publishing the signed head.
* Never reuse a sequence for a different root.
* Reject a received sequence lower than the highest accepted sequence.
* Accept an identical already-known sequence idempotently.
* Record an equivocation error if the same `(origin, registry_seq)` has a
  different head hash or signature payload.

### 8.4 Previous-head linkage

`previous_head_hash` is:

```text
SHA256("bonnet-user-registry-signed-head-v1" || encoded_head_with_signature)
```

This creates an authenticated head chain. It proves sequence linkage when all
intermediate heads are available, but it does not prove that a mutable snapshot
changed only by additions. Do not call it a standard append-only Merkle
consistency proof.

## 9. Snapshot Construction

### 9.1 Lazy construction

The user requested signatures to be calculated at export time rather than stored
inside each userfile record. Implement snapshot generation lazily:

* UME mutations mark the authoritative registry dirty.
* A head/export request checks the dirty generation.
* If unchanged, return the existing signed head.
* If dirty, capture a consistent raw-record view, rebuild changed tree state,
  persist the new head, and clear the captured dirty generation.
* If another mutation occurs during construction, leave the registry dirty so a
  subsequent request creates another head.

### 9.2 Consistent raw scan

Add an internal UME method that returns raw records while holding the UME lock:

```python
def snapshot_raw_records(self) -> list[bytes]:
```

Requirements:

* Read exact `RECORD_SIZE` chunks.
* Ignore all-zero deleted slots.
* Reject or log a trailing partial record.
* Decode each record for validation.
* Include only records native to `config.origin` when building the authoritative
  registry.
* Return immutable `bytes` values.

Do not expose a generator that continues reading after the lock is released.

### 9.3 Mutation notification

Notify the registry service after successful changes in:

* `Ume.put`;
* `Ume.upd` when an authenticated field changes;
* `Ume.delete`;
* `Ume.ensure_root_user` through its existing put/update calls.

Remote upserts must update the relay cache, not the local origin registry.

Avoid rebuilding the entire Merkle tree while holding the userfile lock.

## 10. Sidecar Persistence

Create `src/core/user_registry.py` and a SQLite database under `data_dir`, for
example `user_registry.db`.

Keep registry persistence separate from `TrustStore`; origin-key trust and
registry snapshots have different responsibilities and lifecycles.

### 10.1 Proposed schema

```sql
CREATE TABLE registry_heads (
    origin              TEXT NOT NULL,
    registry_seq        INTEGER NOT NULL,
    snapshot_timestamp  INTEGER NOT NULL,
    leaf_count          INTEGER NOT NULL,
    merkle_root         BLOB NOT NULL,
    previous_head_hash  BLOB NOT NULL,
    signature           BLOB NOT NULL,
    encoded_head        BLOB NOT NULL,
    head_hash           BLOB NOT NULL,
    is_authoritative    INTEGER NOT NULL DEFAULT 0,
    accepted_at         INTEGER NOT NULL,
    PRIMARY KEY (origin, registry_seq)
);

CREATE UNIQUE INDEX registry_heads_origin_head_hash
    ON registry_heads(origin, head_hash);

CREATE TABLE registry_records (
    origin          TEXT NOT NULL,
    registry_key    BLOB NOT NULL,
    username        TEXT NOT NULL,
    raw_record      BLOB NOT NULL,
    value_hash      BLOB NOT NULL,
    source_seq      INTEGER NOT NULL,
    PRIMARY KEY (origin, registry_key)
);

CREATE TABLE registry_nodes (
    origin          TEXT NOT NULL,
    registry_seq    INTEGER NOT NULL,
    level           INTEGER NOT NULL,
    prefix          BLOB NOT NULL,
    node_hash       BLOB NOT NULL,
    left_hash       BLOB,
    right_hash      BLOB,
    PRIMARY KEY (origin, registry_seq, level, prefix)
);

CREATE TABLE registry_state (
    origin                  TEXT PRIMARY KEY,
    highest_accepted_seq    INTEGER NOT NULL,
    current_head_hash       BLOB NOT NULL,
    current_merkle_root     BLOB NOT NULL,
    current_leaf_count      INTEGER NOT NULL,
    dirty_generation        INTEGER NOT NULL DEFAULT 0,
    snapshotted_generation  INTEGER NOT NULL DEFAULT 0
);
```

SQLite integers are signed 64-bit. Reject registry sequences above
`2^63 - 1` at the persistence boundary even though the wire field is unsigned.

### 10.2 Retention

For the first implementation:

* Keep every signed head indefinitely — needed for equivocation and linkage
  proofs.
* Keep Merkle node sets for the current generation and the immediately previous
  generation per origin to support interrupted synchronization.
* Garbage-collect node sets for older generations.
* Keep raw attested bytes (`registry_records`) for any key referenced by a
  retained head; drop rows referenced only by pruned generations.
* Deleted-user records are removed together with their pruned node sets.

Future disk optimization (not in the first release): key `registry_nodes` by
`node_hash` with a refcount instead of `(origin, registry_seq, level, prefix)`.
Consecutive snapshots share almost all nodes, so 100 snapshots of a mostly-stable
registry cost barely more than one. This is content-addressed deduplication — the
same structural sharing trick git uses. Defer until disk usage is actually a
problem and correctness tests exist.

### 10.3 Atomic acceptance

Accepting a remote snapshot must be one transaction:

1. Re-check highest accepted sequence.
2. Re-check same-sequence equivocation.
3. Store the verified records/nodes.
4. Store the signed head.
5. Advance `registry_state`.
6. Commit.

Only after this transaction succeeds should normalized changes be applied to
UME. If UME application then fails, retain enough sidecar state to retry
idempotently.

An alternative is an explicit `pending_apply` state in `registry_state`; prefer
that if crash recovery is implemented in the first version.

## 11. Protocol Additions

Keep `LIST_USERS` (`0x03`) for legacy listing and user interfaces. Do not use it
as the authoritative federation mechanism after registry sync is available.

The following opcodes are currently unused and are proposed for protocol v2:

| Opcode | Name | Purpose |
|---|---|---|
| `0x05` | `USER_REGISTRY_HEAD` | Fetch a signed head for one origin |
| `0x06` | `USER_REGISTRY_NODES` | Fetch child hashes for a bounded prefix batch |
| `0x07` | `USER_REGISTRY_RECORDS` | Fetch exact records and optional compressed proofs |
| `0x08` | `USER_REGISTRY_HEADS` | List cached origin heads exposed by a relay |
| `0x09` | `USER_REGISTRY_HEAD_CHAIN` | Fetch bounded previous heads for linkage checks |

Confirm these opcode assignments against any external protocol registry before
merging.

### 11.1 Common constraints

* Origins and usernames are UTF-8 with a `uint16` byte length.
* Prefix lengths are 0 through 256 bits.
* Counts are bounded before allocation.
* Record length must equal 1079.
* Batch response size must respect `config.max_request_size` and a dedicated
  registry response limit.
* Parsers reject truncation and trailing bytes.
* All integer fields use big-endian network byte order.
* HTTP response-envelope signatures remain mandatory.

### 11.2 `USER_REGISTRY_HEAD` (`0x05`)

Request:

```text
opcode               uint8
origin_length        uint16_be
origin               UTF-8 bytes
requested_seq        uint64_be; zero means latest
```

Response payload:

```text
encoded_head_length  uint16_be
encoded_signed_head  bytes
```

The directly authoritative origin may lazily construct a new head. A relay may
return only a head already present in its cache.

### 11.3 `USER_REGISTRY_NODES` (`0x06`)

Request:

```text
opcode               uint8
origin_length        uint16_be
origin               UTF-8 bytes
registry_seq         uint64_be
prefix_count         uint16_be
repeated:
  prefix_bit_length  uint16_be
  prefix_byte_length uint8
  prefix_bytes       ceil(prefix_bit_length / 8)
```

Response payload:

```text
node_count           uint16_be
repeated:
  prefix_bit_length  uint16_be
  prefix_byte_length uint8
  prefix_bytes       bytes
  node_kind          uint8; 0=default, 1=branch, 2=leaf
  node_hash          32 bytes
  if branch:
    left_hash        32 bytes
    right_hash       32 bytes
  if leaf:
    registry_key     32 bytes
    value_hash       32 bytes
```

The client verifies that each returned child pair hashes to the expected parent.
Unknown heads or pruned sequences return a protocol error rather than silently
falling back to a different sequence.

### 11.4 `USER_REGISTRY_RECORDS` (`0x07`)

Request:

```text
opcode               uint8
origin_length        uint16_be
origin               UTF-8 bytes
registry_seq         uint64_be
record_count         uint16_be
include_proofs       uint8
registry_keys        record_count * 32 bytes
```

Response payload:

```text
record_count         uint16_be
repeated:
  registry_key       32 bytes
  present            uint8
  if present:
    record_length    uint16_be; must be 1079
    raw_record       1079 bytes
  if include_proofs:
    proof_length     uint16_be
    proof            compressed proof bytes
```

Use multiproofs later if per-record proofs become a significant bandwidth cost.
The subtree traversal path does not require a full standalone proof for every
record because each expected leaf hash is already authenticated through the
traversal.

### 11.5 `USER_REGISTRY_HEADS` (`0x08`)

This command advertises what a relay has cached. It does not confer authority.

Request:

```text
opcode               uint8
offset               uint32_be
limit                uint16_be
```

Response payload:

```text
head_count           uint16_be
repeated:
  encoded_head_length uint16_be
  encoded_signed_head bytes
```

Clamp `limit` to a configured maximum.

### 11.6 `USER_REGISTRY_HEAD_CHAIN` (`0x09`)

Request a bounded descending sequence of signed heads to connect a newly
observed head to a locally stored head. The client verifies each
`previous_head_hash`.

This proves head linkage, not append-only set consistency.

## 12. Sync Algorithm

Replace `_sync_users` with registry synchronization once both peers advertise
support.

### 12.1 Capability handling

Add registry protocol capability information to discovery, for example:

```json
{
  "protocol_versions": [2],
  "capabilities": ["user-registry-merkle-v1"]
}
```

Behavior:

* If the peer advertises `user-registry-merkle-v1`, use registry sync.
* During a limited transition period, optionally use fixed legacy `LIST_USERS`
  sync only for explicitly trusted peers.
* Do not silently treat unsigned legacy data as equivalent to verified registry
  data.

### 12.2 Head acquisition

1. Apply existing hostname and DNS SSRF gates.
2. Establish the signed HTTP connection with `server_identity`.
3. Verify and pin the directly contacted peer key.
4. Fetch the requested origin head.
5. Resolve the origin key from `TrustStore`.
6. Verify the signed head payload.
7. Enforce rollback and equivocation rules.
8. If the root equals the local cached root, finish without fetching records.

### 12.3 Subtree comparison

Maintain a queue of differing prefixes, beginning with the root prefix.

For each bounded batch:

1. Request node descriptions from the peer.
2. Verify every node against the expected parent hash.
3. Skip subtrees whose remote hash equals the cached local hash.
4. Record default remote subtrees as deletions of previously cached keys.
5. Queue differing branch children.
6. Queue differing leaf keys for record retrieval.
7. Enforce maximum nodes, depth, response bytes, and wall-clock duration.

The sync is complete only when the queue is empty and the reconstructed root and
leaf count equal the signed head.

### 12.4 Record application

For each changed leaf:

1. Fetch exact raw record bytes.
2. Confirm length is 1079.
3. Recompute registry key, value hash, and leaf hash.
4. Decode the record strictly.
5. Confirm `record_origin == signed_head.origin`.
6. Confirm public key length is 32 bytes.
7. Store raw attested bytes in the sidecar transaction.
8. Normalize and apply to UME using `upsert_remote_user`.

For removed leaves:

1. Confirm the removed sidecar record belonged to this origin.
2. Remove it from the sidecar's current origin view.
3. Delete the local UME user only when its current `record_origin` still equals
   that origin and no newer accepted record replaced it.
4. Never delete a conflicting local-origin user.

### 12.5 Conflict behavior

The current UME is globally keyed by username. Until that schema is changed:

* Same username and same origin: update.
* Same username and different origin: retain existing record and report a
  conflict.
* Still retain the verified foreign record in the sidecar so it can be relayed
  and inspected even when it cannot be materialized in UME.

Do not allow first-seen relay order to silently erase conflict evidence.

### 12.6 Cancellation and failure

An invalid proof or signature aborts that origin's sync without advancing the
accepted head. A malformed record must not partially advance registry state.

The background worker should log the origin, peer, sequence, and failure class,
then continue servicing later queued peers.

## 13. Relay Forwarding Model (No Aggregate CSMT)

### 13.1 Decision: direct forwarding only

A relay aggregate CSMT is permanently excluded from this design. Relays cache
and forward individual origin-signed heads, exact attested record bytes, and
Merkle proofs. The consumer verifies each origin head against its pinned origin
key. The `USER_REGISTRY_HEADS` (`0x08`) listing command advertises what a relay
has cached, but it does not confer authority.

Rationale: aggregation manufactures new authorities, and silent omission only
fools consumers who do not know what they are looking for.

### 13.2 Constructive expansion

Adding another origin to a relay's cache does not alter any existing origin tree
or invalidate that origin's proofs. Each origin registry is independent. This is
the safe form of constructive expansion across relays — no cross-origin
aggregation structure is built.

```text
raw record
  -> origin CSMT leaf and proof
  -> origin-signed registry head
  -> optional relay aggregate CSMT leaf
  -> relay-signed aggregate head
```

The relay aggregate key is:

```text
SHA256("bonnet-user-registry-relay-origin-v1" || origin_utf8)
```

The aggregate value commits the full origin signed-head hash.

### 13.3 Avoid arbitrary nesting

A relay may learn an origin head from another relay, but it must cache that
origin head directly and serve it as an individual origin-signed head — never
as part of a relay aggregate structure. The origin signature remains mandatory
at the bottom of every chain.

## 14. Legacy Export Changes

The signed registry transfer already includes `creation_time` and `relay_time`
inside the exact 1079-byte record.

Update `Ume.export` so the human-readable export includes timestamps as explicit
tab-separated attributes:

```text
!<username@registrar>[record_origin|relay]:publickey_hex\tcreation_time=...\trelay_time=...
```

The leading `!` remains the local banned marker. Document that local ban and
privilege flags are not federated registry authority.

No import parser in this repository consumes this format, so there is no in-repo
breakage. The timestamp fields are trailing tab-separated attributes, making the
change a backward-compatible extension. No `export_v2` method is added; the
existing `Ume.export` is modified in place.

## 15. Required Code Changes

### 15.1 New files

`src/core/user_registry.py`

* Domain-separated hash helpers.
* Default sparse-tree hash computation.
* Registry key and record hash functions.
* Compressed proof encoding and verification.
* CSMT node update and traversal.
* Signed-head encoding, signing, decoding, and verification.
* SQLite-backed `UserRegistryStore`.
* Snapshot build and remote snapshot acceptance transactions.

`tests/test_user_registry.py`

* Core data-structure and persistence tests.

`tests/test_http_sync.py`

* Real two-server federation tests.

### 15.2 Existing files

`src/engine/ume.py`

* Keep all record constants and `RECORD_SIZE` unchanged.
* Add a raw snapshot method.
* Add mutation notifications.
* Extend remote upsert to accept origin creation time.
* Preserve receiver-local sequence and moderation state.
* Add timestamps to text export or add a versioned export method.

`src/core/config.py`

* Add registry database path and limits.
* Add registry batch-size, node-count, and timeout settings.
* Add the registry read commands to default public commands.

`src/core/trust.py`

* Keep origin key pinning here.
* Do not place Merkle nodes in this database.
* Optionally expose a helper that verifies a signed registry head against the
  pinned origin key.

`src/net/http_server.py`

* Permit unknown valid signers to invoke public commands.
* Continue rejecting unknown signers for non-public commands.
* Advertise registry capability.
* Ensure discovery is itself verified by clients before trust is established.

`src/net/commands.py`

* Add registry command names, dispatch, and handlers.
* Remove the contradictory registration check from public report-list sync.
* Enforce strict request bounds before parsing batch payloads.

`src/client/protocol.py`

* Add registry opcodes, builders, strict parsers, and proof encoders.
* Reuse parsers in sync code rather than manually decoding the same payload.

`src/client/models.py`

* Add typed models for registry heads, nodes, proofs, and attested records if
  Pydantic models remain the client convention.

`src/client/http.py`

* Add high-level registry methods.
* Expose peer capabilities after discovery.
* Use persistent trust storage for federation clients.

`src/net/sync.py`

* Immediately fix `response` versus `payload` in users and reports.
* Replace manual parsers with protocol helpers.
* Add registry-based user sync.
* Preserve board/report origin verification.
* Add bounded subtree traversal and cancellation.

`src/app/server.py`

* Construct `UserRegistryStore` using `data_dir`.
* Connect it to UME and `SyncManager`.
* Close it during shutdown.

## 16. Configuration Defaults

Add conservative defaults such as:

```toml
[registry]
enabled = true
db_path = "user_registry.db"
max_heads_per_response = 100
max_nodes_per_request = 256
max_records_per_request = 64
max_proof_bytes = 16384
max_sync_nodes = 1000000
max_sync_seconds = 30
retain_previous_node_sets = 1
max_creation_time_correction = 86400
allow_legacy_unsigned_user_sync = false
```

Resolve `db_path` relative to `data_dir` using the existing configuration path
rules.

## 17. Implementation Phases

### Phase 0: Lock down behavior with failing tests

Add tests that demonstrate:

* non-empty `_sync_users` currently raises because `response` is undefined;
* non-empty `_sync_reports` has the same problem;
* an unregistered server identity cannot currently call a public command;
* `REPORT_LIST_SINCE` rejects the public principal despite configuration.

Do not weaken assertions merely to preserve current broken behavior.

### Phase 1: Repair existing federation plumbing

* Replace `response` references with parser-helper use.
* Fix public-command handling for unknown valid signers.
* Fix the report-list authorization contradiction.
* Add focused tests for users and reports.

This phase establishes a functional transport for the new registry commands. If
legacy user sync remains enabled during development, label its data unverified.

### Phase 2: Implement pure Merkle primitives

Implement without networking or SQLite first:

* domain-separated hashes;
* default hashes;
* insert/update/delete;
* deterministic root;
* compressed inclusion proof;
* compressed non-inclusion proof;
* strict proof parser;
* subtree child verification.

Use property-style randomized tests where practical.

### Phase 3: Implement signed heads and sidecar storage

* Define canonical binary encoding.
* Sign and verify heads.
* Add SQLite schema and transactions.
* Add rollback and equivocation enforcement.
* Bootstrap sequence 1 from existing native records.
* Add dirty-generation snapshot construction.

No existing userfile migration is required.

### Phase 4: Add server/client protocol commands

* Add capability discovery.
* Implement head, node, record, head-list, and head-chain commands.
* Add parser bounds and protocol fixtures.
* Add HTTP round-trip tests for every new command.

### Phase 5: Integrate registry synchronization

* Fetch and verify heads.
* Compare and traverse differing subtrees.
* Fetch and verify records.
* Atomically accept sidecar state.
* Normalize records into UME.
* Reconcile removals.
* Resume interrupted apply operations safely.

### Phase 6: Add relay support

* Serve cached foreign origin heads and proofs.
* Add relay head listing (`USER_REGISTRY_HEADS` `0x08`).
* No relay aggregate CSMT — direct forwarding only (see Section 13).
* Test origin -> relay A -> relay B transfer while preserving origin proofs.

### Phase 7: Disable unsigned federation fallback

After all supported peers advertise registry capability:

* set `allow_legacy_unsigned_user_sync = false` by default;
* keep `LIST_USERS` only as a listing API;
* log and reject attempts to treat legacy lists as verified registry state.

## 18. Test Plan

### 18.1 Record and UME tests

* Confirm `RECORD_SIZE == 1079`.
* Confirm exact raw bytes round-trip through `User.decode` and `User.encode` for
  canonical records.
* Confirm remote insert gets a unique local sequence.
* Confirm remote update preserves that local sequence.
* Confirm remote update preserves local banned/admin/moderator state.
* Confirm origin creation time is corrected to the attested value on update.
* Confirm out-of-bounds creation_time corrections (future timestamps, excessive
  deltas) are rejected.
* Confirm relay time is local.
* Confirm text export includes timestamps.

### 18.2 Merkle primitive tests

* Empty root is deterministic.
* Insertion order does not change the root.
* One changed byte changes the root.
* Insert, update, and delete affect only the expected path.
* Valid inclusion proof verifies.
* Valid non-inclusion proof verifies.
* Modified record, key, sibling, bitmap, level, and root fail verification.
* Truncated and trailing proof bytes fail parsing.
* Compressed and full proofs reconstruct the same root.
* Duplicate registry keys are rejected.

### 18.3 Signed-head tests

* Signature round-trip succeeds.
* Modification of every signed field fails verification.
* Wrong origin key fails verification.
* Lower sequence is rejected.
* Identical sequence/head is idempotent.
* Same sequence/different root is recorded as equivocation and rejected.
* Previous-head linkage verifies.
* A missing intermediate head is reported distinctly from an invalid chain.

### 18.4 Persistence tests

* First bootstrap creates sequence 1.
* No mutation returns the same signed head.
* Mutation increments the sequence exactly once.
* Concurrent snapshot requests publish one head for one generation.
* Mutation during snapshot leaves the registry dirty.
* Crash/reopen retains highest accepted sequence.
* Failed transaction does not advance state.
* Pending UME apply resumes idempotently.

### 18.5 Protocol tests

* Builders match frozen binary fixtures.
* Strict parsers reject every truncated field boundary.
* Batch limits are enforced before allocation.
* Unknown and pruned sequences return errors.
* Public registry commands work for an unknown valid server signer.
* Invalid HTTP signatures remain rejected.

### 18.6 Sync tests

* Empty-to-full initial sync succeeds.
* Equal roots transfer no records.
* One update transfers one changed leaf path.
* One insertion and one deletion reconcile correctly.
* Tampered record is rejected.
* Tampered node is rejected.
* Tampered signed head is rejected.
* Rollback is rejected.
* Same-sequence equivocation is rejected.
* A relay omitting a subtree cannot complete sync.
* A conflicting username remains in sidecar without overwriting local authority.
* SSRF and TOFU failures occur before registry ingestion.

### 18.7 End-to-end topology tests

Create real ASGI/HTTP test setups for:

* origin A -> node B;
* origin A -> relay B -> node C;
* origin A and origin D -> relay B -> node C;
* peer key mismatch;
* origin key rotation;
* interrupted sync followed by retry;
* stale relay head after the receiver has observed a newer head.

## 19. Verification Commands

Use the repository's Python environment. On Windows, expected commands are:

```bat
.venv\Scripts\python.exe -m pytest tests\test_user_registry.py -v
.venv\Scripts\python.exe -m pytest tests\test_sync.py tests\test_ume.py -v
.venv\Scripts\python.exe -m pytest tests\test_http_sync.py -v
.venv\Scripts\python.exe -m pytest tests -v
```

Run formatting, linting, or type-check commands already configured by the
repository. Do not introduce a new formatter solely for this work.

## 20. Security Invariants

Treat these as review blockers:

1. No remote user reaches UME before its origin head and Merkle path verify.
2. A relay signature never substitutes for an origin signature.
3. A signed record's decoded `record_origin` must match the signed-head origin.
4. Receiver-local sequence and moderation state are never accepted from a peer.
5. The exact attested bytes are retained separately from normalized UME bytes.
6. Rollback and same-sequence equivocation checks occur inside the acceptance
   transaction.
7. A partial traversal is never reported as a complete snapshot.
8. Unknown signed identities may execute only explicitly public commands.
9. Parser bounds are checked before memory allocation or loops.
10. Existing SSRF, TLS, TOFU, response-signature, and replay protections remain
    in front of registry ingestion.

## 21. Review Decisions Resolved

All six open review decisions have been confirmed with the maintainer. The
resolutions below are locked in and supersede any tentative language elsewhere
in this document.

1. **Commit full 1079 bytes including privilege flags.** The origin's
   `is_administrator`, `is_moderator`, and `is_banned` flags are visible to
   anyone who fetches registry records, but they do not take effect remotely.
   This matches the existing `LIST_USERS` exposure and preserves the exact-bytes
   principle. No subset hashing or flag stripping is needed.

2. **Correct `creation_time` to the origin's attested value on update.** On
   insert, use the supplied `creation_time`. On update (same username, same
   origin), overwrite the local `creation_time` with the origin's latest
   attested value. This is not first-seen immutable. Bounds checking is required
   to prevent malicious history rewriting — reject timestamps in the future
   relative to receiver wall-clock plus clock-skew tolerance, and reject
   timestamps that differ from the existing local value by more than a
   configurable threshold (e.g. `max_creation_time_correction`).

3. **Change `Ume.export` in place.** Append
   `\tcreation_time=...\trelay_time=...` to the existing export line format.
   No `export_v2` method is added. No import parser in this repository consumes
   the format, so there is no in-repo breakage. If an external consumer is
   discovered later, treat the timestamp addition as a backward-compatible
   extension since the new fields are trailing tab-separated attributes.

4. **Heads forever; nodes for current + previous only; GC the rest.** Keep every
   signed head indefinitely for equivocation and linkage proofs. Keep Merkle
   node sets for the current generation and the immediately previous generation
   per origin to support interrupted synchronization. Garbage-collect node sets
   for older generations. Keep raw attested bytes (`registry_records`) for any
   key referenced by a retained head; drop rows referenced only by pruned
   generations. A configurable retention count is not needed initially.

   Future disk-optimization (not in the first release): key `registry_nodes` by
   `node_hash` with a refcount instead of `(origin, registry_seq, level,
   prefix)`. Consecutive snapshots share almost all nodes, so 100 snapshots of a
   mostly-stable registry cost barely more than one. This is content-addressed
   deduplication — the same structural sharing trick git uses. Defer until disk
   usage is actually a problem and correctness tests exist.

5. **No relay aggregate CSMT — ever.** Relays cache and forward individual
   origin-signed heads and proofs. The consumer verifies each origin head
   against its pinned origin key. A relay aggregate tree is permanently excluded
   because it manufactures new authorities and silent omission only fools
   consumers who do not know what they are looking for. The
   `USER_REGISTRY_HEADS` (`0x08`) listing command remains as an unauthenticated
   advertisement of what a relay has cached — it does not confer authority.

6. **Use opcodes `0x05`–`0x09` as proposed.** No external protocol consumer,
   fork, or integration reserves these opcodes. Assign them to the five registry
   commands as specified in Section 11.

## 22. Definition of Done

The work is complete when:

* Existing 1079-byte userfiles open without migration.
* A native origin can lazily produce a deterministic signed registry head.
* Another node can verify and partially synchronize that registry.
* A relay can forward the original attestation without becoming the authority.
* Local UME sequences and moderation state remain local.
* Creation timestamps are available in authenticated transfer and text export.
* Insertions, updates, deletions, rollback, equivocation, and omission attempts
  are covered by tests.
* Real two-server and origin-relay-consumer tests pass.
* Existing board, report, HTTP-authentication, trust, and protocol tests remain
  green.
