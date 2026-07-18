# Peered Moderation, Merkle Registries, Import Allowlists, and ACL Modernization

## 1. Purpose

This document is an implementation handoff for the next Bonnet development
phase. It consolidates the decisions made while discussing:

1. Federating ("peering") punishment records.
2. Relaying punishment records for multiple origins.
3. Moving reports and punishments onto origin-signed Merkle registries.
4. Adding default-deny, object-specific origin allowlists for imports only.
5. Replacing the legacy `public_commands` authorization mechanism with
   granular command and object ACLs.
6. Distinguishing the well-known anonymous identity from a valid but unknown
   Ed25519 identity with `match.unknown`.
7. Applying remote punishments to effective ban checks and command gating.

The intended implementer is another engineering agent. Treat the decisions in
this document as frozen unless an implementation detail is impossible or
contradicts the current code.

This phase is already broad. Do not use it as an opportunity to redesign board
ACL semantics, HTTP authentication, UME storage, moderation policy, or every
legacy protocol command. Make the smallest coherent changes necessary for the
specified behavior.

## 2. Current Baseline

The workspace already includes these completed changes:

- Punishments are append-only rather than `INSERT OR REPLACE`.
- Punishments have monotonic `punishment_id`, `issued_by`, and `created_at`.
- Existing punishment databases migrate to that append-only schema.
- `PUNISHMENT_GET` currently accepts a bare punishment ID.
- `PUNISHMENT_LIST_BY_PUBKEY` exists at opcode `0x64`.
- A per-origin, multi-window creation-time filter exists in `Config`.
- User ACL evaluation applies that temporal filter to origin/wildcard ACLs,
  while preserving explicit pubkey ACLs and role bypasses.
- Effective punishment evaluation applies the temporal filter, while audit
  reads remain unfiltered.
- The test suite passed with 612 tests after those changes.

Relevant current files:

- `src/core/config.py`
- `src/engine/facade.py`
- `src/engine/keibatsu.py`
- `src/net/commands.py`
- `src/net/sync.py`
- `src/core/user_registry.py`
- `src/net/http_server.py`
- `src/client/protocol.py`
- `src/client/http.py`
- `src/client/models.py`
- `src/client/tools.py`
- `tests/test_acl.py`
- `tests/test_config.py`
- `tests/test_keibatsu.py`
- `tests/test_user_registry.py`
- `tests/test_http_sync.py`

## 3. Frozen Product Decisions

### 3.1 Punishment peering

- Punishments are federated records.
- Effective `is_banned` considers active, accepted punishments from every
  origin, not only the local origin.
- Remote punishments block non-public behavior by participating in command
  gating.
- More precisely, banned principals may execute ACL-authorized read commands
  but must be denied every write command.
- Punishment conflicts mirror report rollover behavior. Distinct variants for
  the same origin and punishment ID are retained under increasing `rollover`.
- `PUNISHMENT_GET` changes from a bare ID to `(origin, punishment_id)`, matching
  the conceptual shape of `REPORT_GET`.
- Punishment exports include cached records/heads for multiple origins, not
  only records originating locally.
- Punishment export remains readable by the well-known anonymous principal by
  default, subject to the new command and object ACLs.

### 3.2 Reports and punishments use Merkle registries

- Do not put reports or punishments into the existing user-registry tree.
- Create separate logical registries for users, reports, and punishments.
- Share generic Merkle primitives, persistence machinery, head verification,
  relay behavior, rollback checks, and protocol patterns.
- Each object type retains an independent per-origin sequence and signed head.
- The existing list-since report sync becomes legacy and is removed from the
  active sync path after report-registry support is complete.

### 3.3 Import allowlists

- Allowlists apply only to importing/copying remote data.
- Allowlists must never filter exports.
- Export authorization is controlled by command/object/board ACLs.
- Import allowlists are per object type: boards, users, reports, punishments.
- They are origin allowlists, not relay-host allowlists.
- They are default-deny ("allowlist-first"). If no origins are configured for
  an object type, no remote records of that type are imported.
- Trust pinning and signatures remain mandatory. An allowlist entry says "we
  bother to copy this origin"; it does not establish cryptographic trust.
- The object allowlist replaces `allow_legacy_unsigned_user_sync` for covered
  import behavior.

### 3.4 Export ACLs

- Add object-level ACL targets for at least `reports` and `punishments`.
- Command permission and object permission are separate checks and compose
  with AND.
- Report/punishment registry export commands require both command read access
  and corresponding object read access.
- Multi-origin export is not filtered by the local import allowlist.
- `public_commands` is obsolete and must have no authorization effect.
- Legacy `public_commands` configuration is silently ignored. Do not fail
  startup and do not preserve it as a fallback.
- No matching command/object ACL means deny.

### 3.5 Principal classes

There are three signed-request principal classes:

1. Anonymous: key equals the server's published shared anonymous key.
2. Unknown: signature is valid, key is not the anonymous key, and no UME user
   matches that key.
3. Known: signature is valid and a UME user matches the key.

Add `match.unknown = true` to ACL matching.

An invalid signature is not an unknown principal; it is rejected before ACL
evaluation.

ACL match-bucket precedence must be:

1. anonymous
2. pubkey
3. unknown
4. origin
5. wildcard

This preserves current anonymous precedence and allows a specific pubkey rule
to override a generic unknown-key rule.

### 3.6 Admin and moderation bypass behavior

- `admin_bypass_acl` remains relevant to existing board ACL checks.
- It must not bypass command ACLs.
- It must not bypass object ACLs.
- Existing handler-level role requirements remain mandatory. For example, an
  ACL write grant for `PUNISHMENT_CREATE` does not make a caller a moderator.
- Moderator write behavior for boards is outside this phase and remains as-is.

## 4. Authentication and Principal Classification

### 4.1 Preserve the anonymous/unknown distinction

Current behavior in `src/net/http_server.py` already distinguishes the shared
anonymous key via direct comparison with `_anonymous_public_key`. Preserve it.

Add `is_unknown` to `CommandContext` in `src/net/context.py`. It can be stored
or exposed as a property, but its semantics must be:

```python
is_unknown = not is_anonymous and user is None
```

Do not infer unknown status from a failed signature. A request only reaches
`CommandContext` after successful RFC 9421 verification.

### 4.2 Remove HTTP public-command preauthorization

Current HTTP handling allows an unknown key to proceed only for REGISTER or
commands in `public_commands`. Remove that command authorization decision from
the HTTP layer.

After successful signature verification and rate/replay checks:

1. Resolve the key against UME.
2. Classify the context as anonymous, unknown, or known.
3. Dispatch to `CommandHandler`.
4. Let command ACL evaluation decide whether the opcode is allowed.

Keep these transport differences:

- Anonymous requests remain IP-rate-limited.
- Unknown/known requests remain identity-rate-limited.
- Anonymous requests retain their current replay behavior unless a separate
  security change is explicitly requested.
- Unknown/known requests remain replay checked.

### 4.3 Registration

`REGISTER` becomes an ordinary ACL-controlled write command with an explicit
default grant to unknown identities.

Default generated ACL:

```toml
[[acl]]
name = "unknown-registration"
match.unknown = true
commands = ["REGISTER"]
write = true
```

Do not grant REGISTER to `match.anonymous` by default. Otherwise every caller
would register the same shared anonymous public key.

## 5. Command Metadata and ACL Targets

### 5.1 Canonical command registry

Introduce one canonical command-spec table, preferably in a small core module
such as `src/core/commands.py`. Avoid adding another duplicated opcode map.

Each entry needs at least:

```python
CommandSpec(
    opcode=0x65,
    name="PUNISHMENT_REGISTRY_HEAD",
    action="read",
    object_name="punishments",
)
```

Required fields:

- `opcode: int`
- `name: str`
- `action: Literal["read", "write"]`
- `object_name: str | None`

The client protocol, server dispatch logging, and config ACL parsing should use
this table where practical. Do not undertake a total protocol module rewrite
if it materially increases risk; the minimum requirement is that server ACL
decisions use one authoritative opcode-to-spec map.

### 5.2 Command action classification

Classify commands by effect, not by whether they are traditionally public.

Examples of reads:

- GET_USER
- LIST_USERS
- LIST_PEERS
- BOARD_LIST
- POST_GET
- POST_LIST
- QUERY_POSTS
- POST_CONTENT_SEARCH
- GET_PUBKEY
- RULE_GET / RULE_GET_BY_NAME / RULE_LIST
- REPORT_GET / REPORT_LIST_BY_CULPRIT
- PUNISHMENT_GET / PUNISHMENT_LIST_ACTIVE / PUNISHMENT_LIST_BY_PUBKEY
- IS_BANNED
- all Merkle HEAD/NODES/RECORDS/HEADS/HEAD_CHAIN commands
- PEER_KEY_LIST

Examples of writes:

- REGISTER
- BOARD_CREATE / BOARD_CLOSE / BOARD_DELETE
- POST_CREATE / POST_UPDATE / POST_DELETE / POST_SIGN
- USER_PROMOTE / USER_DEMOTE
- RULE_CREATE / RULE_UPDATE
- REPORT_CREATE / REPORT_SIGN
- PUNISHMENT_CREATE
- PEER_KEY_ROTATE

### 5.3 ACL schema

Extend `ACLEntry` with:

- `command_patterns` from `commands = [...]`
- `object_patterns` from `objects = [...]`
- Existing `board_patterns` remain from `boards = [...]`

Use command names in config, with `"*"` wildcard support. Object names are
lowercase canonical identifiers (`reports`, `punishments`).

Provide separate helpers:

- `command_matches(command_name)`
- `object_matches(object_name)`
- existing `board_matches(board_name)`

### 5.4 Command permission evaluation

Add `BonnetEngine.check_command_permission(spec, ctx)` and
`Config.check_command_permission(...)`, or a clean equivalent.

Rules:

- No matching ACL means deny.
- Admin bypass must not apply.
- Board-owner bypass must not apply.
- Moderator board-write bypass must not apply.
- Use the principal match buckets and precedence defined above.
- Use `spec.action` to select the ACL's `read` or `write` field.
- Existing temporal user filters should apply consistently to origin/wildcard
  command ACL matching, preserving explicit pubkey matching and role behavior
  already decided for board ACLs. Do not silently make temporal filters
  stronger during this phase.

### 5.5 Object permission evaluation

Add `BonnetEngine.check_object_permission(action, object_name, ctx)` and the
corresponding Config method.

Rules:

- No matching object ACL means deny.
- Admin bypass must not apply.
- Use the same principal precedence.
- Object export handlers must check this after command ACL succeeds.

Initially require object ACL checks for report and punishment registry exports.
Do not expand object ACLs to every existing subsystem unless needed for a
specific command in this plan.

### 5.6 Composed authorization

Authorization is conjunctive:

```text
valid signature
AND command ACL
AND object ACL (if command has object_name)
AND board ACL (if handler addresses a board)
AND handler business rules
```

Examples:

- POST_GET: command read AND board read.
- PUNISHMENT_REGISTRY_HEAD: command read AND punishments object read.
- PUNISHMENT_CREATE: command write AND moderator/admin handler check.
- REPORT_CREATE: command write AND registration/record checks.

### 5.7 Remove `public_commands`

Remove all runtime authorization uses of `public_commands`:

- HTTP unknown-key exception logic.
- CommandHandler anonymous gate.
- Banned user's "unless public command" exception.
- Config command-name map used only for `public_commands`.

Legacy TOML `public_commands` must be silently ignored. It may remain parsed by
tomllib as unknown data, but it must not affect Config or authorization. Remove
it from generated config examples.

## 6. Banned Principal Command Gating

### 6.1 Effective ban source

Keibatsu becomes the authoritative effective-ban evaluator. It must consider
accepted active punishments from all origins, subject to the existing
per-origin temporal filter.

Do not rely only on `ctx.user.is_banned`; that flag currently reflects local
UME state and cannot represent all remote punishment origins safely.

### 6.2 Read/write behavior

After command metadata is resolved and command ACL permission is checked:

- If the caller is effectively banned and `spec.action == "write"`, deny.
- If the caller is effectively banned and `spec.action == "read"`, continue
  through object/board ACL and normal handler checks.

The effective check uses `ctx.user.publickey` (or the authenticated peer key if
the user representation differs). Do not apply ban gating to the shared
anonymous principal or an unregistered unknown key unless a punishment can
meaningfully target that exact key and product behavior explicitly supports it.
At minimum, preserve current known-user behavior.

Avoid setting/clearing the UME `is_banned` flag as the sole response to remote
punishment ingestion. The table-backed multi-origin evaluation is the source
of truth. Existing local flag updates may remain for compatibility, provided
they cannot override the table-backed result.

## 7. Generic Merkle Registry Foundation

### 7.1 Do not mix object types in one tree

Maintain independent per-origin registries:

- users
- reports
- punishments

Each registry type has independent:

- `registry_seq`
- signed head chain
- Merkle root
- leaf count
- record encoding
- import allowlist
- object ACL export target

### 7.2 Extract reusable primitives

Refactor reusable code from `src/core/user_registry.py` into a generic module,
for example `src/core/merkle_registry.py`:

- sparse Merkle tree implementation
- default hashes
- inclusion/non-inclusion proofs
- proof encoders/decoders
- generic signed-head payload and verification
- rollback/equivocation acceptance logic
- generic head/state/node persistence helpers

Keep user-specific record validation and UME normalization in
`user_registry.py`.

Do this incrementally. First preserve user-registry behavior and tests exactly,
then add report and punishment registries.

### 7.3 Registry type domain separation

Every hash and head signature must be domain separated by registry type. A user
head must not be replayable as a punishment head.

Either include a canonical `registry_type` field in the signed head or use
distinct signature/hash domain constants. Prefer both explicit type encoding
and domain-separated constants.

Example logical head fields:

```text
registry_type
origin
registry_seq
snapshot_timestamp
leaf_count
merkle_root
previous_head_hash
signature
```

### 7.4 Persistence schema

Either use separate databases per type or a generic sidecar keyed by
`(registry_type, origin, ...)`. Prefer one generic sidecar if the migration is
manageable.

Required logical tables:

```text
registry_heads(
    registry_type,
    origin,
    registry_seq,
    head_hash,
    encoded_head,
    ...
)

registry_state(
    registry_type,
    origin,
    highest_accepted_seq,
    current_head_hash,
    current_merkle_root,
    ...
)

registry_records(
    registry_type,
    origin,
    registry_key,
    record_id,
    raw_record,
    value_hash,
    source_seq,
    ...
)

registry_nodes(
    registry_type,
    origin,
    path,
    node_hash,
    source_seq,
    ...
)
```

The exact schema may reuse existing columns, but object type and origin must be
part of every relevant primary key.

## 8. Rollback, Equivocation, and Retraction Semantics

### 8.1 Required rollback checks

For each `(registry_type, origin)`:

- Reject `incoming_seq < highest_accepted_seq` as rollback.
- For `incoming_seq == highest_accepted_seq`:
  - same head hash: idempotent success
  - different head hash: equivocation, reject
- For `incoming_seq > highest_accepted_seq`:
  - verify origin signature
  - verify expected `previous_head_hash` linkage where available
  - accept atomically only after all required records/proofs validate

Do not use timestamps as rollback ordering. `registry_seq` and head linkage are
authoritative.

### 8.2 Append-only moderation invariant

Reports and punishments are audit records. Their registries should be
append-only for this phase:

- A newer accepted head must not silently remove an already accepted report or
  punishment leaf.
- A report rollover adds a distinct leaf.
- A punishment rollover adds a distinct leaf.
- Origin omission is not a valid retraction.

Before accepting a newer report/punishment head, ensure previously accepted
record keys remain represented, unless a future explicit signed tombstone or
revocation record type is implemented.

Do not implement tombstones in this phase unless required to finish registry
correctness. Document them as the future mechanism for explicit retraction.

### 8.3 Existing board behavior remains separate

Board synchronization currently deletes native boards by omission and has no
sequence rollback protection. Do not redesign board rollback semantics in this
phase. The boards import allowlist can be added without moving boards to the
Merkle registry.

## 9. Report Registry

### 9.1 Record identity

Registry key input:

```text
domain("bonnet-report-registry-key-v1")
origin
report_num:u64
rollover:u64
```

Each `(origin, report_num, rollover)` is a distinct immutable leaf.

### 9.2 Canonical record

Define one canonical report registry encoding that includes every federated
field and both signatures. Keep transport-local relay metadata out of the
origin-signed payload because relay changes by hop.

At minimum include:

- origin
- report_num
- rollover
- rule_num
- culprit pubkey/board/post
- reporter pubkey
- report_time
- description
- origin signature
- reporter signature (optional)

The value hash must include the canonical record and be domain separated.

### 9.3 Report mutation and rollover

Current `_sign_report` updates `reporter_sig` in place. That conflicts with an
append-only registry.

Change signing behavior so adding a reporter signature creates a new rollover
version rather than mutating an already published leaf. Preserve the old
version for audit history.

Ensure local report creation/signing marks the report registry dirty, analogous
to UME mutation callbacks marking the user registry dirty.

### 9.4 Legacy sync

Replace active `_sync_reports` / `REPORT_LIST_SINCE` importing with report
registry synchronization. The old endpoint may remain temporarily for client
compatibility, but it must no longer be the federation source of truth.

Remove `allow_legacy_unsigned_user_sync` as a report import gate.

## 10. Punishment Data Model and Migration

### 10.1 Target schema

Punishments need per-origin IDs and rollover variants:

```sql
CREATE TABLE punishments_v3 (
    punishment_id   INTEGER NOT NULL,
    origin           TEXT NOT NULL,
    rollover         INTEGER NOT NULL DEFAULT 0,
    punished_pubkey  BLOB NOT NULL,
    report_ids       TEXT NOT NULL,
    expires_at       INTEGER NOT NULL,
    ban_notes        TEXT,
    issued_by        BLOB,
    created_at       INTEGER NOT NULL,
    relay            TEXT NOT NULL,
    origin_sig       TEXT NOT NULL,
    PRIMARY KEY (origin, punishment_id, rollover)
);
```

Add indexes for:

- `punished_pubkey`
- `created_at`
- `origin`
- active evaluation as appropriate for SQLite query plans

### 10.2 Migration

Migrate current append-only local rows transactionally:

- `origin = config.origin`
- `rollover = 0`
- `relay = config.origin`
- Preserve punishment ID, pubkey, report IDs, expiry, notes, issuer, created_at.
- Generate `origin_sig` using the local server signing key over the new
  canonical punishment payload.

Legacy rows with `created_at = 0` remain timestamp-unknown and continue to be
subject to the configured temporal filter.

Perform create/copy/verify/rename/drop in one transaction. Add a migration test
that starts with the current v2 schema and verifies all fields and signatures.

### 10.3 Local ID allocation

Allocate local IDs per origin:

```sql
SELECT MAX(punishment_id) FROM punishments WHERE origin = ?
```

Then insert `max + 1`, rollover 0. Serialize allocation under the existing
Keibatsu lock or an immediate SQLite transaction to avoid duplicate IDs.

### 10.4 Canonical punishment signature payload

Define a single canonical byte encoding and test it with fixed vectors.

Include:

- punishment_id
- rollover if variants are individually signed, otherwise define exactly how
  rollover variants derive signatures
- origin
- punished_pubkey
- ordered report ID list
- expires_at
- ban_notes
- issued_by
- created_at

Do not include `relay`; it is receiver-local hop metadata.
Do not include `origin_sig` in the signed payload.

`issued_by` is audit metadata. The origin signature is mandatory for federation
and proves the origin accepted the punishment. A separate issuer signature is
out of scope unless already required elsewhere.

### 10.5 Report reference semantics

Current `report_ids` are bare integers. For this phase, define them as report
IDs scoped implicitly to the punishment's origin. Document that cross-origin
report references are unsupported. Do not silently interpret them as receiver-
local IDs.

### 10.6 Conflict rollover

On import for the same `(origin, punishment_id)`:

- Exact canonical duplicate: idempotent, skip.
- Distinct valid origin-signed content: store under `max(rollover) + 1`.
- Invalid origin signature: reject.

Every stored rollover is a registry leaf and remains audit-visible.

## 11. Punishment Registry

### 11.1 Record identity

Registry key input:

```text
domain("bonnet-punishment-registry-key-v1")
origin
punishment_id:u64
rollover:u64
```

### 11.2 Registry value

Hash the canonical serialized punishment record, including `origin_sig` but
excluding receiver-local relay metadata.

### 11.3 Mutation callbacks

Local punishment creation marks the local punishment registry dirty. Remote
ingestion updates the cached registry/store but must not cause the receiver to
publish remote records as though they originated locally.

### 11.4 Effective evaluation

Update Keibatsu punishment evaluation:

- Search active punishments across all origins.
- Apply `Config.record_in_window(punishment.origin, punishment.created_at)` per
  row.
- Return the latest effective punishment according to deterministic ordering.
  Prefer `(created_at DESC, origin ASC, punishment_id DESC, rollover DESC)` or
  explicitly document another stable order.
- `list_active_punishments` includes accepted active in-window records from all
  origins.
- Audit reads remain unfiltered by the temporal window.

`check_expiry` must not clear compatibility UME state while any effective
active in-window punishment remains across any origin.

## 12. Registry Protocol and Multi-Origin Export

### 12.1 Opcode ranges

Use parallel command ranges if available:

```text
0x55 REPORT_REGISTRY_HEAD
0x56 REPORT_REGISTRY_NODES
0x57 REPORT_REGISTRY_RECORDS
0x58 REPORT_REGISTRY_HEADS
0x59 REPORT_REGISTRY_HEAD_CHAIN

0x65 PUNISHMENT_REGISTRY_HEAD
0x66 PUNISHMENT_REGISTRY_NODES
0x67 PUNISHMENT_REGISTRY_RECORDS
0x68 PUNISHMENT_REGISTRY_HEADS
0x69 PUNISHMENT_REGISTRY_HEAD_CHAIN
```

Confirm no current opcode collision before implementation.

These mirror the user registry `0x05-0x09` protocol.

### 12.2 Multi-origin export

`*_REGISTRY_HEADS` must enumerate cached heads for all origins available for
that registry type, including relayed origins.

Exports are not filtered by import allowlists.

Each HEAD/NODES/RECORDS/HEADS/HEAD_CHAIN handler must require:

- command read ACL for its command name
- object read ACL for `reports` or `punishments`

Anonymous access is granted by default config, not by hardcoded behavior.

### 12.3 Anonymous versus unknown export ACLs

Generated defaults should distinguish them explicitly. For example:

```toml
[[acl]]
name = "anonymous-moderation-export"
match.anonymous = true
commands = [
  "REPORT_REGISTRY_HEAD",
  "REPORT_REGISTRY_NODES",
  "REPORT_REGISTRY_RECORDS",
  "REPORT_REGISTRY_HEADS",
  "REPORT_REGISTRY_HEAD_CHAIN",
  "PUNISHMENT_REGISTRY_HEAD",
  "PUNISHMENT_REGISTRY_NODES",
  "PUNISHMENT_REGISTRY_RECORDS",
  "PUNISHMENT_REGISTRY_HEADS",
  "PUNISHMENT_REGISTRY_HEAD_CHAIN",
]
objects = ["reports", "punishments"]
read = true
write = false
```

Outbound federation clients currently sign with the server identity, which is
usually an unknown key on the remote server. Add a separate default rule if
peer-to-peer export should work without pre-registering server identities:

```toml
[[acl]]
name = "unknown-peer-moderation-export"
match.unknown = true
commands = [
  "REPORT_REGISTRY_HEAD",
  "REPORT_REGISTRY_NODES",
  "REPORT_REGISTRY_RECORDS",
  "REPORT_REGISTRY_HEADS",
  "REPORT_REGISTRY_HEAD_CHAIN",
  "PUNISHMENT_REGISTRY_HEAD",
  "PUNISHMENT_REGISTRY_NODES",
  "PUNISHMENT_REGISTRY_RECORDS",
  "PUNISHMENT_REGISTRY_HEADS",
  "PUNISHMENT_REGISTRY_HEAD_CHAIN",
]
objects = ["reports", "punishments"]
read = true
write = false
```

### 12.4 PUNISHMENT_GET

Change request format to:

```text
origin: u8-length UTF-8
punishment_id: u64be
```

Mirror REPORT_GET behavior for rollover selection unless protocol users require
an explicit rollover. Under the frozen decision, the command takes origin and
ID only. Document which rollover is returned (prefer rollover 0 for exact
report parity, or latest rollover if that is already established by tests).
Do not leave behavior ambiguous in code or protocol documentation.

Update client builders, HTTP client, MCP tools, wire fixtures, and conformance
tests together.

### 12.5 Capability discovery

Advertise explicit capabilities from `/.well-known/bonnet`, for example:

- `report-registry-merkle-v1`
- `punishment-registry-merkle-v1`
- `command-object-acl-v1` if capability negotiation is useful

Sync must not assume a peer supports a registry command without checking
capability or handling unknown-command responses cleanly.

## 13. Object-Specific Import Allowlists

### 13.1 Config shape

Use a dedicated import-only section. A compact shape is preferred:

```toml
[import_allowlist]
boards = ["boards.example"]
users = ["identity.example", "relay-origin.example"]
reports = ["moderation.example"]
punishments = ["moderation.example", "appeals.example"]
```

Exact origins are sufficient for this phase. Do not add glob semantics unless
explicitly needed. Normalize origin casing consistently with existing origin
handling.

### 13.2 Config API

Add:

```python
Config.is_import_origin_allowed(object_type: str, origin: str) -> bool
```

Rules:

- Unknown object type: deny.
- Missing object list: deny.
- Empty object list: deny.
- Exact configured origin: allow.
- Local origin is not implicitly allowed for import; sync already skips own
  origin where appropriate.

### 13.3 Apply by record origin, not relay

The allowlist checks the cryptographically claimed record/head origin:

- boards: each board entry's `origin`
- users/direct registry: peer registry head's `origin`
- users/relayed registry: advertised/verified `head.origin`
- reports: report registry head/record origin
- punishments: punishment registry head/record origin

Do not check only `peer_hostname`. A permitted origin may arrive through a
different relay, and a permitted relay may advertise disallowed origins.

### 13.4 Apply before expensive work where safe

When an origin is visible before record fetch, skip it early to avoid network
and verification cost. Still never trust unverified data merely because its
origin string is allowlisted.

Suggested placements:

- `_sync_boards`: after parsing origin, before pin/signature work.
- `_sync_registry`: after obtaining peer origin, before fetching full records.
- `_sync_relayed_origins`: after decoding advertised head origin, before full
  head/record fetch.
- generic report/punishment registry sync: after advertised origin is known,
  before subtree/record requests.

### 13.5 Export independence

Never use `is_import_origin_allowed` in command handlers or registry export
services. A locally disallowed import origin may still have cached records from
earlier configuration, and export visibility is determined solely by ACLs.

## 14. Sync Orchestration

### 14.1 Generic registry sync

Generalize current user `_sync_registry` and `_sync_relayed_origins` around a
registry adapter:

```python
RegistrySyncAdapter(
    registry_type,
    command_builders,
    response_parsers,
    store,
    record_decoder,
    record_validator,
    import_callback,
)
```

Do not over-abstract before the report/punishment paths work. A small shared
helper plus type-specific validators is preferable to an opaque framework.

### 14.2 Sync order

Recommended order:

1. boards (existing list sync, import-allowlisted)
2. user registry (direct origin)
3. report registry (direct origin)
4. punishment registry (direct origin)
5. relayed user/report/punishment origin discovery and sync

Legacy `_sync_users` and `_sync_reports` should be removed from the active
sequence after their registry replacements pass integration tests.

### 14.3 Import and enforcement transaction boundary

Accept a signed head and its validated records atomically into the sidecar.
Then normalize/apply records into Keibatsu. If normalization fails, retain the
verified sidecar data and log the failure; a later repair/replay path should be
possible.

Do not partially advance accepted registry state before all required Merkle
validation succeeds.

## 15. Generated Default ACLs

The generated default configuration must be explicit because authorization is
default-deny and `public_commands` has no effect.

At minimum include examples/rules for:

1. Local registered users' normal command access as intended by current
   defaults.
2. Anonymous board reading where currently intended.
3. Unknown registration only.
4. Anonymous report/punishment registry reads.
5. Unknown server-identity report/punishment registry reads.
6. Local administrators/moderators still subject to command/object ACLs, with
   handler roles providing the second authorization factor.

Review every command in the canonical command table. An omitted command will
be unreachable under default-deny; that may be correct, but it must be
intentional and tested.

## 16. Client and MCP Changes

Update together:

- `src/client/protocol.py`
- `src/client/http.py`
- `src/client/models.py`
- `src/client/tools.py`
- `src/client/resources.py`
- package exports if needed

Required changes include:

- origin/rollover/signature fields on punishment models
- `(origin, punishment_id)` GET builder/client/tool
- report/punishment registry command builders/parsers
- multi-origin head listing models
- updated active/list responses
- protocol error handling for ACL-denied reads

Do not expose import allowlist mutation through MCP in this phase. It is
config-file-only.

## 17. Testing Plan

Use `uv` for every Python/test command.

### 17.1 Principal classification tests

- Well-known anonymous key => `is_anonymous=True`, `is_unknown=False`.
- Valid unregistered key => `is_anonymous=False`, `is_unknown=True`.
- Registered key => both false, `is_registered=True`.
- Invalid signature never reaches command ACL.
- Unknown key can REGISTER only with matching write ACL.
- Anonymous key cannot REGISTER under generated defaults.

### 17.2 Command ACL tests

- Default deny with no command ACL.
- Read/write selection from CommandSpec.
- Anonymous, pubkey, unknown, origin, wildcard precedence.
- Specific pubkey overrides generic unknown.
- Admin does not bypass command ACL.
- Object/board handler checks remain conjunctive.
- Legacy `public_commands` is silently ignored.

### 17.3 Object ACL tests

- Report registry export needs command + reports-object read.
- Punishment registry export needs command + punishments-object read.
- Missing object ACL denies even when command ACL grants.
- Admin does not bypass object ACL.
- Anonymous and unknown grants can differ.
- Import allowlist never changes export results.

### 17.4 Banned command behavior

- Local active punishment blocks writes, permits ACL-authorized reads.
- Remote active punishment blocks writes, permits ACL-authorized reads.
- Out-of-window punishment does not block.
- Expired punishment does not block.
- Multiple origins: any effective active punishment blocks writes.
- UME flag disagreement does not override Keibatsu effective state.

### 17.5 Import allowlist tests

For each object type (boards/users/reports/punishments):

- Missing list denies import.
- Empty list denies import.
- Allowed origin imports.
- Disallowed origin is skipped.
- Allowed relay cannot smuggle a disallowed record origin.
- Allowed origin can arrive via a different trusted relay.
- Signature/pin failure still rejects an allowlisted origin.
- Export behavior is unchanged by import allowlist.

### 17.6 Generic Merkle regression tests

- Existing user registry roots/proofs remain stable.
- Registry type is domain separated.
- Lower sequence rejected.
- Same sequence/same hash idempotent.
- Same sequence/different hash rejected as equivocation.
- Broken previous-head linkage rejected.
- Multi-origin heads are independently verified against origin pins.
- Relay cannot introduce an unpinned origin.

### 17.7 Report registry tests

- Existing reports backfill into seq 1.
- Local create advances report registry.
- Reporter signing creates rollover rather than mutating an existing leaf.
- Multi-origin relay/export/import.
- Import allowlist.
- Append-only invariant rejects disappearing prior leaves.
- Legacy list-since is not used by active sync.

### 17.8 Punishment migration and registry tests

- Current schema migrates to origin/rollover/signature schema.
- Migrated signature verifies.
- Local IDs increase per origin.
- Local create advances punishment registry.
- Exact remote duplicate is idempotent.
- Valid conflict creates rollover.
- Invalid origin signature rejected.
- Multi-origin export and relay.
- Import allowlist.
- Temporal filter uses row origin.
- PUNISHMENT_GET requires origin + ID.
- Audit history remains unfiltered.
- Append-only invariant rejects disappearing prior leaves.

### 17.9 Integration tests

At least three nodes:

- Origin A issues punishment.
- Relay B imports A (allowlisted), caches and exports A's punishment head.
- Node C imports A through B (A allowlisted, B trusted relay).
- C blocks writes by the punished known user but permits authorized reads.
- C rejects origin D punishments advertised by B when D is not allowlisted.
- Removing A from C's import allowlist prevents future imports but does not
  delete or automatically deactivate already accepted A punishments.

### 17.10 Full verification

Run incrementally, then full suite:

```text
uv run pytest tests/test_acl.py -x -q
uv run pytest tests/test_http_server.py -x -q
uv run pytest tests/test_user_registry.py -x -q
uv run pytest tests/test_keibatsu.py -x -q
uv run pytest tests/test_sync.py tests/test_http_sync.py -x -q
uv run pytest -x -q
```

No plain `python -m pytest`; use `uv run`.

## 18. Recommended Implementation Phases

### Phase 1: Command/object ACL foundation

- Add `is_unknown`.
- Add `match.unknown` and precedence.
- Add canonical CommandSpec table.
- Add `commands` and `objects` ACL targets.
- Add command/object ACL checks.
- Remove authorization dependence on `public_commands`.
- Implement banned read/write gating against current local punishment state.
- Update generated defaults and tests.

Do not begin federation work until ACL tests are green.

### Phase 2: Generic Merkle extraction

- Extract reusable primitives without changing user behavior.
- Add registry type domain separation.
- Keep all user registry tests green.

### Phase 3: Import allowlists

- Parse config and add helper.
- Gate board and user registry imports.
- Remove active legacy user sync and obsolete flag behavior.
- Add tests proving exports are unaffected.

### Phase 4: Report registry

- Add canonical record/key.
- Add service/store wiring and mutation callback.
- Convert reporter signing to rollover.
- Add protocol/export ACLs/import allowlist/sync.
- Backfill existing reports.
- Remove legacy report sync from active path.

### Phase 5: Punishment schema and registry

- Migrate schema.
- Add canonical origin signatures and rollover.
- Add service/store wiring.
- Add protocol/export ACLs/import allowlist/sync.
- Add multi-origin relaying.
- Update temporal evaluation and GET semantics.

### Phase 6: Effective remote enforcement

- Make Keibatsu multi-origin ban evaluation authoritative.
- Block writes for effectively banned known users.
- Preserve ACL-authorized reads.
- Add end-to-end relay/enforcement tests.

### Phase 7: Cleanup and documentation

- Remove obsolete runtime `public_commands` logic.
- Silently ignore legacy config key.
- Remove obsolete legacy sync calls/flag.
- Update discovery capabilities and protocol documentation.
- Run full suite with `uv`.

## 19. Explicit Non-Goals

Do not include these unless strictly required:

- Redesigning board rollback/deletion semantics.
- Putting boards into a Merkle registry.
- Runtime mutation APIs for import allowlists or temporal filters.
- A universal aggregate Merkle tree across origins or object types.
- Export filtering based on import allowlists.
- New admin/moderator role policy.
- Tombstone/revocation UX.
- Cross-origin report references inside punishments.
- Replacing UME storage.
- Reworking anonymous replay behavior.

## 20. Definition of Done

The phase is complete when:

1. `public_commands` has no runtime authorization effect.
2. Every command is default-deny and authorized through command ACL metadata.
3. Report/punishment registry exports also require object read ACLs.
4. Anonymous, unknown, and known signed principals are distinguishable in ACLs.
5. Admins cannot bypass command/object ACLs.
6. Banned known users can perform authorized reads but no writes.
7. Reports and punishments have separate per-origin Merkle registries with
   rollback/equivocation protection.
8. Punishments are origin-signed, multi-origin, relayable, and effective for
   command gating.
9. Import allowlists are per object type, origin-based, default-deny, and never
   affect export.
10. Multi-origin punishment export works for anonymous and unknown callers only
    when explicitly granted by generated/default ACLs.
11. Existing databases migrate without losing report or punishment history.
12. All tests pass under `uv run pytest -x -q`.
