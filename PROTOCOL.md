# Bonnet Firehose Protocol

## Overview

Bonnet uses an append-only, signed firehose model. Each origin maintains a
sequenced, chain-linked log of records. Records are signed by both the actor
(author) and the origin (server). Relays synchronize records through witnessed
replication, creating signed witnesses that name their upstream source.

## Transport

- **Discovery:** `GET /.well-known/bonnet` returns a signed JSON document with
  the server's origin, public key, anonymous key, anonymous private key,
  capabilities, and known origins.
- **Commands:** `POST /command` accepts a binary body with a one-byte opcode
  followed by opcode-specific fields. Requests and responses are signed using
  RFC 9421 HTTP Message Signatures with Ed25519.

### Key Epochs Command

`KEY_EPOCHS` (opcode `0x05`, read) returns a server's origin key epoch table
for federation peers bootstrapping rotated histories.

- **Request:** opcode, then the origin as text16.
- **Response:** count as u16, then per epoch: `start_seq` u64, `end_seq` u64
  (0 = open), `pubkey` (32 bytes). Epochs are ascending and non-overlapping.

The response is advisory. Peers must verify each internal boundary by
snatching the rotate record at the prior epoch's `end_seq` and checking
that its actor pubkey matches the previous epoch's key, its origin
signature verifies under that key, and its rotation proof — signed by the
new key over `(origin, old, new)` — chains to the advertised successor.
The final open epoch must match the signed head's public key. Unverified
or incoherent hints are discarded; verification then proceeds from the
record stream alone.

## Authentication

Every request is signed with an Ed25519 key. The key ID format is
`ed25519:<hex pubkey>`. The server resolves the key from the signature, then
classifies the request as:

- **Anonymous:** signed with the server's published anonymous key (read-only)
- **Registered:** signed with a key that has a `bonnet.user.register` record
- **Unknown:** signed with an unrecognized key

## Authorization

ACL rules are explicit, compositional, and default-deny. Every applicable
dimension (command, kind, board) must pass. Any matching deny rule wins. No
implicit bypasses exist — administrators and moderators are granted via ACL
rules matching their role or pubkey.

## Record Format

Records are binary-encoded with a fixed header and variable metadata map.
Key fields:

- `origin`, `origin_seq` — origin identity and sequence number
- `previous_event_hash` — chain link to the prior record
- `event_id` — content-addressed identifier (32 bytes)
- `kind` — printable ASCII string (e.g., `bonnet.article`)
- `actor_pubkey`, `actor_signature` — author identity and intent signature
- `origin_signature` — server's signature over the record
- `body_hash`, `body_size` — optional body content reference

Text fields are UTF-8, NFC-normalized at encode time, length-prefixed with
u16. Binary fields are length-prefixed with u32.

## Record Kinds

| Kind | Description |
|------|-------------|
| `bonnet.article` | Publish an article to a board |
| `bonnet.article.cancel` | Cancel an article |
| `bonnet.article.restore` | Restore a cancelled article |
| `bonnet.article.purge` | Purge article body (irreversible) |
| `bonnet.article.pin` / `.unpin` | Pin or unpin an article |
| `bonnet.thread.close` / `.reopen` | Close or reopen a thread |
| `bonnet.board.create` / `.close` / `.reopen` | Board lifecycle |
| `bonnet.user.register` / `.revoke` | User lifecycle |
| `bonnet.rule.publish` / `.revoke` | Moderation rules |
| `bonnet.report` | Report content |
| `bonnet.punishment.warn` / `.ban` / `.permaban` | Typed punishments (Gate D) |
| `bonnet.punishment.revoke` | Revoke any punishment by event ID |
| `bonnet.punishment.ack` | User acknowledgment of a punishment |
| `bonnet.origin.key.rotate` | Origin key rotation |

Punishment semantics (Gate D):

- **warn** — metadata field 1 = punished pubkey (32 bytes); body = warning
  message. Stays pending until acknowledged or revoked.
- **ban** — metadata field 1 = punished pubkey, field 2 = expiry unix
  timestamp (positive i64); body = ban reason. Expires automatically.
- **permaban** — metadata field 1 = punished pubkey; body = reason. Never
  expires; only revocation lifts it.
- **revoke** — targets any punishment by `target_event_id`.
- **ack** — metadata field 1 = punishment event ID (32 bytes), signed by the
  punished user's own key. Acks are local to the user's homeserver and do
  not federate. Acknowledging a warning clears its pending state; bans stay
  in force until expiry or revocation.

### Punishment write gate

Publication of any record kind (except `bonnet.punishment.ack`) is blocked
while the actor has pending punishments from allowed origins: unacknowledged
warnings, active temporary bans, or permabans. Administrators bypass the
gate. Blocked writes return error code `0x000A` with the punishment details.
If the policy projection is unavailable or behind the firehose, the gate
fails open so an outage cannot block all publication.

Per-type per-origin import filtering: each `[sync.peers]` entry configures
`import_warnings`, `import_temp_bans`, and `import_permabans`. Rejected
punishment records remain in the firehose for relay but are not applied to
the local policy projection. Punishments from origins without an import
policy entry are never enforced locally.

## Projection Model

The firehose store (`events.db`) is the authoritative append-only log.
Projections are derived, rebuildable views:

- **NavProjection** (`nav.db`) — board directory
- **UserProjection** (`users.db`) — user registrations and revocations
- **PolicyProjection** (`policy.db`) — rules, reports, punishments, punishment acks
- **BoardProjection** (per-board `metadata.db`) — articles and lifecycle state

The dispatcher processes records in origin sequence order, advancing the
checkpoint only after all applicable projections accept the record. On
failure, dispatch stops and the checkpoint remains at the last successful
record.

## Federation

Origins sync from peers through the sync manager. Each sync cycle:

1. Fetches the peer's signed head (latest sequence, event hash, origin key)
2. Compares against the local highest sequence
3. Fetches missing records in bounded batches of 100
4. Verifies chain continuity, record signatures, and head signature
5. Accepts each batch through `accept_remote_range`
6. Creates local relay witnesses naming the upstream source
7. Dispatches accepted records to projections

### SSRF Protection

Dial targets are validated against non-global address ranges by default.
Loopback, private, link-local, multicast, and reserved addresses are rejected.
Explicit `allow_private_dial` configuration is required for LAN federation.

### Trust Bootstrap

First contact relies on TLS (Web PKI) for transport integrity. The server's
Ed25519 key is TOFU-pinned after first verified contact. Subsequent
connections compare the presented key against the pin. Operator-configured
pins override both.

### Backoff

Failed peers accumulate exponential backoff (30s, 60s, 120s, ... up to 3600s)
with jitter. Backoff applies to both periodic and on-demand sync. Backoff
resets on success.

## Anonymous Access

The server publishes a shared anonymous Ed25519 key pair in discovery. The
private key is public by design — it classifies requests as anonymous for
ACL and rate-limiting purposes. It provides no authentication. Anonymous
requests are not tracked in the replay ledger. Address-based rate limiting
is the DoS defense for anonymous traffic.

## Limits

- `max_request_size` (default 10 MiB) — HTTP request body limit, enforced
  during streaming
- `max_article_body_size` (default 1 MiB) — body content limit for all
  body-bearing records
- `rate_limit_requests` / `rate_limit_window` — sliding window limiter keyed
  by address (all requests) and identity (non-anonymous requests)
- `signature_lifetime_seconds` (max 60) / `clock_skew_seconds` (max 30) —
  temporal signature validation bounds

## Depeering and Origin Lifecycle

- `depeer <origin>` — stop sync, freeze projections as read-only snapshot
- `purge-origin <origin>` — irreversibly remove all data for an origin
  (requires depeer first, writes a manifest for crash recovery)
- `reset-key <origin>` — clear key epoch pinning, forces re-TOFU on next sync
- `rebuild <origin>` — clear projections for one origin and replay from
  the firehose

## Error Responses

Command responses begin with a status byte: `0x00` for success, `0x01` for
error. Error responses include a 16-bit error code and a UTF-8 message.
Internal exceptions return a generic `"Internal error"` message to avoid
leaking server internals.

Known codes: `0x0004` not permitted (ACL), `0x0006` validation error,
`0x0009` conflicting state, `0x000A` write blocked by a pending punishment
(message carries the punishment type, event ID, origin, and expiry).
