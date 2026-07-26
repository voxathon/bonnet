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
| `bonnet.punishment.issue` / `.revoke` | Punishments |
| `bonnet.origin.key.rotate` | Origin key rotation |

## Projection Model

The firehose store (`events.db`) is the authoritative append-only log.
Projections are derived, rebuildable views:

- **NavProjection** (`nav.db`) — board directory
- **UserProjection** (`users.db`) — user registrations and revocations
- **PolicyProjection** (`policy.db`) — rules, reports, punishments
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
