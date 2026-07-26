# Bonnet Glossary

## Core Concepts

**Origin** — The cryptographic identity of a server. An origin string
(typically resembling a hostname) identifies the authoritative source of
records. Origins sign records with their Ed25519 key.

**Record** — A signed, append-only entry in an origin's firehose. Contains
a kind, metadata, optional body reference, and is chain-linked to the
previous record via `previous_event_hash`.

**Intent** — The actor-authored portion of a record, signed by the actor's
key. The server signs the full record (intent + chain fields) with the
origin key.

**Firehose** — The append-only event store (`events.db`) containing all
records for all origins known to the server. Each origin has its own
sequence number space.

**Head** — A signed summary of an origin's firehose state: latest sequence
number, event hash, event count, and origin public key. Used by federation
to detect gaps and verify chain integrity.

**Witness** — A signed statement from a relay naming an upstream source for
a record. Witnesses form a chain that allows tracing the path a record took
through the network.

## Projections

**Projection** — A derived, rebuildable view of the firehose. Projections
are never authoritative — they can be deleted and rebuilt from `events.db`.

**Dispatcher** — Routes firehose records to projections in origin sequence
order. Advances the checkpoint only after all applicable projections accept
the record. Stops on failure.

**Checkpoint** — The last successfully dispatched sequence number for an
origin. Per-projection checkpoints track each projection's progress within
the origin-level checkpoint.

**NavProjection** — Board directory: maps (origin, board) to board lifecycle
state (created, closed, reopened).

**UserProjection** — User registrations and revocations keyed by
(origin, pubkey).

**PolicyProjection** — Moderation policy: rules, reports, punishments, and
revocations.

**BoardProjection** — Per-board article store with lifecycle state
(visibility, pin, thread, body state).

## Federation

**Sync Manager** — Background service that fetches signed heads and record
ranges from peers, verifies them, and dispatches accepted records to
projections.

**TOFU (Trust On First Use)** — The server's Ed25519 key is pinned after
first verified contact. Subsequent connections compare the presented key
against the stored pin and reject mismatches.

**Relay** — A server that forwards records from other origins. Creates
signed witnesses naming its upstream source for each accepted record.

**Backoff** — Exponential delay applied to sync attempts after failures
(30s, 60s, 120s, ... up to 3600s with jitter). Resets on success.

## Authentication

**Anonymous** — Requests signed with the server's published shared
anonymous key. Read-only, classified for ACL and rate-limiting. The key is
public by design and provides no authentication.

**Registered** — Requests signed by a key with a `bonnet.user.register`
record on the local origin.

**Unknown** — Requests signed by an unrecognized key. May be granted limited
write access (e.g., user registration) via ACL rules.

## Moderation

**Punishment** — A moderation action targeting a user. Types: warning,
temporary ban, permanent ban. Punishments from allowed origins are effective
locally. Users must acknowledge warnings before resuming writes.

**ACL (Access Control List)** — Explicit, compositional, default-deny
authorization rules. Every applicable dimension (command, kind, board) must
pass. Deny rules win over allow rules.
