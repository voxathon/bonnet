# Bonnet Public-Readiness Plan

## Status

This document is the authoritative roadmap for preparing the current Bonnet
server implementation for public review. Existing Markdown files in this
repository are historical material unless they are explicitly reconciled and
adopted during Phase 8.

The current implementation and its executable tests are the baseline for this
plan. Existing documentation must not be used to infer intended behavior when
it contradicts the source code.

## Goal

Make the Bonnet server suitable for detailed external review by ensuring that:

- persisted and projected state cannot be silently lost or corrupted;
- untrusted network input is bounded, validated, and fails closed;
- authentication, authorization, moderation, replay, and federation behavior
  is explicit and tested;
- startup, shutdown, configuration, packaging, and installation are reliable;
- the tracked repository contains only intentional source and project assets;
- public documentation describes the implementation that actually ships;
- automated checks make regressions visible before merge;
- cleanup is delivered as small, reviewable commits.

## Scope

Primary implementation scope:

- `src/core/`
- `src/net/`
- `src/app/`
- server-facing portions of `src/client/`
- `tests/`
- package, build, configuration, and repository metadata
- public operator and protocol documentation

Client changes are in scope only when required to test the server, preserve a
coherent server/client protocol, or implement an approved protocol change.

## Constraints

- Do not rewrite Git history as part of this plan.
- Do not silently introduce wire-format or protocol changes.
- Discuss and approve every protocol-affecting change before implementation.
- Prefer the smallest correct change over broad restructuring.
- Add regression tests before or with each behavioral fix.
- Do not combine correctness fixes with unrelated formatting or renaming.
- Preserve unrelated worktree changes encountered during implementation.
- Keep each commit focused enough to review independently.

Removing sensitive files from the current tree does not remove them from
existing history. Repository reinitialization and credential rotation remain
operator actions outside this plan.

## Current Risk Summary

The audit identified four dominant risk areas:

1. Projection failures can be skipped permanently and origin-scoped rebuilds
   can erase projection state belonging to other origins.
2. HTTP and federation boundaries contain unbounded reads, missing dial-target
   validation, rate-limit bypasses, and incomplete lifecycle cleanup.
3. Important configured policy, including article body limits and effective
   punishments, is not enforced during publication.
4. Critical integration surfaces have little or no direct test coverage, while
   the repository contains stale documentation and tracked runtime artifacts.

## Delivery Rules

Every implementation change should follow this order:

1. Reproduce the defect with a focused test when practical.
2. Make the smallest production change that fixes the defect.
3. Run the focused test module.
4. Run the full non-slow suite.
5. Run the full suite when the affected behavior includes concurrency,
   federation, persistence, packaging, or lifecycle management.
6. Inspect the diff for unrelated edits and generated files.
7. Commit only the focused change when a commit is requested.

Large file moves, mass formatting, package renaming, and documentation rewrites
must not share commits with behavior fixes.

## Decision Gates

The following decisions have been resolved with the maintainer. Each gate's
resolution is the authoritative specification for its associated implementation
work. Items marked as deferred are intentionally excluded from this cleanup
cycle.

### Gate A: Anonymous Authentication

**Decision: Retain the shared anonymous key.**

Current behavior publishes a shared anonymous Ed25519 private key in the
discovery document. Clients fetch it and use it to sign nominally anonymous
requests. The key is public by design — it provides no authentication, only a
classification mechanism for ACL and rate-limiting.

No protocol change is required. The limited security semantics of the shared
anonymous key must be documented during Phase 8 so that public reviewers
understand it is a classifier, not a secret.

### Gate B: Discovery Trust

**Decision: Layered trust — Web PKI, TOFU with persistent pinning, and
operator-configured pins.**

The discovery response is signed by the server's own key, which is advertised
in the same response. On first contact this is circular — a MITM can substitute
their own key and sign the response with it. The client's `discover()` method
parses the response and pins the key before constructing the verifier, and never
verifies the discovery response signature at all.

The approved trust model layers three mechanisms:

- **Web PKI** validates first contact when TLS is enabled. The TLS certificate
  chain provides an independent trust anchor that the self-attested Ed25519 key
  cannot.
- **TOFU with persistent pinning** persists the server's Ed25519 key after first
  contact. Subsequent connections compare the presented key against the pinned
  value and reject mismatches.
- **Operator-configured pins** override both. If an operator pre-configures the
  expected server key, the client uses that pin exclusively and does not
  TOFU-pin from discovery.

Implementation must:

- verify the discovery response signature using the key from the same response
  (detects post-parse corruption);
- rely on TLS for first-contact integrity when enabled;
- persist TOFU pins in the trust store after first verified contact;
- reject unexpected key changes after pinning;
- document operator recovery for stale or compromised pins;
- avoid claiming first-contact MITM resistance when running in pure TOFU mode
  without TLS.

### Gate C: Federation Network Policy

**Decision: Reject non-global addresses by default; explicit
`allow_private_dial` required for private/loopback.**

No SSRF protection exists on any dial path. The protocol mandates rejecting
loopback, private, link-local, multicast, reserved, and non-global addresses.

The approved policy:

- reject loopback, private, link-local, multicast, reserved, and non-global
  resolved addresses by default;
- permit them only when `allow_private_dial = true` is explicitly set in the
  peer configuration;
- apply identical validation to configured peers, body redirects, relay-derived
  hostnames, and every future server-supplied URL;
- validate hostname syntax, reject unsupported schemes, embedded credentials,
  fragments, and malformed ports;
- defend against DNS rebinding by validating the resolved address actually used
  where the HTTP stack permits it.

### Gate D: Effective Punishments

**Decision: Three explicit punishment types, per-type per-origin import
filtering, server-tracked acknowledgment, ACL-enforced authority.**

#### Record Kinds

| Kind | Metadata field 1 | Metadata field 2 | Body |
|------|------------------|------------------|------|
| `bonnet.punishment.warn` | punished pubkey (BYTES 32) | — | warning message |
| `bonnet.punishment.ban` | punished pubkey (BYTES 32) | expires\_at (I64, positive timestamp) | ban reason |
| `bonnet.punishment.permaban` | punished pubkey (BYTES 32) | — | ban reason |
| `bonnet.punishment.revoke` | unchanged — targets any punishment by event\_id | — | revocation reason |
| `bonnet.punishment.ack` | target punishment event\_id (BYTES 32) | — | — |

The existing `bonnet.punishment.issue` kind is replaced by the three typed
kinds above. The `bonnet.punishment.revoke` kind is unchanged in structure but
can target any of the three types.

#### Authority

Permaban authority is ACL-enforced, not hardcoded. The default ACL rules grant
administrators all punishment kinds and restrict moderators to warnings, temp
bans, and revocations:

```toml
[[acl]]
effect = "allow"
match.role = "administrator"
actions = ["write"]
kinds = ["bonnet.punishment.warn", "bonnet.punishment.ban", "bonnet.punishment.permaban", "bonnet.punishment.revoke"]

[[acl]]
effect = "allow"
match.role = "moderator"
actions = ["write"]
kinds = ["bonnet.punishment.warn", "bonnet.punishment.ban", "bonnet.punishment.revoke"]
```

Moderators cannot publish `bonnet.punishment.permaban` because no ACL rule
grants them that kind. Operators may override these defaults.

#### Import Filtering

Import filtering is per-type per-origin, configured on each `[[sync.peers]]`
entry:

```toml
[[sync.peers]]
origin = "example.peer"
hostname = "example.peer"
port = 2272
import_warnings = true
import_temp_bans = true
import_permabans = false
```

The local origin's own punishments are always applied. The dispatcher checks
the import policy before routing a federated punishment to the policy
projection. Rejected records remain in the firehose for relay but are not
applied locally.

#### Acknowledgment Flow

1. A user attempts a write (`PUBLISH_RECORD`).
2. The server checks the policy projection for active or unacknowledged
   punishments targeting this user from allowed origins.
3. If any unacknowledged warning or active ban exists, the publish handler
   returns an error containing the punishment details (event\_id, type, origin,
   expiry, body reference).
4. The client fetches the punishment body (via `EVENT_BODY`), displays it to
   the user.
5. The client publishes `bonnet.punishment.ack` with the punishment's
   event\_id, signed by the user's own key.
6. The server stores the ack in the policy projection. Warnings with acks are
   cleared from the pending state. Bans with acks still block until expiry or
   permaban — the ack confirms the user has seen the reason.
7. The user retries the write. If all warnings are acked and no active bans
   remain, the write proceeds.

Acknowledgment records are local to the user's homeserver. They reference the
punishment event\_id regardless of which origin issued the punishment. Acks do
not federate — they are a local user-server relationship.

#### Write Gate Logic

```
if actor is administrator:
    skip punishment gate
else:
    pending = policy.list_pending_for_pubkey(actor_pubkey, allowed_origins)
    if pending:
        return error with punishment details
```

`list_pending_for_pubkey` returns:

- unacknowledged warnings from allowed origins;
- active (non-expired, non-revoked) temp bans from allowed origins;
- active permabans from allowed origins.

If the policy projection is unavailable or behind the firehose, the gate fails
open — publication is allowed rather than blocking all users during a
projection outage.

#### Expiry Semantics

- Warnings: no auto-expiry. Persist until acknowledged or revoked.
- Temp bans: positive timestamp in metadata field 2. Expire automatically.
- Permabans: no expiry field. Permanent by definition.

#### Ban Status Command Changes

The current `ban_status` command returns a single active ban. It must return
all pending punishments with type, event\_id, origin, expiry, and body
reference, so the client can display each and the user can acknowledge them.

#### Projection Schema Changes

The `punishments` table gains a `type` column (`warning`, `ban`, `permaban`).
A new `punishment_acks` table stores
`(user_pubkey, punishment_event_id, ack_event_id, acked_at)`. The
`list_punishments_for_pubkey` method gains filtering by type and acknowledgment
status.

### Gate E: HTTP Signature Tightening

**Decision: Require both request `expires` and response `bonnet-request-nonce`
now.**

Current clients always send both parameters. The server verifier treats
`expires` as optional and skips `bonnet-request-nonce` if absent. Requiring
both tightens the boundary against malicious clients and servers and is
compatible with the current client.

Implementation must:

- reject request signatures that omit the `expires` parameter;
- reject response signatures that omit the `bonnet-request-nonce` header;
- enforce exact value matching for the response request-nonce;
- enforce configured maximum lifetime and clock skew within protocol maxima;
- test missing, duplicated, malformed, expired, and future parameters.

### Gate F: Package Namespace

**Decision: Defer to a later breaking release.**

The wheel currently exposes generic top-level packages (`core`, `net`, `app`,
`client`). Moving to `bonnet.core`, `bonnet.net`, `bonnet.app`, and
`bonnet.client` is a broad import and packaging change that is deferred.

This cleanup cycle will:

- remove `sys.path` hacks from `app/server.py` and `app/main.py`;
- verify that wheel installation and console entry points work correctly with
  the current package layout;
- ensure the PyInstaller spec references actual module names.

The namespace migration is a separate focused change after test coverage and
lifecycle reliability are in place.

## Phase 1: Establish Regression Coverage

### Objective

Create a trustworthy safety net around the server's highest-risk behavior
before changing production logic.

### Decisions

- **Import strategy:** Add `pythonpath = ["src"]` to
  `[tool.pytest.ini_options]` in `pyproject.toml`. Remove all `sys.path.insert`
  calls from individual test files. Tests work in IDEs, CI, and CLI without
  `PYTHONPATH` environment variables.
- **asyncio mode:** Set `asyncio_mode = "auto"` in `pyproject.toml`. Async test
  functions are automatically detected without `@pytest.mark.asyncio`
  decorators. Existing sync tests that call `asyncio.run()` internally continue
  to work.
- **ASGI harness:** Use `httpx.ASGITransport` to wrap `FirehoseHTTPServer` in
  process. Tests use the real `FirehoseHTTPClient` to sign requests and verify
  responses, giving true end-to-end coverage of the HTTP path. `httpx` is
  already a dependency.
- **Parallelism:** Keep `-n auto` as the default. Mark tests that share state
  or use threads with `@pytest.mark.xdist_group` for serial execution within
  the parallel run. `@pytest.mark.slow` tests run only when explicitly
  requested.
- **Test naming:** New test files use descriptive names:
  `test_dispatcher.py`, `test_firehose_http_server.py`, `test_config.py`,
  `test_rate_limiter.py`, `test_server_lifecycle.py`. Existing phase-named
  files keep their names until they are rewritten.
- **Commit order:** Follow the plan's suggested order — fixtures first, then
  dispatcher tests, then ASGI, then config, rate-limiter, and lifecycle.

### Work

#### Dispatcher and Projection Tests

- add a test that forces a projection method to raise during dispatch;
- assert that the origin checkpoint remains immediately before the failing
  record;
- assert that later records are not dispatched past the failed record;
- assert that retrying after the fault is removed applies the failed record and
  advances normally;
- add a multi-origin rebuild test with records from at least two origins;
- rebuild one origin and prove that navigation, users, policy, and board state
  for the other origin remain unchanged;
- add tests for unknown boardless records and projection idempotency;
- add tests proving per-projection checkpoints never exceed the origin-level
  checkpoint.

Likely files:

- `tests/test_phase2.py`
- `src/core/dispatcher.py`
- `src/core/global_projections.py`
- `src/core/board_projection.py`

#### ASGI Server Tests

Build an in-process ASGI harness or use `httpx.ASGITransport` where practical.
Do not start a real external listener for unit and integration tests.

Cover:

- signed discovery response structure;
- valid signed command request and signed response;
- missing and malformed authentication headers;
- invalid content digest;
- unsupported protocol and content type;
- replayed nonce rejection;
- anonymous, unknown, registered, moderator, and administrator contexts;
- rate-limit acceptance and rejection;
- oversized body rejection during streaming;
- sanitized internal-error responses;
- lifespan startup and shutdown;
- repeated resource close without exception.

Likely new file:

- `tests/test_firehose_http_server.py`

#### Configuration Tests

Cover:

- complete TOML loading;
- defaults for omitted optional values;
- origin normalization;
- ACL loading through an actual TOML file;
- peer loading;
- TLS settings;
- missing configuration behavior;
- invalid ports, sizes, windows, lifetimes, and paths;
- bind-host configuration once implemented.

Likely new file:

- `tests/test_config.py`

#### Rate Limiter Tests

Cover:

- requests below and above the limit;
- expiry at the window boundary;
- stale-bucket cleanup;
- address and identity key construction;
- unknown-key behavior;
- concurrent checks against one bucket;
- high-cardinality key cleanup.

Likely new file:

- `tests/test_rate_limiter.py`

#### Lifecycle Tests

Cover:

- construction against temporary directories;
- root registration on first startup;
- idempotent root registration on restart;
- startup failure when required initialization fails;
- sync-client and SQLite cleanup;
- repeated `close()` calls;
- SIGTERM-triggered shutdown once signal handling is implemented.

Likely new file:

- `tests/test_server_lifecycle.py`

#### Existing Test Repairs

- make the equivocation test require an actual stored conflict instead of
  conditionally asserting only when one happens to exist;
- move the identity test database under `tmp_path`;
- remove the unused repository-local temporary-directory fixture;
- standardize import setup so tests run through `pytest`, IDEs, and CI without
  per-file `sys.path` edits;
- choose and configure one `pytest-asyncio` mode;
- review thread-test timeouts for slow CI environments.

### Acceptance Criteria

- Each critical defect scheduled for Phases 2 through 6 has a failing or
  behavior-locking test.
- Tests create no files in the repository root.
- Tests pass both serially and with the project's selected parallel mode.
- No test relies on committed identities, certificates, runtime databases, or
  live network services.

### Suggested Commit Boundaries

1. Repair stale and unsafe test fixtures.
2. Add dispatcher and rebuild regression tests.
3. Add ASGI integration harness and request-path tests.
4. Add configuration tests.
5. Add rate-limiter tests.
6. Add lifecycle tests.

## Phase 2: Repair Projection Integrity

### Objective

Guarantee that projection failures are visible, retryable, and isolated to the
affected origin.

### Decisions

- **Dispatch failure behavior:** Hard stop. When a projection method raises,
  stop dispatching the origin immediately. The checkpoint remains at the record
  before the failure. Later records are not dispatched until the fault is
  cleared and dispatch is retried. No dead-letter or skip mechanism is
  introduced.
- **Cross-origin user revocation:** Deferred to the Gate D punishment schema
  work, which will revisit cross-origin moderation semantics holistically.
  Current behavior remains unchanged in this phase.

### Work

#### Stop Checkpoint Advancement on Failure

In `src/core/dispatcher.py`:

- move origin checkpoint advancement inside the successful dispatch path;
- stop processing the origin when one record fails;
- return a count containing only successfully dispatched records;
- log the failing origin, sequence, event ID, and kind;
- leave the failed record available for retry;
- avoid adding an implicit dead-letter or skip mechanism without a separate
  explicit design.

#### Make Rebuild Origin-Safe

- add origin-scoped clear operations to navigation, user, and policy
  projections, or rebuild all origins when using global clears;
- prefer origin-scoped deletion to avoid unnecessary downtime and work;
- clear only board-projection instances belonging to the selected origin;
- preserve records and projection state for every other origin;
- keep rebuild and dispatch mutually exclusive under the dispatcher lock;
- ensure lock ordering is consistent between dispatcher and board caches.

#### Make Projection Checkpoints Real

- update each applicable projection checkpoint after state mutation and
  idempotency marking;
- perform mutation, applied-event marking, and checkpoint update in one SQLite
  transaction;
- advance the origin-level checkpoint only after every applicable projection
  commits successfully;
- define behavior for records that intentionally apply to no projection;
- expose checkpoint inspection through public methods rather than direct
  connection access.

#### Correct Unknown-Kind Handling

- remove the private, unlocked call to `NavProjection._mark_applied`;
- define a transaction-safe no-op application path for unknown boardless
  records;
- preserve unknown records in the firehose for relay and replay;
- do not misrepresent unknown events as navigation events merely to track
  idempotency.

#### Remove Projection Logic Debris

- remove the unreachable `visibility='restored'` cancel path;
- remove dead query variables;
- make pending-control replay consistently update `latest_control_seq` where
  that field is intended to represent all controls;
- test pending cancel, restore, purge, pin, unpin, thread-close, and
  thread-reopen records received before their target;
- review cross-origin user revocation semantics before changing them.

### Acceptance Criteria

- A failed projection never advances any checkpoint past the failed record.
- Retrying dispatch after a transient failure succeeds without duplicate state.
- Rebuilding origin A cannot alter projected state for origin B.
- Projection databases can be deleted and deterministically rebuilt from the
  firehose.
- Unknown kinds remain relayable and cannot break dispatch.

### Suggested Commit Boundaries

1. Stop checkpoint advancement on dispatch failure.
2. Add origin-scoped global projection clearing.
3. Make rebuild origin-safe.
4. Implement transactional per-projection checkpoints.
5. Correct unknown-kind application.
6. Remove isolated projection dead code.

## Phase 3: Harden Publication and Persistence

### Objective

Ensure local publication validates all configured limits and semantic gates
before creating durable records or body files.

### Decisions

- **Event body limits:** Apply `max_article_body_size` to all body-bearing
  records, not just articles. One limit, one check. Non-article event bodies
  are typically smaller than articles and do not warrant a separate config
  knob.
- **NFC encoding strategy:** Auto-normalize text to NFC at encode time in
  `enc_text16`. Any valid Unicode input becomes canonical. Clients do not need
  to pre-normalize. The protocol's "MUST be NFC" requirement is guaranteed on
  the wire by the encoder rather than pushed to every caller.
- **Effective-ban enforcement:** Blocked on Gate D. The punishment schema
  redesign (three typed kinds, per-type per-origin import filtering,
  server-tracked acknowledgment) must be implemented before the publish gate
  can be wired. This is the largest single work item in the phase and may be
  split into its own sub-phase.

### Work

#### Enforce Body Limits

- reject an intent whose declared body size exceeds the configured article
  limit before copying or staging the body;
- decide whether non-article event bodies need a separate limit;
- reject request/body size inconsistencies before hashing;
- return stable, documented error codes for each limit violation;
- ensure no rejected request leaves a staged body behind.

#### Unify Verified Body Writes

In `src/core/bodies.py`:

- centralize temporary write, flush, size verification, hash verification, and
  atomic rename;
- use the same verified path for local staging, remote article caching, and
  event bodies;
- remove temporary files after verification or rename failures;
- make staging cleanup tolerate concurrent deletion and unexpected directory
  entries;
- keep reads defensive by rechecking expected size and hash;
- test that retrying a purge after body corruption is safe and leaves no
  partial state;
- bound body-search process output and total results.

#### Harden Cryptographic Input Handling

- make `Identity.verify()` return `False` for malformed public-key and signature
  lengths rather than leaking library exceptions;
- validate Ed25519 public keys as exactly 32 bytes at schema boundaries;
- validate signatures as exactly 64 bytes before cryptographic calls;
- validate all metadata fields that represent IDs or public keys as exactly 32
  bytes;
- add malformed-input tests for local publication and remote acceptance.

#### Enforce Canonical Encoding

- prevent encoders from producing text their decoders reject;
- reject or normalize non-NFC top-level text consistently;
- require printable ASCII for record kinds;
- document whether normalization is rejection or canonicalization before
  signing;
- add round-trip and rejection tests for origins, boards, kinds, usernames, and
  hostnames.

#### Effective-Ban Gate

This work is blocked on Decision Gate D.

After approval:

- calculate effective status through one policy-projection method;
- account for revocation, warning status, expiry, trusted origins, and local
  enforcement settings;
- perform the check before body staging and firehose append;
- fail closed or explicitly fail open according to the approved policy when the
  policy projection is unavailable;
- test ordinary users, moderators, administrators, expired punishments,
  revoked punishments, warnings, and untrusted origins.

#### Persistence and Transaction Corrections

- correct remote-range accepted counts when processing stops at a conflict;
- add consistent SQLite busy timeouts where a database may be accessed by
  multiple threads or connections;
- replace direct external access to `FirehoseStore._conn` with locked public
  query methods;
- fix trust-key rotation so the update is conditional on the expected old key;
- verify that body-finalization and record-append failures do not produce
  unrecoverable partial state.

### Acceptance Criteria

- Configured body limits are enforced before durable writes.
- Every stored body has passed size and hash verification.
- Malformed cryptographic inputs produce deterministic rejection, not uncaught
  exceptions.
- Encoders cannot emit non-canonical records.
- Publication policy is enforced exactly as approved.
- Persistence tests pass under concurrent append, dispatch, and read activity.

### Suggested Commit Boundaries

1. Enforce configured body limits.
2. Centralize verified atomic body writes.
3. Harden malformed cryptographic input handling.
4. Enforce canonical record text and kind encoding.
5. Fix accepted-count and trust-rotation transaction defects.
6. Add effective-ban enforcement after approval.

## Phase 4: Harden the HTTP Boundary

### Objective

Make every HTTP request path bounded, authenticated according to policy, and
safe under malformed or adversarial input.

### Decisions

- **Anonymous replay protection:** Skip the replay ledger for anonymous
  requests. The shared anonymous key is public by design (Gate A), so replay
  tracking is meaningless — anyone can generate fresh signed requests with the
  public key. Address-based rate limiting is the real DoS defense for anonymous
  traffic.
- **Signature tightening:** Gate E is approved — require request `expires` and
  response `bonnet-request-nonce` immediately. Current clients already send
  both.

### Work

#### Bound Streaming Request Bodies

- track cumulative bytes while consuming ASGI request messages;
- stop retaining chunks as soon as the configured request limit is exceeded;
- drain or terminate the request according to ASGI server requirements;
- distinguish disconnect, malformed receive messages, and oversized input;
- ensure the handler never constructs an oversized joined byte string;
- test one-chunk and many-chunk oversized bodies.

#### Correct Rate-Limit Identity

- apply an address-based limit to every request;
- optionally apply an additional identity limit to authenticated registered
  identities;
- do not grant a fresh unrestricted budget to every unregistered public key;
- retain a documented proxy-address policy rather than trusting forwarded
  headers by default;
- invoke stale-bucket cleanup periodically or amortize it across requests;
- cap high-cardinality bucket growth defensively.

#### Replay Protection

- decide whether anonymous requests require replay storage under the approved
  anonymous-authentication design;
- validate nonces before accessing the replay ledger;
- require expiry after Decision Gate E approval;
- ensure replay records expire and are cleaned without unbounded database
  growth;
- test replay behavior across process restart and clock-skew boundaries.

#### Fail Closed and Sanitize Errors

- return a generic internal-error message to remote clients;
- log the concrete exception with request context server-side;
- do not expose filesystem paths, SQL errors, or internal exception strings;
- fail discovery if its required signature cannot be produced;
- keep protocol error bodies and status codes stable and documented;
- centralize command error codes rather than scattering magic values.

#### Validate Command Fields Before Parsing

- validate integer, boolean, key, ID, string, and collection lengths before
  indexing or `struct.unpack`;
- ensure malformed commands return protocol errors rather than generic internal
  failures;
- fuzz command parsing with arbitrary byte strings;
- ensure decoding work is bounded by configured request size and per-command
  result limits.

#### Signature Verification Tightening

This work is partially blocked on Decision Gate E.

After approval:

- require request `created`, `expires`, and nonce parameters;
- require signed response request-nonce coverage and exact value matching;
- enforce configured maximum lifetime and clock skew within protocol maxima;
- validate that signed authority matches the configured deployment authority or
  an explicit trusted-host configuration;
- test missing, duplicated, malformed, expired, and future parameters.

#### Projection Cache Concurrency

- protect the command handler's board-projection cache with a lock;
- avoid check-then-create races and leaked SQLite connections;
- close all cached projections exactly once;
- test concurrent first access to the same and different boards.

### Acceptance Criteria

- Oversized streaming input is rejected before full buffering.
- Rotating unknown keys cannot bypass address limits.
- Rate-limit storage remains bounded after high-cardinality traffic.
- Malformed commands never leak internal errors or crash request handling.
- Approved signature requirements are enforced symmetrically by server and
  client.
- Concurrent requests do not leak projection connections.

### Suggested Commit Boundaries

1. Enforce request limits while streaming.
2. Add layered address and identity rate limiting.
3. Schedule or amortize bucket cleanup.
4. Sanitize HTTP and command errors.
5. Validate binary command field lengths.
6. Protect board-projection caching.
7. Tighten signature requirements after approval.

## Phase 5: Harden Federation

### Objective

Bound all remote synchronization work, make trust decisions explicit, and close
every federation resource reliably.

### Decisions

- **Batch conflict behavior:** Keep committed batches, stop at the conflict,
  and let the next sync cycle resume from where it stopped. Records already
  accepted are permanent — matches the append-only firehose model. Conflicts
  are stored and stop advancement, same as today.
- **Dial-target validation:** Gate C is approved — reject non-global addresses
  by default, explicit `allow_private_dial` required for private/loopback.
- **Discovery trust:** Gate B is approved — layered PKI + TOFU + operator pins.

### Work

#### Centralize Dial-Target Validation

This work is blocked on Decision Gate C.

After approval:

- parse and validate hostname syntax before dialing;
- resolve all returned addresses and reject any disallowed address;
- defend against DNS rebinding by validating the address actually used where
  the HTTP stack permits it;
- apply identical policy to configured peers, body redirects, relay tracing,
  and every future server-supplied URL;
- reject unsupported schemes, embedded credentials, fragments, and malformed
  ports;
- make private-network access an explicit configuration choice;
- test IPv4, IPv6, localhost names, private ranges, link-local ranges,
  multicast, reserved addresses, mixed DNS answers, and redirects.

#### Process Sync in Bounded Batches

- validate remote head sequence ranges before allocation or looping;
- fetch and accept bounded batches instead of collecting an entire remote range
  in memory;
- preserve chain and signed-head verification across batch boundaries;
- avoid holding the firehose writer lock for the full remote backlog;
- define behavior when a later batch conflicts or fails after earlier batches
  were committed;
- store witnesses incrementally after accepted records;
- cap per-cycle records and allow later cycles to continue catch-up.

#### Consolidate Sync Logic

- remove the duplicated checked and unchecked sync implementations;
- keep one implementation with an explicit caller policy for allowlist bypass;
- ensure manual operator sync remains visibly distinct from automatic sync;
- keep common verification, batching, dispatch, and witness logic in one path.

#### Verify Witness Chaining and Tracing

- test multi-hop witness creation through the real relay path;
- verify that tracing follows each signed upstream hop in order;
- reject malformed, cyclic, or unverifiable witness chains within a bounded
  hop count;
- ensure tracing behavior matches the approved trust model and documentation.

#### Respect Backoff Everywhere

- apply peer backoff to periodic and on-demand sync;
- avoid hammering a failing peer when remote reads repeatedly queue sync;
- bound queue size and deduplicate queued origins;
- expose enough state for diagnostics without leaking internals;
- test exponential growth, maximum backoff, jitter bounds, reset after success,
  and cancellation.

#### Close Federation Resources

- capture clients before clearing the manager's client map;
- cancel and await tasks;
- close each HTTP client exactly once;
- clear queued and inflight state safely;
- make `stop_origin()` and `stop_all()` idempotent;
- ensure server shutdown always awaits federation shutdown before closing shared
  stores.

#### Clarify First-Contact Trust

This work is blocked on Decision Gate B.

After approval:

- persist or configure the selected trust anchor;
- verify signed discovery according to the approved model;
- reject unexpected key changes;
- test rotation through the real sync path;
- document operator recovery for stale or compromised pins;
- avoid claiming first-contact MITM resistance when running in pure TOFU mode.

### Acceptance Criteria

- No federation path can dial a disallowed target under the configured policy.
- A maliciously large head cannot cause unbounded memory growth or one
  unbounded write transaction.
- Periodic, on-demand, and manual synchronization share one verified core path.
- Backoff applies consistently.
- Shutdown leaves no open HTTP pools or sync tasks.
- Trust guarantees are accurately tested and documented.

### Suggested Commit Boundaries

1. Consolidate duplicate sync paths without changing behavior.
2. Add bounded sync-cycle and batch processing.
3. Apply backoff to queued sync.
4. Close clients and make shutdown idempotent.
5. Add multi-hop witness chaining and tracing tests.
6. Add dial-target validation after approval.
7. Implement the approved discovery and trust model.

## Phase 6: Fix Configuration and Lifecycle

### Objective

Make startup, operation, shutdown, and installed execution predictable across
supported environments.

### Decisions

- **SIGHUP reload:** Not supported. Configuration changes require a restart.
  Simpler, fewer edge cases, works identically on Windows. Document that
  SIGHUP is ignored and restart is the reload mechanism.
- **Package namespace:** Gate F is deferred — keep current layout, fix
  `sys.path` hacks, verify wheel installation. Namespace migration is a
  separate focused change after this cleanup cycle.

### Work

#### Validate Configuration

Validate at load time:

- non-empty normalized origin and hostname;
- host syntax;
- port range from 1 through 65535;
- positive request, body, rate, search, and sync limits;
- signature lifetime and clock skew within approved protocol maxima;
- TLS certificate and key presence when TLS is enabled;
- CA bundle type and path;
- peer origin, hostname, port, and duplicate-origin constraints;
- ACL rule shape and principal selectors;
- data paths that conflict with existing files or have unwritable parents.

Errors should identify the configuration field and invalid value without
exposing secrets.

#### Separate Load From Initialization

- stop silently creating a default file when a requested path is missing;
- fail startup with a clear missing-config error;
- add an explicit command or flag to create a sample configuration if desired;
- keep sample generation deterministic and testable;
- never start with a different in-memory configuration than the file just
  created.

#### Make Binding Explicit

- add configurable bind host;
- support a CLI override only if precedence is documented and tested;
- retain a deliberate default rather than a hardcoded value;
- document safe local-only and externally reachable examples.

#### Establish One Shutdown Owner

- make `BonnetFirehoseServer.close()` the authoritative cleanup path;
- remove component closes from ASGI lifespan when they are owned by the outer
  server, or clearly transfer ownership;
- close resources in dependency order: stop accepting work, stop sync, close
  command/projection caches, close stores, then close logging;
- make every close method idempotent;
- preserve the first shutdown error while attempting remaining cleanup;
- test startup failure cleanup as well as normal shutdown.

#### Handle Process Signals

- handle SIGTERM in addition to keyboard interruption;
- request uvicorn shutdown through its supported interface;
- cancel the REPL task without leaving executor work attached;
- decide whether SIGHUP reload is supported or explicitly unsupported;
- ensure REPL `quit` requests server shutdown rather than only exiting the
  prompt loop.

#### Fix Installed Execution and Packaging

- remove source-tree `sys.path` modifications;
- verify console entry points from an installed wheel;
- ensure package discovery includes every runtime module;
- repair or remove stale PyInstaller configuration;
- resolve duplicate and conflicting development dependency groups;
- provide a supported Windows build path or document the required environment;
- address the package namespace only after Decision Gate F.

### Acceptance Criteria

- Invalid configuration fails before server resources are opened.
- A missing configuration file is not silently created during normal startup.
- Bind address and CLI precedence are documented and tested.
- SIGTERM and REPL exit perform a complete, exception-free shutdown.
- Repeated close calls are harmless.
- A clean wheel can be installed and both declared entry points start far
  enough to validate imports and argument parsing.

### Suggested Commit Boundaries

1. Add configuration validation.
2. Separate configuration loading and creation.
3. Add configurable bind host and tested precedence.
4. Make resource cleanup idempotent and singly owned.
5. Add graceful process-signal shutdown.
6. Remove source path hacks and verify wheel entry points.
7. Repair or remove standalone build configuration.

## Phase 7: Clean the Current Repository Tree

### Objective

Make the checked-out tree contain only intentional project assets without
rewriting existing Git history.

### Work

#### Remove Tracked Runtime and Sensitive Material

Review and remove from the current tree as appropriate:

- tracked TLS private key and certificate;
- likely private test identity material;
- `.pytest_tmp/` databases, WAL files, journals, and body data;
- `.vs/` workspace state;
- tracked runtime board bodies;
- debug dumps and personal run notes;
- stale identity databases and local runtime state;
- obsolete benchmark code importing nonexistent modules.

Do not print private key contents during cleanup or review.

#### Rebuild `.gitignore`

- remove the stray `=======` line;
- deduplicate the merged Python templates;
- keep project-specific rules clear and grouped;
- ignore `.pytest_tmp/`, `.vs/`, runtime databases and journals, generated body
  storage, logs, identities, certificates, private keys, local config, and
  build output;
- keep files that are intentionally tracked, such as a maintained build spec,
  explicitly unignored;
- verify rules with `git check-ignore` against representative paths.

#### Sanitize Shipped Configuration

- replace live hostnames and operator keys with reserved examples;
- do not point sample configuration at real certificate paths;
- avoid normalizing disabled TLS verification without explanation;
- ship a clearly named example configuration if runtime config should remain
  untracked;
- ensure examples match the actual loader and validation rules.

#### Normalize Test Artifacts

- use pytest-managed temporary paths exclusively;
- configure cache and temporary retention intentionally;
- verify the full suite leaves `git status --short` unchanged;
- add a CI check for a dirty tree after tests and builds where practical.

### Acceptance Criteria

- The current tree contains no private key, runtime database, live board body,
  IDE state, or test-generated artifact.
- `.gitignore` has no merge debris or redundant generated template sections.
- Sample configuration contains no real operator identity or deployment domain.
- Running tests from a clean checkout leaves the checkout clean.
- Existing Git history remains untouched, as required.

### Suggested Commit Boundaries

1. Remove tracked generated and runtime artifacts.
2. Remove current-tree credential material without history rewriting.
3. Replace `.gitignore` with a concise project-specific version.
4. Add sanitized example configuration.
5. Remove or rewrite stale benchmark and local run artifacts.

## Phase 8: Make Documentation and Tooling Reviewable

### Objective

Replace historical cruft with documentation and automation that accurately
describe and protect the shipping implementation.

### Work

#### Documentation Inventory

Classify every existing Markdown file as one of:

- current and retained after verification;
- rewritten from the source implementation;
- historical and moved under `docs/archive/` with a warning;
- deleted because it is misleading and has no archival value.

Do not incrementally patch a document whose architecture is obsolete. Rewrite
it or archive it.

#### README

Create a concise public entry point containing:

- project purpose and maturity status;
- supported Python versions and platforms;
- installation with the selected package manager;
- minimal secure server startup;
- configuration location and sample;
- high-level architecture;
- test and development commands;
- protocol and operator documentation links;
- security reporting link;
- license statement.

#### Protocol Documentation

Derive current behavior from source and tests, then:

- document the actual record and command formats;
- document authentication and trust guarantees without overclaiming;
- document exact limits and failure behavior;
- document projection and checkpoint invariants;
- document federation allowlists, dial policy, backoff, and trust bootstrap;
- document anonymous access after Decision Gate A;
- remove completed migration maps and references to nonexistent modules;
- add conformance examples generated or checked by tests where practical.

#### Operator Guide

Rewrite around the current server:

- generating identities and TLS material;
- creating and validating configuration;
- setting ACL rules;
- starting and stopping the server;
- storage layout and backup expectations;
- peer setup and trust bootstrap;
- key rotation and pin recovery;
- rebuilding projections;
- interpreting logs and health failures;
- upgrading and rollback limitations;
- incident response for exposed credentials.

#### Glossary and Architecture

- remove obsolete engine terminology;
- define firehose, intent, record, witness, origin, projection, dispatcher,
  relay, checkpoint, and effective punishment;
- add a concise data-flow diagram matching current module names;
- keep implementation details out of the glossary where possible.

#### Public Project Files

Add:

- `SECURITY.md` with private reporting instructions and support expectations;
- `CONTRIBUTING.md` with environment setup, tests, style, and commit guidance;
- changelog or release-note policy;
- copyright and license attribution;
- optional code of conduct if external contributions are invited.

#### Automated Quality Gates

Add CI that runs on supported Python versions and includes:

- clean dependency installation from the lockfile;
- linting with Ruff or an approved equivalent;
- formatting verification;
- type checking at an initially achievable strictness;
- serial and parallel tests;
- slow/security tests on an appropriate schedule;
- wheel build and installed-entry-point smoke tests;
- dependency vulnerability audit;
- secret scanning;
- verification that test runs and builds do not dirty the tree.

Adopt lint and type rules incrementally. Avoid a single mass-fix commit that
mixes formatting with behavior changes.

### Acceptance Criteria

- No retained public document describes nonexistent modules or discarded
  architecture as current.
- README instructions work from a clean checkout.
- Operator configuration examples pass the actual loader.
- Protocol claims are backed by tests or clearly marked as design decisions.
- CI runs automatically and blocks known test, lint, build, and packaging
  regressions.
- Security and contribution channels are documented.

### Suggested Commit Boundaries

1. Inventory and archive obsolete documents.
2. Rewrite README.
3. Rewrite current protocol documentation.
4. Rewrite operator guide and glossary.
5. Add security and contribution documents.
6. Add lint and formatting checks without mass behavior edits.
7. Add type checking with a documented baseline.
8. Add test, build, audit, and clean-tree CI jobs.

## Phase 9: Final Nitpick Pass

### Objective

Remove avoidable review noise only after correctness, security, and behavioral
coverage are stable.

### Work

#### Dead Code and Duplication

- remove unused kind sets and validators;
- remove unused logging helpers or route them through thread-safe logging;
- remove unused exceptions and stale compatibility comments;
- remove dead conditional expressions and always-true branches;
- remove redundant lazy imports and duplicate imports;
- remove duplicated sync logic if not already completed;
- remove unused checkpoint APIs only if the corrected dispatcher does not need
  them.

#### API and Encapsulation Cleanup

- replace direct access to private connections and projection internals with
  narrow public methods;
- standardize ownership and close semantics;
- verify that error-code definitions are centralized;
- standardize modern Python type syntax;
- document non-obvious public methods and remove misleading docstrings;
- avoid broad compatibility wrappers without a demonstrated consumer.

#### Performance and Resource Bounds

- bound aggregate cross-origin article list and search operations;
- avoid loading full body files merely to produce excerpts;
- bound ripgrep output and use fixed-string mode when regex behavior is not
  explicitly requested;
- use efficient incremental hashing and metadata encoding where worthwhile;
- profile before introducing abstractions or caches.

#### Logging and Observability

- make log initialization failure visible;
- serialize writes through one thread-safe logging path;
- include request, origin, sequence, and event context where relevant;
- avoid logging secret keys, body contents, bearer tokens, or raw credentials;
- define log levels and rotation expectations;
- ensure shutdown flushes and closes logs.

#### Structural Refactoring

Only after tests cover behavior:

- separate REPL concerns from the oversized server bootstrap class;
- keep component construction in one clear composition root;
- avoid splitting code solely to reduce line count;
- move to a `bonnet.*` namespace only if Decision Gate F approves it;
- perform moves separately from behavior changes to preserve reviewability.

#### Final Verification Matrix

Run and record:

- focused unit tests;
- full serial tests;
- full parallel tests;
- slow tests;
- concurrency tests under repetition;
- ASGI server/client integration tests;
- multi-origin federation and rotation tests;
- malformed-input and fuzz tests;
- lint and formatting checks;
- type checking;
- dependency and secret audits;
- wheel build and clean-environment install;
- entry-point smoke tests;
- standalone build, if retained;
- Linux and Windows checks for claimed support;
- clean-tree verification after every command.

### Acceptance Criteria

- Static checks contain no unexplained suppressions.
- Public APIs do not require callers to reach into private SQLite connections
  or projection internals.
- Expensive read and search paths have explicit bounds.
- The server starts, serves, synchronizes, rebuilds, and shuts down cleanly in a
  fresh environment.
- The final diff contains no generated files, secrets, live configuration, or
  obsolete documentation.
- Remaining known limitations are documented rather than hidden.

### Suggested Commit Boundaries

1. Remove proven dead code.
2. Replace private connection access with narrow APIs.
3. Bound aggregate queries and body search.
4. Consolidate logging behavior.
5. Extract REPL concerns after coverage exists.
6. Apply approved package namespace changes separately.
7. Address final static-analysis findings in focused commits.

## Cross-Phase Test Requirements

The following scenarios are mandatory before declaring the repository
public-ready:

- projection failure does not advance checkpoints;
- rebuilding one origin preserves every other origin;
- deleting projection databases and replaying the firehose reconstructs exact
  state;
- all article controls work when received before their target;
- body corruption is detected and purge retry is safe;
- malformed keys, signatures, records, commands, and HTTP signatures fail
  closed;
- oversized streaming requests are rejected before full buffering;
- unknown-key rotation cannot evade address limits;
- replay protection survives restart;
- federation rejects disallowed dial targets;
- federation sync is bounded and resumes across cycles;
- key rotation works through the real federation path;
- equivocation stops automatic advancement;
- unknown kinds survive storage, sync, relay, and rebuild;
- multi-hop witnesses and tracing behave as documented;
- effective punishments gate publication exactly as approved;
- startup failure and normal shutdown close all opened resources;
- installed wheel entry points import and start correctly;
- tests and builds leave the repository clean.

## Deferred or Conditional Work

The following work should not be smuggled into unrelated cleanup:

- anonymous-authentication redesign;
- package namespace migration;
- cross-origin user revocation semantic changes;
- moderator or administrator ban bypass behavior;
- compatibility adapters for historical protocols;
- database migrations for formats not proven to exist in deployed data;
- broad server-class decomposition before lifecycle coverage;
- Git history rewriting.

Each item requires an explicit need, design discussion, and independent plan or
approved extension to this document.

## Completion Definition

Bonnet is public-ready when all of the following are true:

- Phases 1 through 8 are complete and Phase 9 has no release-blocking finding.
- Every decision gate is either resolved and implemented or documented as an
  intentional retained behavior.
- The full verification matrix passes from a clean checkout.
- Current-tree credentials and runtime artifacts are removed.
- Public documentation matches the tested implementation.
- CI reproduces the project's required checks.
- No known correctness defect can silently lose projection state.
- No known untrusted-input path permits unbounded memory, storage, subprocess,
  or network work without an explicit operator-controlled limit.
- Remaining risks and compatibility constraints are stated plainly in release
  documentation.
