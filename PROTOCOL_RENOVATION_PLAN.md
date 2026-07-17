# Bonnet Protocol Renovation Plan

Status: Proposed

Target: Bonnet protocol v2

Primary decision: Replace the one-command-per-WebSocket protocol with an HTTPS
command endpoint authenticated using Bonnet Ed25519 HTTP Message Signatures.

## 1. Executive Summary

Bonnet is a command-response system. Its WebSocket currently exists primarily
to support a stateful challenge-response handshake, but the server processes one
command and closes the socket. On top of WebSocket, Bonnet implements another
length-prefixed framing layer and a custom encrypted session.

Protocol v2 will use the layers according to their actual responsibilities:

* HTTP owns command-response semantics, message boundaries, connection reuse,
  cancellation, timeouts, and status codes.
* TLS owns transport confidentiality, integrity, and forward secrecy. A TLS
  certificate identifies a network endpoint; it is not a Bonnet identity.
* RFC 9421 HTTP Message Signatures own proof of possession of Bonnet Ed25519
  identity keys.
* RFC 9530 `Content-Digest` fields bind signatures to command and response
  bodies.
* Bonnet TOFU and signed key rotation bind logical origins to Bonnet Ed25519
  keys independently of DNS and TLS certificates.
* The existing binary command and response bodies remain intact during the
  transport renovation. Replacing their encoding is a separate project.

This design eliminates the connection handshake without replacing Bonnet's
identity model. Each authenticated request proves the client key directly, and
each response proves the server/origin key directly.

## 2. Why Renovation Is Required

### 2.1 Current lifecycle

The current server lifecycle in `src/app/server.py` is:

1. Upgrade an HTTP connection to WebSocket.
2. Send the server public key and a random challenge.
3. Receive the client public key and its signature over the challenge.
4. Convert the static Ed25519 keys to X25519 keys.
5. Create a NaCl `Box` session.
6. Receive one encrypted command.
7. Send one encrypted response.
8. Close the WebSocket.

The federation client in `src/net/sync.py` assumes the opposite lifecycle: it
tries to issue several commands over one connection. The protocol abstraction
and server implementation therefore disagree about connection ownership.

### 2.2 Demolition inventory

The following mechanisms become unnecessary in protocol v2:

* `ConnectionMode` and most of `ConnectionState` in
  `src/net/connection.py`.
* The client and server WebSocket handshake implementations.
* The additional four-byte length prefix inside every WebSocket message.
* The application-level static-key `EncryptedSession` used for command traffic.
* The duplicate client `EncryptedSession` implementation.
* The encrypted, interactive username-selection exchange.
* One-WebSocket-per-tool-call lifecycle code.
* WebSocket-specific sync retry and cleanup code.
* The `websockets` runtime dependency after protocol v1 is removed.

The existing command codec, command handler, authorization checks, engine,
content signatures, SSRF protections, peer-key database, and key-rotation rules
are not demolition targets.

### 2.3 Existing security defects to retire

The renovation must not preserve these properties accidentally:

* The normal client accepts the server key received on each connection without
  checking a persistent origin-to-key pin.
* Static identity keys are used directly to derive command-encryption keys, so
  command traffic has no forward secrecy.
* The client-side encryption nonce counter starts at zero for every connection
  while the static encryption key remains the same.
* The server challenge proves the client key, but the client has no persistent
  proof that the responding key is the expected Bonnet origin key.
* Rate limits are stored on a connection that handles only one request, making
  the general request limit ineffective.
* The inner length prefix is not checked strictly against the actual WebSocket
  message length.
* Unexpected server exceptions are swallowed without useful diagnostics.

## 3. Goals

Protocol v2 must:

1. Preserve Ed25519 public keys as Bonnet user, server, relay, and origin
   identities.
2. Keep Bonnet identity independent of DNS names and TLS certificates.
3. Authenticate command bodies and all security-relevant request metadata.
4. Authenticate responses with the responding server's Bonnet identity key.
5. Reject replayed authenticated commands.
6. Preserve confidentiality, integrity, and forward secrecy in transit.
7. Preserve anonymous commands and their default-deny policy.
8. Preserve explicit username selection when one key owns several users.
9. Preserve federation TOFU, old-key-authorized rotation, origin signatures,
   relay separation, and SSRF protections.
10. Preserve existing binary command semantics during the migration.
11. Fail closed on malformed signatures, stale requests, unknown keys, key-pin
    mismatches, oversized bodies, and unsupported protocol versions.
12. Make resource limits effective across HTTP connections.
13. Produce a protocol that can be implemented by clients without copying
    Bonnet's Python internals.

## 4. Non-Goals

The initial renovation will not:

* Turn every command into a REST resource.
* Replace the binary command payloads with JSON, CBOR, or Protocol Buffers.
* Replace Ed25519 identities with X.509 identities.
* Replace TOFU with a certificate authority or DNS-based trust system.
* Add server push, subscriptions, or bidirectional streaming.
* Add OAuth, passwords, bearer tokens, cookies, or PAKE authentication.
* Redesign board, post, report, or key-rotation signature payloads.
* Permit automatic downgrade from protocol v2 to protocol v1.
* Introduce application encryption over TLS unless the deployment threat model
  explicitly requires protection from a TLS-terminating intermediary.

## 5. Trust Model

### 5.1 Separate transport from identity

Protocol v2 deliberately uses two independent trust layers:

* HTTPS establishes an encrypted transport to a network endpoint. It prevents
  passive observation, provides forward secrecy, and lets mature HTTP stacks
  handle connection mechanics.
* Bonnet message signatures establish which Ed25519 identity authored a request
  or response. Authorization and federation trust use only this layer.

A valid TLS certificate must never satisfy a Bonnet ACL, select a UME user,
authorize an origin, validate a board, or rotate a peer key. Conversely, a
Bonnet signature must not be treated as proof that a hostname is safe to dial.

### 5.2 User identity

An authenticated request carries a `keyid` containing the client's raw Ed25519
public key. The server verifies the signature first and then resolves that key
through UME. Usernames are labels selected after key authentication.

Registration uses the same mechanism. The registering public key is not yet in
UME, so the request supplies the raw key and proves possession directly.

### 5.3 Server and origin identity

Every protocol response is signed with `server_identity`. Clients associate the
configured logical origin with that public key using TOFU or a preconfigured
pin. A response from an unpinned first-contact key may establish a pin only
after its self-signature verifies.

This is still TOFU: the first observation can be intercepted. The protocol must
state this honestly and support out-of-band pin provisioning for deployments
that require first-contact authenticity.

### 5.4 Relay identity

The directly contacted relay signs its HTTP response. The relay signature
authenticates the response envelope, not the origin of every enclosed resource.
Boards and reports received through a relay continue to require their existing
origin signatures, verified against the origin's pinned key.

### 5.5 TLS requirement

Production remote endpoints require HTTPS. Cleartext HTTP may be allowed only
for explicitly configured loopback development endpoints.

TLS is required here for confidentiality and forward secrecy, not as a
replacement for Bonnet identity. If protection from a TLS-terminating reverse
proxy is a requirement, implementation must pause at the security decision gate
in section 15. That threat model requires an authenticated application channel,
preferably Noise, rather than an improvised encryption envelope.

## 6. Protocol v2 Surface

### 6.1 Versioning

The initial version identifier is `2`.

Every protocol response includes:

```text
Bonnet-Version: 2
Bonnet-Origin: <logical-origin>
```

Requests to versioned endpoints use `/v2`. Unknown versions fail with HTTP
`426 Upgrade Required` or `404 Not Found`; they never fall back automatically.

### 6.2 Discovery endpoint

```text
GET /.well-known/bonnet
```

The response body is a small canonical JSON document:

```json
{
  "protocol_versions": [2],
  "origin": "bbs.example.com",
  "public_key": "<lowercase-ed25519-hex>",
  "command_endpoint": "/v2/command"
}
```

The response is signed using the same response-signature profile as command
responses. On first contact, the included key verifies the self-signature and
becomes the TOFU candidate. On later contacts, the signature must verify against
the existing pin; an advertised replacement key is rejected unless authorized
through the existing key-rotation process.

The discovery key and the key used to sign command responses must be the same
`server_identity` key. They are one Bonnet identity, not independently
configurable keys. Key rotation must update discovery and command signing
atomically, after clients have received an old-key-signed rotation statement.

Discovery does not authorize resources and does not establish that the origin
string is truthful. It communicates the identity presented by the endpoint. The
JSON `origin` field is informational; the client compares the signed
`Bonnet-Origin` header with the logical origin it intended to contact.

### 6.3 Command endpoint

```text
POST /v2/command
Content-Type: application/vnd.bonnet.command
```

The request body remains:

```text
command-byte || existing-command-payload
```

The successful transport response body remains:

```text
existing-status-byte || existing-response-payload
```

This boundary allows `CommandHandler.handle()` and the current client command
builders and parsers to survive the transport migration.

### 6.4 HTTP status policy

HTTP status describes whether the protocol envelope was accepted:

* `200`: signature, replay, size, and protocol checks passed; the body contains
  the existing Bonnet command response, including command-level errors.
* `400`: malformed HTTP signature fields, nonce, username, digest, or envelope.
* `401`: an authenticated command lacked a valid client signature.
* `403`: the presented key is valid but cannot select the requested user.
* `409`: replayed nonce.
* `413`: HTTP body exceeds `max_request_size`.
* `415`: unsupported content type.
* `426`: unsupported Bonnet protocol version.
* `429`: identity/IP request limit exceeded.
* `500`: internal failure represented by a signed, generic response.
* `503`: a required service dependency is unavailable.

Once the envelope is accepted, command-level authorization remains in the
binary response so existing command clients retain their semantics.

All HTTP responses, including protocol errors where possible, are signed. A
client must not trust an unsigned error as a Bonnet-authenticated response.
Signed errors use a generic body with a matching `Content-Digest`. If the server
identity key is unavailable and the error cannot be signed, the server closes
the request without presenting an unsigned response as authoritative.

## 7. Authenticated Request Profile

### 7.1 Standards

Authenticated commands use:

* RFC 9421 HTTP Message Signatures.
* RFC 9530 `Content-Digest` using SHA-256.
* RFC 8032 Ed25519 signatures.

The implementation should use a maintained RFC 9421 library rather than
implementing Structured Fields parsing or signature-base canonicalization.
`http-message-signatures` is the initial candidate and must be pinned and tested
against RFC vectors before adoption.

### 7.2 Required fields

An authenticated request includes:

```text
Bonnet-Version: 2
Bonnet-Nonce: <unpadded base64url-encoded 32 random bytes>
Bonnet-Username: <selected username, when applicable>
Content-Digest: sha-256=:...:
Signature-Input: bonnet=(...);keyid="ed25519:<hex>";alg="ed25519";created=...;expires=...;nonce="...";tag="bonnet-v2"
Signature: bonnet=:...:
```

The signature labeled `bonnet` must cover exactly one accepted signature. The
server rejects ambiguous or additional signatures unless a future protocol
version defines them.

### 7.3 Mandatory covered components

The verifier requires these covered components:

* `@method`
* `@authority`
* `@target-uri`
* `content-type`
* `content-digest`
* `bonnet-version`
* `bonnet-nonce`
* `bonnet-username` when that field is present

`@authority` is signed to prevent cross-endpoint replay. It remains
client-supplied network metadata and must not be used as a Bonnet origin or ACL
input.

The verifier follows RFC 9421's "see what is signed" rule: authorization uses
only verified covered values returned by the signature verifier, never parallel
raw header values.

### 7.4 Signature parameters

The profile requires:

* `keyid`: `ed25519:` followed by exactly 64 lowercase hexadecimal characters.
* `alg`: exactly `ed25519`.
* `created`: integer Unix timestamp.
* `expires`: integer Unix timestamp no more than 60 seconds after `created`.
* `nonce`: identical to the covered `Bonnet-Nonce` value.
* `tag`: exactly `bonnet-v2`.

The server permits a configurable clock skew, initially 30 seconds. It rejects
requests created too far in the future, already expired, or valid for longer
than the protocol maximum.

Nonce encoding uses the RFC 4648 base64url alphabet without `=` padding. The
verifier rejects padding, non-canonical encodings, and values that do not decode
to exactly 32 bytes.

### 7.5 Replay prevention

Signature verification alone does not prevent replay. Before dispatching an
authenticated command, the server atomically records:

```text
(client_public_key, nonce, expires_at)
```

A duplicate record fails with `409` and is never dispatched.

The initial implementation should use a small SQLite replay ledger under
`data_dir` so process restarts do not reopen the validity window. Expired rows
are removed in bounded batches after successful insertions and during startup.
Rows remain until `expires_at + clock_skew_seconds` has passed. The table must
have a unique constraint on
`(publickey, nonce)` and insertion must occur in the same critical path as
verification, before any command side effect.

If the server later runs multiple workers or instances, they must share an
atomic replay store. An in-memory cache is not an acceptable silent substitute
in that deployment model.

### 7.6 Anonymous requests

Anonymous commands omit `Signature-Input`, `Signature`, and `Bonnet-Username`.
They still include `Bonnet-Version` and `Content-Digest`.

If an empty body is ever valid for an endpoint, its digest is SHA-256 over zero
bytes. `/v2/command` itself always requires at least the command byte.

The request context has no peer public key and no UME user. Existing
`public_commands` enforcement remains authoritative. Partial authentication
fields fail as malformed authentication rather than being treated as anonymous.

Anonymous rate limiting is keyed by a normalized remote address. Proxy-derived
client addresses are trusted only when the proxy itself is explicitly trusted.

### 7.7 Multiple usernames for one key

Interactive username selection is replaced by the signed `Bonnet-Username`
field:

1. Verify the request signature using the raw `keyid` public key.
2. Query all UME users associated with that key.
3. If there is one user and no username is supplied, select it.
4. If there are multiple users, require a signed username; omission fails with
   HTTP `403`.
5. Select only an exact username associated with the verified key.
6. Reject a supplied username that is not associated with the key.

Registration supplies the requested username inside the signed command body;
it does not require an existing UME record.

## 8. Signed Response Profile

Every response includes:

```text
Bonnet-Version: 2
Bonnet-Origin: <configured logical origin>
Bonnet-Request-Nonce: <request nonce, or empty for unsigned discovery>
Content-Digest: sha-256=:...:
Signature-Input: bonnet=(...);keyid="origin:<origin>";alg="ed25519";created=...;expires=...;tag="bonnet-v2"
Signature: bonnet=:...:
```

The response signature covers:

* `@status`
* `content-type`
* `content-digest`
* `bonnet-version`
* `bonnet-origin`
* `bonnet-request-nonce`

Echoing and signing the request nonce binds the response to the initiating
command. Clients reject a validly signed response carrying the wrong nonce.

Client verification order is:

1. Enforce response size limits.
2. Parse exactly one `bonnet` signature.
3. Determine the expected Bonnet key from the configured pin or first-contact
   TOFU procedure.
4. Resolve `keyid="origin:<origin>"` through that pin; the key-id string is a
   lookup name, not public-key material.
5. Verify required covered components and signature parameters.
6. Reject responses with stale, excessive-lifetime, or unacceptably future
   `created`/`expires` values.
7. Verify signed `Bonnet-Origin` exactly matches the configured logical origin.
8. Verify `Content-Digest` against the exact received body.
9. Verify the echoed request nonce.
10. Parse the binary response.

Clients must not process redirects automatically. A network redirect changes
the contacted endpoint and requires an explicit Bonnet discovery and trust
decision.

## 9. Request Context and Authorization Boundary

The current command handler receives a network `Connection` object that also
acts as an authorization principal. Protocol v2 will separate those roles.

Introduce a transport-neutral `CommandContext` containing only the information
required by command and ACL code:

```text
peer_public_key
user
username
remote_addr
request_id
is_anonymous
is_registered()
is_administrator()
is_moderator()
can_create_board()
can_promote_to_mod()
can_demote_mod()
can_edit_post(author)
can_delete_post(author)
```

Do not include an HTTP `Host`, `Origin`, TLS certificate subject, or request URL
as a trusted Bonnet origin. Diagnostic transport metadata may be stored
separately but must never enter ACL resolution.

`LocalConnection` should become a local `CommandContext` constructor rather
than a second connection implementation.

## 10. Rate and Resource Limits

Protocol v2 moves general rate limiting out of `Connection` and into a shared
limiter invoked before command dispatch.

Authenticated keys use:

```text
identity:<ed25519-public-key>
```

Anonymous clients use:

```text
address:<normalized-remote-address>
```

Required controls:

* Maximum request body enforced by the ASGI server and again before command
  parsing.
* Maximum response body enforced before signing.
* Global concurrent-request limit corresponding to `max_connections` or a
  renamed `max_concurrent_requests` setting.
* Per-identity/IP token-bucket request limit.
* Existing per-identity search limiter retained for expensive search commands.
* Request timeout spanning body read, signature verification, dispatch, and
  response creation.
* Bounded HTTP keepalive, header size, and body buffering settings.
* No trust in `X-Forwarded-For` unless an explicit trusted-proxy list is
  configured.

Rate limiting occurs after enough parsing to identify a valid signer but before
replay-ledger insertion and command dispatch. Invalid-signature floods also
need a cheaper address-based limiter.

Discovery and all anonymous endpoints use the cheaper address-based limiter so
unauthenticated callers cannot force unbounded Ed25519 response signing.

## 11. Federation Mapping

Federation remains pull-based and maps naturally to repeated HTTP commands over
an HTTP keepalive or HTTP/2 connection.

For each peer:

1. Apply `_is_dialable_host()` before resolving or dialing.
2. Apply `_resolves_to_global_only()` immediately before dialing.
3. Fetch `/.well-known/bonnet` without following redirects.
4. Verify the discovery response self-signature.
5. Atomically check or insert the peer pin before ingesting data. Concurrent
   first contact must result in one pin; all contenders then re-read and compare
   that stored value.
6. Reject a key mismatch without issuing data commands.
7. Sign federation command requests with `server_identity`.
8. Verify every response against the directly contacted peer's pinned key.
9. Continue verifying each board/report against its resource origin key.
10. Close the HTTP client after the sync unit or return it to a bounded pool.

Port fallback may remain, but each target is independently subject to SSRF and
TLS policy. Redirects, CNAMEs, and relays do not alter the logical origin or
resource-signature rules.

Peer-key rotation keeps the existing old-key signature requirement. HTTP
message authentication is an outer envelope; it does not replace the canonical
rotation payload signature.

An origin rotating its own serving key publishes a rotation statement signed
by the old pinned key before switching `server_identity`. Clients update their
pin only after validating that statement. A discovery response self-signed only
by a new key can never replace an existing pin.

## 12. Data Model Changes

### 12.1 Server replay ledger

Add a database under `data_dir`, or a table in a dedicated protocol database:

```sql
CREATE TABLE request_nonces (
    publickey BLOB NOT NULL,
    nonce BLOB NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (publickey, nonce)
);

CREATE INDEX request_nonces_expiry
    ON request_nonces (expires_at);
```

Anonymous requests are not signed and do not enter this ledger.

### 12.2 Client origin pins

The client identity database needs a separate trust table:

```sql
CREATE TABLE origin_keys (
    origin TEXT PRIMARY KEY,
    publickey BLOB NOT NULL,
    first_seen INTEGER NOT NULL,
    last_rotated INTEGER NOT NULL,
    trust_mode TEXT NOT NULL
);
```

`trust_mode` initially supports `tofu` and `configured`. Client and server
peer-key stores should share behavior and canonical rotation verification, even
if they use separate database files.

An identity password protects the user's private key; it must not control or
silently reset origin pins.

TOFU insertion and comparison must be one atomic database operation. The shared
trust implementation must replace the current read-then-insert behavior and
include a concurrent first-contact test.

## 13. Implementation Sequence

Each phase has an exit gate. Later demolition may not begin until its gate is
green.

### Phase 0: Freeze and specify protocol v1

Deliverables:

* Add protocol-v1 handshake, frame, command, and response fixtures to tests.
* Record current command opcodes and body formats.
* Add an end-to-end test demonstrating the server's one-command lifecycle.
* Add a failing or quarantined test demonstrating federation's expectation of
  multiple commands over one connection.
* Document current key, nonce, and TOFU behavior.

Exit gate:

* Existing behavior is captured well enough to distinguish intentional v2
  changes from accidental command-format regressions.

### Phase 1: Immediate protocol-v1 containment

This phase protects users while v2 is under construction.

Deliverables:

* Replace the client reconnecting counter nonce with random NaCl nonces or the
  canonical `core.crypto.EncryptedSession`.
* Enforce strict inner-frame length validation.
* Guarantee server connection cleanup with `finally`.
* Log unexpected failures without exposing secrets.
* Document that protocol v1 lacks forward secrecy and persistent server pins.

Exit gate:

* Reconnection tests prove no nonce reuse under a static key.
* The existing test suite passes.

### Phase 2: Extract the command boundary

Deliverables:

* Introduce `CommandContext`.
* Migrate `CommandHandler`, `BonnetEngine`, ACL checks, and local CLI use away
  from network `Connection` details.
* Extract general request rate limiting into a shared service.
* Keep protocol-v1 behavior unchanged through an adapter.

Exit gate:

* The same command-handler tests run with local, v1, and synthetic HTTP
  contexts.
* No command or ACL code reads HTTP/WebSocket headers as identity.

### Phase 3: Build and verify the signature profile

Deliverables:

* Add the RFC 9421 and RFC 9530 dependency.
* Implement a Bonnet-specific signer and strict verifier wrapper.
* Implement request/response profile validation.
* Implement `Content-Digest` validation.
* Implement the persistent replay ledger.
* Implement shared origin-key pinning and rotation verification.
* Publish deterministic wire fixtures.

Exit gate:

* RFC vectors pass.
* Independent Bonnet fixtures reproduce identical signature bases.
* Tampering with every mandatory covered component fails.
* Replays and stale/future requests fail before dispatch.

### Phase 4: Add the HTTP server transport

Deliverables:

* Add an ASGI application exposing discovery and `/v2/command`.
* Apply body, concurrency, timeout, and address limits.
* Convert verified requests into `CommandContext` instances.
* Dispatch the existing binary body through `CommandHandler`.
* Sign all responses.
* Integrate startup and shutdown for engines, sync workers, databases, and the
  HTTP server.

Exit gate:

* Every command-handler integration test can run through HTTP.
* Anonymous/default-deny, banned-user, ACL, report-origin, and search-limit
  tests pass through HTTP.
* Malformed traffic cannot reach command dispatch.

### Phase 5: Replace the client transport

Deliverables:

* Replace WebSocket lifecycle methods with an async HTTP client.
* Sign authenticated command requests using the unlocked local Ed25519 key.
* Verify all response signatures and origin pins before parsing bodies.
* Add explicit first-contact TOFU and configured-pin user flows.
* Send signed username selection when needed.
* Reuse HTTP connections through a bounded client pool.
* Remove long-lived plaintext password caching from client tool state; retain
  unlocked signing material only for an explicitly bounded client session.
* Preserve existing high-level client method signatures where practical.

Exit gate:

* Client/server end-to-end tests cover every command family.
* A changed server key fails closed.
* Unsigned, stale, mismatched-nonce, and wrong-origin responses fail closed.

### Phase 6: Replace federation transport

Deliverables:

* Replace `Connection.client()` with the signed HTTP client.
* Preserve both SSRF gates at every dial site.
* Preserve TOFU-before-ingest behavior.
* Preserve board/report origin-signature verification.
* Preserve old-key-authorized rotation.
* Add real HTTP end-to-end sync tests instead of mocked connection-only tests.

Exit gate:

* Board, user, and report synchronization completes over one HTTP client.
* Peer mismatch, poisoned origin, invalid resource signature, DNS rebinding,
  and rotation attacks fail in integration tests.

### Phase 7: Cutover decision

Recommended for the current pre-1.0 project: coordinated protocol-v2 cutover,
without automatic v1 fallback.

If known external protocol-v1 deployments require a transition release, dual
stack must be explicitly enabled and separately bound/configured. A v2 client
must never silently retry a failed v2 identity check using v1. Metrics and logs
must distinguish protocols, and a removal date must be established before dual
stack ships.

Exit gate:

* All supported clients and known federation peers can use v2.
* Operators can inspect and back up origin-key pins.
* No unresolved security-critical findings remain.

### Phase 8: Demolish protocol v1

Remove:

* WebSocket serving from `src/app/server.py`.
* WebSocket client code from `src/net/connection.py` and
  `src/client/connection.py`.
* Challenge generation, verification, and username-selection messages.
* Application command `EncryptedSession` implementations.
* Four-byte WebSocket frame helpers.
* Protocol-v1-only tests and fixtures after retaining archival conformance
  fixtures where useful.
* `websockets` from `pyproject.toml` and packaging metadata.
* Dead connection constants, modes, state, callbacks, and duplicated permission
  helpers.

Exit gate:

* No production import references `websockets`.
* No network code derives encryption keys directly from long-term identity
  keys.
* Full tests, packaging, and frozen build succeed.

### Phase 9: Hardening and external review

Deliverables:

* Fuzz signature fields, digest fields, binary command bodies, and discovery
  documents.
* Load-test replay storage, rate limits, HTTP pooling, and large bodies.
* Run dependency and static security scans.
* Conduct an external protocol/security review.
* Publish protocol-v2 interoperability fixtures and operator migration notes.

Exit gate:

* Review findings are resolved or explicitly accepted.
* Resource use remains bounded under malformed and adversarial traffic.

## 14. File-Level Work Map

Expected additions:

* `src/net/http_auth.py`: strict Bonnet RFC 9421 profile.
* `src/net/http_server.py`: discovery and command ASGI routes.
* `src/net/context.py`: transport-neutral `CommandContext`.
* `src/net/replay.py`: persistent nonce ledger.
* `src/core/trust.py`: shared origin pin and rotation behavior.
* `src/client/http.py`: signed async command client.
* `tests/test_http_auth.py`: profile and replay tests.
* `tests/test_http_server.py`: endpoint integration tests.
* `tests/test_http_client.py`: pin and response-verification tests.
* `tests/test_http_sync.py`: real federation transport tests.
* `tests/fixtures/protocol_v2/`: deterministic interoperability vectors.

Expected major edits:

* `src/app/server.py`: ASGI lifecycle and eventual WebSocket removal.
* `src/app/main.py`: launch and shutdown the ASGI server.
* `src/net/commands.py`: accept `CommandContext`; externalize rate limiting.
* `src/net/sync.py`: HTTP client and shared trust store.
* `src/client/connection.py`: temporary adapter, then removal or rename.
* `src/client/identity.py`: origin pins and trust operations.
* `src/client/tools.py`: HTTP client lifecycle.
* `src/client/simple.py`: HTTP client lifecycle.
* `src/core/config.py`: HTTP/TLS, replay, proxy, and concurrency settings.
* `pyproject.toml`: HTTP/signature dependencies and eventual WebSocket removal.
* `bonnet.spec`: package new dependencies and remove WebSocket artifacts.

Expected deletions after cutover:

* Most or all of `src/net/connection.py`.
* Client `EncryptedSession` and frame helpers.
* `READ_ONLY_COMMANDS` and other protocol-v1-only connection constants.
* Protocol-v1 handshake tests that no longer document supported behavior.

## 15. Security Decision Gates

Implementation must stop for an explicit decision if any of these assumptions
are false:

1. TLS may terminate only at a component trusted to read command contents.
2. A 60-second signature validity window with bounded clock skew is acceptable.
3. A persistent replay ledger is operationally acceptable.
4. First-contact TOFU remains acceptable for federation and clients.
5. Protocol-v2 clients can store origin pins persistently.
6. A coordinated protocol cutover is acceptable, or known v1 peers have been
   identified for an explicit transition plan.

If assumption 1 is false, use a vetted authenticated key-exchange protocol such
as Noise inside HTTP bodies. Do not restore the current static Ed25519-to-X25519
`Box` construction and do not invent a new ephemeral-key transcript.

## 16. Test Strategy

### 16.1 Unit tests

* Signature creation and verification against RFC vectors.
* Exact required covered-component enforcement.
* `Content-Digest` generation and mismatch rejection.
* Key-id format and Ed25519 key parsing.
* Created, expires, skew, and maximum-lifetime rules.
* Nonce encoding, uniqueness, atomic insertion, replay, and expiry cleanup.
* Username selection constrained to the verified public key.
* Origin pin first use, repeat use, mismatch, configured pin, and rotation.
* `CommandContext` permissions matching current behavior.

### 16.2 Integration tests

* Anonymous public command succeeds.
* Anonymous private command fails.
* Registration proves and stores the signing key.
* Authenticated command selects the correct UME user.
* Every command family round-trips through `/v2/command`.
* Command-level errors remain parseable binary responses.
* Signed protocol errors verify correctly.
* Request and response body tampering fail.
* Method, path, authority, username, origin, nonce, status, and version
  substitution fail.
* Duplicate requests are never dispatched twice.
* Changed server keys fail before response parsing.
* Redirects are not followed automatically.
* Rate limits survive HTTP connection churn.
* Timeouts and cancellation release resources.

### 16.3 Federation tests

* First contact pins the directly contacted peer key.
* Repeat contact requires the pin.
* Rotation requires the old pinned key.
* Relay response signature and resource origin signature are checked
  independently.
* Board, user, and report sync use one pooled HTTP client.
* Private, loopback, link-local, mixed DNS, and rebinding targets are rejected.
* A valid TLS connection with the wrong Bonnet key is rejected.

### 16.4 Adversarial tests

* Multiple-signature confusion.
* Missing mandatory covered components.
* Duplicate Structured Field parameters.
* Header normalization and case variations.
* Oversized headers and bodies.
* Invalid UTF-8 username and origin fields.
* Clock boundary behavior.
* Replay across restart.
* Concurrent duplicate nonce insertion.
* Signature-verification CPU exhaustion.
* Untrusted proxy headers.
* Malformed binary payloads after a valid envelope.

## 17. Observability

Log structured events for:

* Protocol version.
* Request ID and command opcode.
* Authenticated public-key fingerprint, never private material or signatures.
* Selected username or `anonymous`.
* Signature failure category without echoing attacker-controlled secrets.
* Replay rejection.
* Origin-pin creation, mismatch, and rotation.
* Rate-limit key category and rejection.
* Federation dial target, pinned fingerprint, and resource-verification result.
* Request duration and response size.

Do not log command bodies, private keys, passwords, decrypted private-key data,
raw authorization headers, or full signatures by default.

Metrics should count accepted and rejected requests by protocol stage so an
operator can distinguish transport failures, identity failures, replay attacks,
authorization failures, and command errors.

## 18. Configuration Changes

Proposed configuration groups:

```toml
[http]
host = "0.0.0.0"
port = 2272
request_timeout_seconds = 30
max_concurrent_requests = 100
keepalive_seconds = 15

[tls]
enabled = true
cert_path = "..."
key_path = "..."
allow_cleartext_loopback = false

[protocol]
versions = [2]
signature_lifetime_seconds = 60
clock_skew_seconds = 30
replay_db_path = "protocol.db" # resolved relative to data_dir

[proxy]
trusted = []
```

Existing limits should be migrated rather than duplicated. Configuration
loading must reject insecure remote cleartext combinations and invalid lifetime
or skew values. `max_connections` is renamed to
`max_concurrent_requests` without retaining both active controls. Signature
lifetime must be positive; clock skew must be non-negative and smaller than the
signature lifetime.

## 19. Deployment and Rollback

### 19.1 Pre-cutover checklist

* Back up server identity keys and peer-key databases.
* Export known origin pins and fingerprints.
* Verify TLS configuration separately from Bonnet key pins.
* Confirm every supported client understands v2 response signatures.
* Confirm federation peers have compatible schedules.
* Confirm replay storage is writable and durable.
* Exercise restore procedures in staging.

### 19.2 Cutover

1. Stop accepting writes briefly if a coordinated cutover requires it.
2. Deploy the v2 server and verify signed discovery locally.
3. Verify the advertised Bonnet fingerprint out of band.
4. Deploy clients and federation peers.
5. Resume writes.
6. Monitor signature, replay, pin-mismatch, and command-error metrics.

### 19.3 Rollback

Rollback means restoring the previous complete server/client release and its
configuration, not allowing clients to downgrade after an identity failure.
Preserve replay and pin databases during rollback. Never delete or overwrite an
origin pin merely to make reconnection succeed.

If protocol v1 has already been demolished, rollback requires a packaged prior
release. The demolition phase therefore begins only after a stable v2 release
artifact and tested data backup exist.

## 20. Acceptance Criteria

The renovation is complete when:

* All supported communication is command-response over HTTP.
* Every authenticated command proves possession of its Bonnet Ed25519 key.
* Every response proves possession of the expected Bonnet server key.
* TLS certificates are never used as Bonnet principals.
* Replays are rejected atomically before command dispatch, including after a
  process restart.
* Remote command contents receive TLS confidentiality and forward secrecy.
* Anonymous and authenticated authorization behavior matches current policy.
* Client and federation origin pins persist and reject unexpected key changes.
* Resource origin signatures remain independent of relay response signatures.
* SSRF gates remain in front of every federation dial.
* General rate limiting cannot be bypassed by opening a new HTTP connection.
* Existing binary command behavior passes through the new transport.
* No production code imports `websockets` or uses the old encrypted session.
* Interoperability fixtures and operator migration documentation are published.
* The protocol has received focused external security review.

## 21. Follow-Up Renovations

Only after protocol v2 is stable should the project consider:

* Replacing the binary command switch with explicit HTTP resources.
* Replacing positional binary payloads with a versioned schema format.
* Adding HTTP caching semantics for public read commands.
* Adding idempotency keys for selected write commands beyond replay prevention.
* Supporting HTTP/3.
* Adding optional Noise protection for deployments with untrusted TLS
  termination.
* Separating sync scheduling and lifecycle from `CommandHandler`.
* Making report synchronization incremental.

These changes must not be bundled into the initial transport renovation. The
smallest safe path is to replace transport and authentication while keeping the
command semantics stable.
