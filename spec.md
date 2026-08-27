# Bonnet Firehose Protocol

This is a protocol for federated bulletin boards. An origin is a server
with an Ed25519 key. It appends signed records to a chain. Other servers
sync those records through witnesses. Clients talk to servers over HTTPS
with signed binary commands.

The protocol is stateless. The server keeps no per-client session. Each
request carries its own signature and nonce.

## Underlying protocol

HTTPS. Requests and responses are signed using RFC 9421 HTTP Message
Signatures with Ed25519. The signature tag is `bonnet-firehose-1`.

The content type for commands is `application/vnd.bonnet.command`. The
content digest algorithm is sha-256.

All multi-byte integers are big-endian, unsigned unless noted. Text is
UTF-8, NFC-normalized, prefixed with a u16 length. Binary blobs are
prefixed with a u32 length. IDs and hashes are 32 bytes. Public keys are
32 bytes. Signatures are 64 bytes.

## Discovery

GET /.well-known/bonnet

Returns a signed JSON document:

    protocol            "bonnet-firehose-1"
    origin              the server's origin string
    hostname            the server's hostname
    public_key          64 hex chars — the server's Ed25519 public key
    anonymous_key       64 hex chars — a shared anonymous public key
    anonymous_private_key  64 hex chars — the matching private key
    command_endpoint    "/command"
    known_origins       list of origin strings this server knows about
    capabilities        list of capability strings

The response is signed by the server's own key. On first contact this is
self-attesting. TLS provides the independent trust anchor. After first
contact, the key is TOFU-pinned. Subsequent connections reject key
changes. An operator can pre-configure a key pin to override TOFU.

The anonymous key pair is public by design. It classifies requests as
anonymous for access control and rate limiting. It provides no
authentication. Anyone can sign requests with it.

## Commands

POST /command

Send a binary body. The first byte is an opcode. The rest is
opcode-specific. The response is also binary: a status byte (0 = success,
1 = error), followed by opcode-specific payload or an error structure.

Error responses after the status byte 0x01:

    u16  error code
    u16  message length
    bytes  message (UTF-8)

Internal errors return "Internal error" — never the raw exception text.

### PUBLISH_RECORD (0x01)

Publish a new record to the firehose. Write command.

Request:

    u32  intent length
    bytes  encoded intent
    64 bytes  actor signature (over the encoded intent)
    u32  body length
    bytes  body

The intent must have origin set to this server's origin. The actor pubkey
must match the key that signed the request. The server validates the kind,
checks ACL, enforces business rules (e.g., only the author can cancel),
checks the body hash and size, stages the body, appends the record to the
firehose, finalizes the body, and dispatches to projections.

Response:

    u32  record length
    bytes  encoded record
    u16  witness length
    bytes  encoded witness

The record contains the allocated sequence number and article number. The
witness is the server's own origin witness for this event.

### EVENT_HEAD (0x02)

Get the signed head for an origin. Read command.

Request:

    text16  origin

Response:

    u16  head length
    bytes  encoded head

The head contains the latest sequence number, latest event hash, event
count, origin public key, and the origin's signature over all of it.

Error 0x0002 if no head exists for the origin.

### EVENT_RANGE (0x03)

Get a range of records with witnesses. Read command.

Request:

    text16  origin
    u64  start sequence
    u16  max count
    u32  max bytes (0 = no limit)

Response:

    u16  record count
    for each record:
        u32  record length
        bytes  encoded record
        u16  witness length
        bytes  encoded witness

If max_bytes is non-zero, the server stops before exceeding it. Each
record includes a witness signed by this server.

### EVENT_GET (0x04)

Get a single record by event ID. Read command.

Request:

    text16  origin
    32 bytes  event ID

Response: same as PUBLISH_RECORD (record + witness).

Error 0x0003 if not found.

### BOARD_LIST (0x10)

List boards for an origin, or all known boards if origin is empty. Read
command.

Request:

    text16  origin (empty = aggregate)

Response:

    u16  board count
    for each board:
        text16  origin (only in aggregate mode)
        text16  board name
        u8  closed (0 or 1)
        u8  owner pubkey length
        bytes  owner pubkey
        text16  display name

### ARTICLE_GET (0x11)

Get a single article by number or by ID. Read command.

Request:

    text16  origin
    text16  board
    u8  selector type (1 = by number, 2 = by ID)
    u64 or 32 bytes  selector
    u8  include body (0 or 1)

Response: an article view (see below).

Error 0x0003 if not found.

### ARTICLE_LIST (0x12)

List articles on a board. Read command.

Request:

    text16  origin (empty = aggregate)
    text16  board
    u32  offset
    u16  limit
    u8  flags (bit 0 = include cancelled, bit 1 = include superseded,
              bit 2 = include purged)

Response:

    u16  article count
    for each article:
        text16  origin (only in aggregate mode)
        article view (without body)

### ARTICLE_SEARCH (0x13)

Search article metadata and bodies. Read command.

Request:

    text16  origin (empty = aggregate)
    text16  board
    text16  metadata query (substring match on subject and tags)
    text16  body query (regex match on body content via ripgrep)
    u32  offset
    u16  limit
    u8  flags (bit 0 = include cancelled, bit 1 = include superseded)

Response:

    u16  result count
    u32  total matches
    u8  truncated (0 or 1)
    for each result:
        text16  origin (only in aggregate mode)
        u64  article number
        u8  article ID length + article ID
        u8  subject length + subject
        u8  author pubkey length + author pubkey
        i64  created at
        u8  body available (0 or 1)
        text16  excerpt

### ARTICLE_QUERY (0x15)

Structured query with field filters. Read command.

Request:

    text16  origin
    text16  board
    u8  filter count
    for each filter:
        u8  field ID
        u8  operator
        u8  value type (1 = bytes, 2 = text, 3 = i64, 4 = bool)
        u16  value length
        bytes  value
    u32  offset
    u16  limit

Response:

    u16  article count
    for each article:
        article view (without body)

### ARTICLE_BODY (0x14)

Get the body content of an article. Read command.

Request:

    text16  origin
    text16  board
    u64  article number

Response:

    u32  body length
    bytes  body

If the body is not available locally and the origin is a remote peer, the
response starts with 0x02 (redirect) instead of 0x00 (success), followed
by:

    text16  origin
    text16  peer hostname
    u16  peer port
    u8  verify TLS (0 or 1)

Error 0x0008 if the body has been purged. Error 0x0003 if not found.

### USER_GET (0x20)

Get a user by public key. Read command.

Request:

    text16  origin
    u8  pubkey length
    bytes  pubkey

Response:

    u8  pubkey length + pubkey
    text16  username
    u64  flags
    u64  registration sequence
    i64  created at
    u8  revoked (0 or 1)
    u64  revoked sequence

Error 0x0001 if not found.

### USER_LIST (0x21)

List users on an origin. Read command.

Request:

    text16  origin
    u8  flags (bit 0 = include revoked)

Response:

    u16  user count
    for each user:
        text16  origin
        u8  pubkey length + pubkey
        text16  username
        u64  flags
        u64  registration sequence
        i64  created at
        u8  revoked (0 or 1)

### BAN_STATUS (0x22)

List all punishments pending against a user. Read command.

Request:

    u8  pubkey length
    bytes  pubkey

Response:

    u8  count
    for each pending punishment:
        u8  type code (1 = warning, 2 = ban, 3 = permaban)
        i64  expires at (0 = no expiry)
        u32  body size
        32 bytes  body hash
        32 bytes  punishment event ID
        text16  origin

Pending means: unacknowledged warnings, active temporary bans, and
permabans from allowed origins. Expired and revoked punishments are not
included. Clients fetch the reason via EVENT_BODY using the event ID.

### EVENT_BODY (0x30)

Get the body of a non-article event (e.g., a rule or report). Read
command.

Request:

    text16  origin
    32 bytes  event ID

Response:

    u32  body length
    bytes  body

Error 0x0003 if not found or body unavailable.

## Article view

The article view is a binary structure returned by ARTICLE_GET and included
in ARTICLE_LIST and ARTICLE_QUERY responses:

    u64  article number
    u8  article ID length + article ID
    u8  event ID length + event ID
    u8  visibility (0 = active, 1 = cancelled, 2 = superseded)
    u8  body state (0 = available, 1 = unavailable, 2 = purged)
    u8  body hash length + body hash
    u64  body size
    i64  created at
    u8  author pubkey length + author pubkey
    text16  author username
    text16  author registrar
    text16  subject
    text16  tags (comma-separated)
    text16  content type
    u8  root article ID length + root article ID
    u8  reply-to article ID length + reply-to article ID
    u8  has replacement (0 or 1) + optional 32-byte replacement ID
    text16  pin state
    text16  thread state
    u32  body length + body (only if include_body was set and body is available)

## Records

A record is what the firehose stores. It contains everything the intent
had, plus the chain fields, the allocated sequence number, the article
number, and two signatures.

Encoded as:

    u8  record format (1)
    text16  origin
    u64  origin sequence
    32 bytes  previous event hash
    32 bytes  event ID
    text16  kind
    u16  schema version
    i64  created at
    32 bytes  actor pubkey
    text16  actor username
    text16  actor registrar
    text16  board
    32 bytes  article ID
    u64  article number
    text16  target origin
    text16  target board
    32 bytes  target article ID
    32 bytes  target event ID
    blob32  metadata
    32 bytes  body hash
    u64  body size
    64 bytes  actor signature
    64 bytes  origin signature

The intent is the actor-authored portion. The actor signs the encoded
intent. The server signs the encoded record (without the origin signature)
to produce the origin signature. The event hash is SHA-256 of the encoded
record. The previous event hash links records into a chain.

## Intent

An intent is what the actor creates and signs. It contains the kind,
origin, actor identity, board, target, metadata, and body reference — but
not the sequence number or chain link, which the server assigns.

Encoded as:

    u8  intent format (1)
    32 bytes  event ID
    text16  kind
    u16  schema version
    text16  origin
    32 bytes  actor pubkey
    text16  actor username
    text16  actor registrar
    text16  board
    32 bytes  article ID
    text16  target origin
    text16  target board
    32 bytes  target article ID
    32 bytes  target event ID
    blob32  metadata
    32 bytes  body hash
    u64  body size

## Metadata

Metadata is a sequence of fields, each with a u8 field number, a u8 type
(1 = text, 2 = text list, 3 = bytes, 4 = u64, 5 = i64, 6 = id list), and
a type-specific value. The whole sequence is length-prefixed with u32.

Field meanings are defined by the kind. See the kind table below.

## Head

A head is a signed summary of an origin's firehose state:

    u8  head format (1)
    text16  origin
    u64  latest origin sequence
    32 bytes  latest event hash
    u64  event count
    i64  generated at
    32 bytes  origin pubkey
    64 bytes  origin signature

The origin signs the unsigned portion (everything except the signature).

## Witness

A witness is a relay's signed statement that it received an event from an
upstream source:

    u8  witness format (1)
    text16  event origin
    32 bytes  event ID
    32 bytes  event hash
    32 bytes  relay pubkey (this server's key)
    text16  relay hostname
    32 bytes  received-from pubkey (upstream relay's key)
    text16  received-from hostname
    i64  seen at
    64 bytes  relay signature

Witnesses form a chain. Following the received-from pointers back through
relays traces the path an event took through the network.

## Kinds

| Kind | Metadata fields | Body | Notes |
|------|-----------------|------|-------|
| bonnet.article | 1=subject, 2=tags, 3=options, 4=content-type, 5=root-id, 6=reply-to-id, 7=supersedes-id | article content | |
| bonnet.article.cancel | — | reason | targets an article by (target_origin, target_board, target_article_id) |
| bonnet.article.restore | — | reason | undoes a cancel |
| bonnet.article.purge | — | reason | deletes body, irreversible |
| bonnet.article.pin | — | — | |
| bonnet.article.unpin | — | — | |
| bonnet.thread.close | — | — | |
| bonnet.thread.reopen | — | — | |
| bonnet.board.create | 1=owner pubkey, 2=display name | — | |
| bonnet.board.close | — | — | |
| bonnet.board.reopen | — | — | |
| bonnet.user.register | 1=username, 2=user pubkey, 3=flags | — | flags bit 0 = admin, bit 1 = moderator |
| bonnet.user.revoke | — | — | targets the user by target_origin |
| bonnet.rule.publish | 1=rule name | rule text | |
| bonnet.rule.revoke | — | — | targets a rule by target_event_id |
| bonnet.report | — | report content | |
| bonnet.punishment.warn | 1=punished pubkey (32B) | warning message | pending until acknowledged or revoked |
| bonnet.punishment.ban | 1=punished pubkey (32B), 2=expires at (i64, positive) | ban reason | expires automatically |
| bonnet.punishment.permaban | 1=punished pubkey (32B) | ban reason | permanent until revoked |
| bonnet.punishment.revoke | — | revocation reason | targets any punishment by target_event_id |
| bonnet.punishment.ack | 1=punishment event ID (32B) | — | signed by the punished user; local to their homeserver |
| bonnet.origin.key.rotate | 1=new pubkey, 2=new-key proof signature | — | |

Kind strings are printable ASCII (bytes 0x20 through 0x7E).

## Authentication

Every request to /command is signed. The keyid is `ed25519:<hex pubkey>`.
The server extracts the pubkey from the keyid, classifies the request, and
enforces ACL rules.

Request signatures require these parameters: created, expires, nonce,
keyid, alg, tag. The expires parameter is required — requests without it
are rejected. The nonce is a base64url-encoded 32-byte random value.

Response signatures include bonnet-request-nonce, which must match the
request nonce. Responses without it are rejected by the client.

Anonymous requests (signed with the shared anonymous key) skip the replay
ledger. Rate limiting by address applies to all requests. Rate limiting
by identity also applies to non-anonymous requests.

## Authorization

ACL rules are explicit and default-deny. Every applicable dimension
(command, kind, board) must pass. Any matching deny rule wins. No implicit
bypasses — administrators and moderators are granted via ACL rules that
match their role or pubkey.

## Federation

One server syncs from another by fetching heads and record ranges over
the command protocol. Each sync cycle:

1. Fetch the peer's head for an origin (EVENT_HEAD).
2. Compare the latest sequence against the local highest.
3. Fetch missing records in batches of 100 (EVENT_RANGE).
4. Verify chain continuity, record signatures, and the head signature.
5. Accept each batch. If a batch conflicts, stop — committed batches are
   kept. The next cycle resumes from where it stopped.
6. Create a local witness for each accepted record naming the upstream
   peer as the source.
7. Dispatch accepted records to local projections.

Dial targets are validated against non-global address ranges by default.
Loopback, private, link-local, multicast, and reserved addresses are
rejected. An explicit allow_private_dial setting permits LAN federation.

Failed peers accumulate exponential backoff: 30s, 60s, 120s, ... up to
3600s, with jitter. Backoff applies to periodic and on-demand sync.
Backoff resets on success.

## Projections

The firehose (events.db) is the authoritative log. Projections are
derived views that can be rebuilt from it:

- nav.db — board directory (created, closed, reopened)
- users.db — user registrations and revocations
- policy.db — rules, reports, punishments
- boards/<origin>/<board>/metadata.db — articles, lifecycle, pin, thread state

The dispatcher processes records in origin sequence order. It advances
the origin-level checkpoint only after all applicable projections accept
the record. If a projection fails, dispatch stops. The checkpoint stays
at the last successful record. Retrying after the fault is cleared
applies the failed record and continues.

## Limits

The server enforces these limits (configurable, with protocol maxima):

- max_request_size (default 10 MiB) — checked while streaming, before
  the body is fully buffered
- max_article_body_size (default 1 MiB) — checked before staging any
  body-bearing record
- rate_limit_requests / rate_limit_window — sliding window, keyed by
  address for all requests and by identity for non-anonymous requests
- signature lifetime — max 60 seconds
- clock skew allowance — max 30 seconds

## REPL commands

The server's interactive REPL provides administrative commands that are
not part of the wire protocol:

- rebuild [origin] — clear projections for one origin and replay from
  the firehose
- depeer <origin> — stop syncing and freeze a peer's data as read-only
- purge-origin <origin> — irreversibly remove all data for an origin
  (requires depeer first; writes a manifest for crash recovery)
- reset-key <origin> — clear key epoch pinning, forcing re-TOFU on next
  sync

## Status codes

Error responses use these codes:

    0x0000  internal error (generic message, never the raw exception)
    0x0001  not found (user)
    0x0002  not found (head)
    0x0003  not found (article, event, or body)
    0x0004  not permitted (ACL denial or origin/actor mismatch)
    0x0005  unhandled opcode or invalid selector
    0x0006  validation error (malformed intent, body mismatch, etc.)
    0x0008  body purged
    0x0009  conflicting state (e.g., already cancelled)
    0x000A  write blocked by a pending punishment (message carries the
            punishment type, event ID, issuing origin, and expiry)

## Punishments

Punishments gate writes. While a user has pending punishments from allowed
origins — unacknowledged warnings, active temporary bans, or permabans —
every PUBLISH_RECORD is rejected with 0x000A except `bonnet.punishment.ack`,
which must pass so the user can acknowledge their warnings. Administrators
bypass the gate. If the policy projection is unavailable or behind the
firehose, the gate fails open.

The acknowledgment flow:

1. A blocked publish returns 0x000A with punishment details.
2. The client fetches the reason via EVENT_BODY and shows it.
3. The user publishes bonnet.punishment.ack referencing the punishment's
   event ID, signed with their own key.
4. Warnings clear from pending state; bans remain until expiry or revocation.

Import filtering is per-type per-origin on each sync peer:

    [[sync.peers]]
    origin = "example.peer"
    import_warnings = true
    import_temp_bans = true
    import_permabans = false

Rejected punishments remain in the firehose for relay but are not applied
locally. Punishments from origins without an import policy entry are never
enforced locally. The local origin's own punishments always apply.
