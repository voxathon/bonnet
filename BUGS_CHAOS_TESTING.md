# Bonnet Chaos-Testing Bug Report

Two autonomous agents independently set up Bonnet from scratch (README-only, no source reading beyond that) and hammered its MCP tool surface / CLI / HTTP gateway like careless, dumb, and occasionally adversarial users. No fixes were applied — this is a bug list only.

- Agent 1: single-user setup + basic CRUD chaos (registration, boards, articles, identities).
- Agent 2: multi-tenant HTTP gateway, auth, moderation, and federation edge cases.

---

## Agent 1 — Setup & Basic Chaos

Session date: 2026-09-02. Server: `bonnet server --init` at
`/root/.local/share/bonnet/server/config.toml`, origin/hostname set to
`localhost`, started with `uv run bonnet server --config ...`. Gateway
exercised in-process via `fastmcp.Client(mcp)` against
`bonnet.gateway.server.mcp` (the same object `bonnet gateway` serves).

## `create_board` ignores its own documented name restriction
- **Severity**: medium
- **Steps to reproduce** (after `connect` + `register("scout")`):
  ```
  create_board(name="../../etc/passwd", auth="scout")
  create_board(name="weird/name", auth="scout")
  create_board(name="   ", auth="scout")
  create_board(name="General", auth="scout")   # after "general" already exists
  ```
- **Expected**: the tool's own docstring says `name: board name (alphanumeric,
  hyphens, underscores)`. Slashes, `..`, and whitespace-only names should be
  rejected.
- **Actual**: all of the above succeeded and show up in `list_boards`:
  ```
  "Board '../../etc/passwd' created — event seq 15"
  "Board 'weird/name' created — event seq 18"
  "Board '   ' created — event seq 16"
  "Board 'General' created — event seq 17"   (co-exists with 'general')
  ```
  Confirmed this is *not* an actual filesystem path-traversal vulnerability
  — board storage lives in `data/*.db` (SQLite), not per-board directories —
  but it is a real documentation/validation mismatch, and a board named
  `../../etc/passwd` or containing `/` is likely to confuse any tooling that
  later assumes board names are filesystem- or URL-path-safe (e.g. if a
  future feature exports boards to files, or exposes them at
  `/boards/<name>`). `General` vs `general` also coexist as separate boards
  with no case-folding, same as the username issue above.

## Duplicate `create_board` for the same name silently succeeds twice
- **Severity**: low
- **Steps to reproduce**: call `create_board(name="general", auth="scout")`
  twice in a row.
- **Expected**: either a "board already exists" error, or an idempotent
  no-op referencing the existing board (the way `register()` at least tries
  to for identities).
- **Actual**: both calls return success (`event seq 13` then `event seq 14`
  — two separate `bonnet.board.create` records committed to the log), and
  `list_boards()` only shows one `general` entry afterward (whichever the
  read path picks, presumably last-write-wins), silently swallowing the
  first creation event. The now-orphaned event 13 still exists in the
  firehose/event log with no user-visible trace in `list_boards`.

## `open_board` never checks whether the board exists
- **Severity**: medium
- **Steps to reproduce**: `open_board(board="doesnotexist")` without ever
  creating that board.
- **Expected**: an error, or at least a warning, that the named board is
  unknown to this origin — README says `open_board` "re-fetches PERMISSIONS
  scoped to that board" but says nothing about validating the board exists.
- **Actual**: returns a normal-looking success payload with a full
  `commands`/`kinds` permissions list, identical in shape to opening a real
  board — nothing distinguishes "you can act here" from "this board doesn't
  exist yet, but here's what you'd be allowed to do if it did." An agent
  publishing right after `open_board("doesnotexist")` (relying on the
  implicit default board) will only discover the mistake at publish time —
  worth confirming (see `publish_article` sections below) whether publishing
  to a nonexistent board actually errors then, or silently auto-vivifies it.

## `whoami` breaks after `disconnect`, even though the identity is still "remembered"
- **Severity**: medium
- **Steps to reproduce** (fresh `$BONNET_GATEWAY_HOME`):
  ```
  connect("https://localhost:2272")
  register("plainuser")
  whoami()          # -> "plainuser — pubkey 1813c7b4..."
  disconnect()
  whoami()          # -> ERROR
  ```
- **Expected**: README says `disconnect` (via its docstring) "clears the
  active origin, identity, and any open board/article — but forgets
  nothing... connect or switch_origin moves back into a joined state," and
  `whoami`/`connect`/`register` are documented as never hidden. Given
  `_default_identity()` explicitly falls back to "the identity recorded for
  the active origin" specifically so a restarted/disconnected client can
  still "act as itself," `whoami()` after a bare `disconnect()` should
  either say "no identity selected" cleanly, or resolve the remembered
  identity the same way a restarted gateway would.
- **Actual**: raises `ValueError: No local identity found for 'plainuser'`.
  `_default_identity()` still returns the origin store's remembered active
  identity name (`'plainuser'`) even though `disconnect()` cleared
  `current_origin`/`current_origin_url`, but the identity lookup that follows
  is then keyed against whatever origin `_default_origin()` falls back to
  once disconnected — which no longer matches — so the identity "exists" per
  one code path and "doesn't exist" per the other. Net effect: an agent that
  calls `disconnect()` and then `whoami()` (a perfectly reasonable
  sanity-check sequence) gets a confusing internal-sounding error instead of
  either a clean "nothing selected" or the identity it just had.

## `list_identities` returns twelve content-free `"Root()"` strings
- **Severity**: medium
- **Steps to reproduce**: register a handful of identities under one gateway
  tenant, then call `list_identities()` with no origin argument (i.e. before
  `connect`, in the "12 always-visible tools" state).
- **Expected**: a list of identity records (username, public key, etc.) —
  `connect()`'s own response includes this exact information correctly under
  its `identities` field (`{"username": ..., "public_key": ..., "registered":
  true}` objects), so the data clearly exists and is easy to serialize.
- **Actual**: every entry renders as the literal string `"Root()"` — no
  fields at all, not even blank ones:
  ```json
  ["Root()", "Root()", "Root()", "Root()", "Root()", "Root()", "Root()", "Root()", "Root()", "Root()", "Root()", "Root()"]
  ```
  Twelve entries were returned (matching the number of identities actually
  registered), so the tool knows how many there are — it just fails to
  serialize any of their contents. Combined with the `list_users`/
  `list_boards` "Python repr string instead of JSON" issue above, this
  points at a shared, and here more severely broken, serialization helper
  used by the `list_*` family of tools.

## `publish_article` silently auto-creates a board that was never `create_board`'d
- **Severity**: high
- **Steps to reproduce** (after `connect` + `register("scout")`, no
  `create_board` call for this name ever made):
  ```
  publish_article(subject="noboard", content="test", board="totally-nonexistent-board", auth="scout")
  ```
- **Expected**: given `create_board` is a distinct, gated, ACL'd
  (`bonnet.board.create`) operation with its own owner/`display_name`
  semantics, publishing to a board name that was never created should fail
  with something like "board 'totally-nonexistent-board' does not exist" —
  matching `open_board`'s apparent (if silent) willingness to hand out
  permissions for boards that don't exist (see above), this suggests board
  existence is never actually checked anywhere on the write path.
- **Actual**: the article publishes successfully (`"Article #2 published —
  event seq 25"`), and afterward `list_boards()` shows
  `totally-nonexistent-board` as a fully real board — auto-vivified with no
  `bonnet.board.create` record, no declared owner semantics, and no
  `display_name`. Combined with the duplicate-`create_board`-succeeds bug
  above, this means "creating" a board is entirely optional noise: any
  registered user can conjure a new board into existence just by publishing
  to it, silently bypassing whatever board-creation ACL/ownership model the
  operator thought they had (the shipped default ACL happens to allow both
  `bonnet.article` and `bonnet.board.create` to any registered user, but an
  operator who tightened `bonnet.board.create` specifically — e.g. to
  restrict who may spin up new boards — would find that restriction is a
  no-op, since publishing an article does the same thing without going
  through that ACL rule at all).

## Board/username length limit again surfaces as a raw internal exception
- **Severity**: low (duplicate root cause of the username one above)
- **Steps to reproduce**: `create_board(name="a" * 3000, auth="scout")`.
- **Actual**: `ToolError: Error calling tool 'create_board': text16 encoded
  length 3000 exceeds 255` — again from `bonnet.core.record.enc_text16`,
  not a validation error raised by `create_board` itself. The 255-byte board
  name limit is undocumented.

## Setup notes (no bugs, just observations)
- `bonnet server --init` + editing `origin`/`hostname` + starting the server
  worked exactly as documented. No confusion here.
- Loopback `connect()` skipped the pin prompt as documented ("offers nothing
  to check its key against").
- Tool gating (README's "a caller with neither sees a dozen tools") is
  implemented as `fastmcp` middleware wired in `bonnet.gateway.server`
  (`mcp.add_middleware(GatingMiddleware())` etc). Importing the bare `mcp`
  object from `bonnet.gateway.tools` (rather than `bonnet.gateway.server`)
  skips that middleware entirely and shows all 45 tools regardless of state
  — a trap for anyone scripting against the tools module directly instead of
  going through `bonnet gateway`/`bonnet.gateway.server`. Not filed as a bug
  since it's not the documented entry point, but worth knowing when
  reproducing anything below.

## Empty and whitespace-only usernames accepted by register()
- **Severity**: medium
- **Steps to reproduce**:
  ```python
  await client.call_tool("register", {"username": ""})
  await client.call_tool("register", {"username": "   "})
  ```
  (after `connect("https://localhost:2272")`)
- **Expected**: `register` should reject an empty or whitespace-only
  username with a clear validation error — an empty display name is
  nonsensical for a BBS identity and likely breaks assumptions elsewhere
  (mentions, moderation reports naming "the user", etc).
- **Actual**: Both succeeded and returned normal-looking success payloads,
  e.g. for `""`:
  ```json
  {"origin": "localhost", "username": "", "public_key": "a08c87ca...", "registered_seq": 2, "tools_unlocked": [...]}
  ```
  and for `"   "` a *separate* identity was minted (not deduped/rejected as
  a collision with the empty string), also unlocking `create_board`,
  `publish_article`, etc. Both are now valid, distinct, fully-privileged
  identities on the board.

## Usernames not case-folded — homograph/impersonation risk, plus null bytes and shell/SQL-looking strings stored verbatim
- **Severity**: medium
- **Steps to reproduce**: register `scout`, `Scout`, `SCOUT` in sequence (all
  after the same `connect`); also register `'; DROP TABLE users; --'`,
  `$(rm -rf /)`, `name\x00withnull`, and `аdmin` (Cyrillic а, U+0430,
  followed by Latin "dmin").
- **Expected**: at minimum, some normalization/collision policy for
  usernames that differ only by case or by confusable Unicode code points,
  since a BBS's whole value proposition here is knowing who said what; a
  reasonable system also rejects control characters like NUL in a display
  name.
- **Actual**: `scout`, `Scout`, and `SCOUT` all registered as three
  completely distinct, fully-privileged identities with no warning. Cyrillic
  `аdmin` (U+0430 + "dmin") registered as a distinct identity that renders
  visually identical to a real `admin` in most fonts/terminals — a classic
  homograph impersonation setup for a moderation/admin context. The
  shell/SQL-metacharacter strings and the embedded NUL byte (`name\x00withnull`)
  were all accepted and stored verbatim (visible via `list_users`, see next
  entry) with no rejection or escaping — no injection was demonstrated, but
  storing raw NUL bytes in a username is likely to misbehave in C-string-based
  tooling (filenames, terminal rendering, log parsers) downstream.

## `list_users` returns Python `repr()` strings instead of structured JSON
- **Severity**: low
- **Steps to reproduce**: `list_users()` after a few registrations.
- **Expected**: a list of structured objects (dicts) with fields like
  `pubkey`, `username`, `flags`, `reg_seq`, etc., matching every other tool's
  JSON-ish output style (`register`, `connect`, etc. all return dicts).
- **Actual**: each entry is a single string that is the Python dataclass
  `repr()`, e.g.:
  ```
  "Root(pubkey='a08c87ca...', username='', flags=0, reg_seq=2, created_at=1788381565, revoked=False, revoked_seq=0, origin='localhost')"
  ```
  A calling agent has to regex/parse this rather than read JSON fields — an
  easy source of downstream parsing bugs, and inconsistent with the rest of
  the tool surface.

## Re-registering an already-known local identity name silently "succeeds" with `registered_seq: null`
- **Severity**: low
- **Steps to reproduce**:
  ```
  register("scout")   # first time -> registered_seq: 6
  register("scout")   # second time, same client/tenant
  ```
- **Expected**: either an explicit error ("already registered locally as
  scout") or, if this is deliberately idempotent, a `registered_seq`
  reflecting the *existing* registration (6), not `null`.
- **Actual**: the second call returns HTTP/tool success with the same
  `public_key` as before but `"registered_seq": null`, with no explanation
  that this was a no-op / cache hit rather than a fresh registration. Easy to
  misread as "the record's sequence number is null" (a red flag in an
  append-only log) rather than "nothing new happened."

## Over-long username crashes with a raw internal traceback instead of a validation error
- **Severity**: medium
- **Steps to reproduce**:
  ```python
  await client.call_tool("register", {"username": "x" * 5000})
  ```
- **Expected**: a clean, tool-level validation error (e.g. "username must be
  at most N bytes") caught before attempting to sign/encode the record.
- **Actual**: an unhandled `LengthExceeded` exception surfaces from deep in
  `bonnet.core.record.enc_text16` (called via `encode_intent`), wrapped only
  by FastMCP's generic `ToolError`:
  ```
  EXCEPTION: ToolError: Error calling tool 'register': text16 encoded length 5000 exceeds 4096
  ```
  There is no length check in the gateway's `register()` tool itself before
  it tries to build/sign the record — the failure happens at wire-encoding
  time, several frames deep, and the traceback exposes internal module paths
  (`bonnet/core/record.py`) to the caller. The limit (4096 bytes) is also
  undocumented anywhere in the README/CLI help.


---

## Agent 2 — Multi-Tenant Gateway / Moderation / Federation Chaos

Test setup: private board server on `https://localhost:2273` (origin
`testboard.local`, `BONNET_SERVER_HOME` under scratch dir) + multi-tenant
HTTP gateway on `http://127.0.0.1:8180` (`BONNET_GATEWAY_HOME` under scratch
dir), tenants `alice`/`bob`/`carol` created via `bonnet gateway tenant add`.
Driven with a small MCP streamable-HTTP client script plus raw `curl` against
`/health` and `/mcp`.

## `tenant remove` on a nonexistent tenant claims it needs `--yes`, hiding that it doesn't exist
- **Severity**: low
- **Steps to reproduce**:
  ```sh
  bonnet gateway tenant remove ghost
  # (ghost was never created)
  ```
- **Expected**: an error stating the tenant does not exist (which is in fact
  what happens when `--yes` *is* passed: `error: no such tenant 'ghost'`).
- **Actual**: without `--yes` the CLI prints
  `refusing to remove ghost without --yes: this deletes its signing keys, and nothing else holds a copy`
  — implying the tenant exists and only needs confirmation. An operator who
  adds `--yes` in response gets a *different*, contradictory error
  (`no such tenant 'ghost'`). The existence check should happen before the
  confirmation-required check, or the two messages should agree.

## Fresh MCP session gives a misleading "identity not held" / empty `list_identities` for an identity that *is* persisted, until `connect()` is called first
- **Severity**: medium (confusing-error / usability; could read as data loss)
- **Steps to reproduce**:
  1. In one MCP session (tenant `bob`): `connect("https://localhost:2273")`,
     `register("bob1")` — succeeds, identity persisted to
     `tenants/bob/identities.db`.
  2. Close that session. Open a brand-new MCP session with the *same* API
     key (same tenant), and — without calling `connect()` first — call
     `list_identities()`, `whoami()`, or `report(...)`.
- **Expected**: since the README states the origin and identity are
  "remembered" across gateway restarts/sessions ("a restarted gateway
  resumes with no environment set at all"), either the identity should be
  visible/usable immediately, or the error should clearly say "call
  connect() to resume your remembered origin" rather than implying the
  identity is missing.
- **Actual**:
  - `list_identities()` → `[]` (silently empty, no error, no hint).
  - `whoami()` → `Error calling tool 'whoami': No local identity found for 'bob1'`
    — reads as if the identity were deleted/lost, when it is present on disk
    (verified directly in `tenants/bob/identities.db`).
  - `report(...)` → `report is unavailable — identity 'bob1' is not held by
    this client for this origin, so nothing can be signed as it. Call
    register('bob1') to create it, ...` — actively suggests re-registering
    an identity that already exists, which would normally be a no-op/error
    but is confusing guidance regardless.
  - Calling `connect("https://localhost:2273")` first in the same session
    immediately fixes all three: `list_identities()` then returns the
    identity and `whoami()`/`report()` work. So the *only* problem is the
    error text/empty-list not pointing at the real fix (`connect` first),
    instead suggesting the identity is gone or needs recreating.

## `Authorization: Bearer` with a value ending in a trailing space crashes the MCP client transport instead of being rejected by the gateway
- **Severity**: low
- **Steps to reproduce**: send an HTTP request to the gateway's `/mcp`
  endpoint with header `Authorization: Bearer ` (scheme + single trailing
  space, empty token). Using the reference Python `mcp` streamable-HTTP
  client (`httpx`/`httpcore`), this raises client-side:
  ```
  httpx.LocalProtocolError: Illegal header value b'Bearer '
  ```
  before any request reaches the gateway.
- **Expected**: Not strictly a gateway bug (h11/httpcore refuses to send a
  header value with trailing whitespace per RFC 7230), but noting it because
  it means *any* MCP client built on this same stack will hard-crash rather
  than gracefully degrade to anonymous for this one malformed-but-plausible
  header value, which cuts against the "bad auth degrades, never fails"
  design goal stated in the README. A defensive gateway-side test (or a
  documented note) that some malformed `Authorization` values never even
  arrive as HTTP requests would be useful.
- **Actual**: unhandled `ExceptionGroup`/`LocalProtocolError` client-side;
  never reaches the gateway's own auth-degradation logic to confirm/deny
  how it would have been handled.

## Things checked and found to behave correctly (no bug, noted for completeness)
- Tenant isolation: `bob`'s API key sees empty `list_identities`/
  `list_joined_origins` even after `alice` registered identities and joined
  an origin; a tenant's identities/origins/pins are not visible or usable by
  another tenant's key.
- Revoked key, unknown/made-up key, no-auth-header, and a disabled tenant's
  live key all degrade to the shared read-only anonymous session as
  documented — never a bare `401`, `register`/`login` correctly hidden and
  refused for the anonymous session.
- Conflicting `Authorization: Bearer` + `X-API-Key` headers: `Authorization`
  wins, consistently.
- `report()` on a nonexistent article, with an empty/whitespace-only reason,
  and with a reason exceeding `max_article_body_size` (1 MiB) are all
  rejected with clear errors (`error 3: Article not found`, "A report needs
  a reason...", `error 6: Body size ... exceeds maximum ...` respectively).
  A 200 KB reason (under the limit) is accepted fine. Repeated reports of
  the same article by the same reporter are all accepted (each becomes its
  own signed record) — appears to be by design (no dedup claimed anywhere).
- `list_reports()` called by a registered, non-moderator identity is
  correctly refused ("not permitted... per the relay's own PERMISSIONS"),
  and `my_permissions()` correctly omits `REPORT_LIST` from that identity's
  granted commands beforehand — no enforcement/claim mismatch found. After
  granting `REPORT_LIST` via ACL to a specific pubkey and restarting the
  server, `my_permissions()` immediately reflects the new grant and
  `list_reports()` succeeds — consistent.
  the same request also confirms the documented "gating hides but never
  disables" behavior: `list_reports` wasn't in the client's original
  `tools/list`, yet the call succeeded once permission existed.
  No client-side way to spoof `role`/moderator status was found — `report`,
  `my_permissions`, and `list_reports` take no such parameter.
  Note: a board author reported by another user, once granted `REPORT_LIST`
  by policy, can read reports naming themself as culprit — this is an
  operator ACL choice (the shipped commented-out example doesn't scope this
  away), not a gateway bug, but worth an operator's attention.
  Duplicate/whitespace/empty/huge (5000-char)/unicode/path-traversal-like
  tenant names are all rejected by `tenant add`'s validator with a clear
  message; no directory traversal or duplicate-tenant issue found.
  `connect()` against a garbage string, a non-Bonnet HTTPS host, `http://`
  instead of `https://`, and a nonexistent port all fail with clear,
  non-crashing errors. `trust_origin_key()` with no pending decision, and
  with a garbage `decision` value, are both rejected cleanly.
  `switch_origin`/`back`/`leave_board` all handle empty/no-prior-state
  cases gracefully (`back()` with nothing to go back to just reports
  `{"state":"origin"}`; `leave_board()` with no board open returns
  `{"board":null}`).
  `GET /health`, `POST /health` (405), `GET /mcp` (406, wrong Accept),
  `DELETE /mcp` with no session (400, clear message), missing/garbage
  Content-Type (400, clear message), and a 20 MB JSON-RPC body with no
  session ID (400, same clear message, no crash/hang) were all handled
  without error or resource exhaustion.
