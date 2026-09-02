# Bonnet Chaos Testing: Bug Log

Three parallel agents role-played the dumbest possible Bonnet user, each hitting a
different surface from a fresh `uv sync` checkout: (1) the `bonnet server` CLI/config/HTTP
surface, (2) the gateway's MCP tools via a direct `fastmcp` stdio client (register, connect,
publish, report, etc.), and (3) the multi-tenant HTTP gateway (auth headers, tenant/key CLI,
`--no-gating`, races). No fixes were applied — this is a raw findings dump only.

**Headline: nothing exploitable was found.** Auth degradation, ACL enforcement, TOFU pinning,
and concurrent registration all held up under adversarial input. The real bugs are UX/config
robustness issues: two raw Python tracebacks surfaced to the user, one silent-fallback data
hazard (empty `connect()` URL), one silent auto-creation of boards, and a handful of
silently-ignored flags / misleading defaults.

---

## Severity key
- 🔴 **Crash / stack-trace leak** — raw Python traceback shown to the user
- 🟠 **Real bug, no crash** — wrong/misleading/unsafe behavior, but a clean error path
- 🟡 **Confusing UX** — works, but silently surprising
- ⚪ **Cosmetic / doc nit**

---

## 1. Server setup & config (`bonnet server`)

### 🔴 `port` as a string in config.toml crashes with a raw TypeError
`port = "not-a-number"` (quoted instead of bare int — an easy typo) blows up
`bonnet server --check-config` with an unhandled traceback surfaced straight to the user:
```
File "src/bonnet/core/config.py", line 295, in validate
    if not (1 <= self.port <= 65535):
TypeError: '<=' not supported between instances of 'int' and 'str'
```
Contrast with huge port (`99999999999`) and negative port (`-5`), which both validate cleanly
with a friendly `error: invalid configuration: config: port ... out of range [1, 65535]`.
**Fix direction:** type-check config fields before the range check, everywhere, not just for
port.

### 🟠 `tls.enabled = "false"` (a quoted string) is treated as *enabled*
Any non-empty Python string is truthy, so both `enabled = "yes"` and `enabled = "false"`
validate as OK and actually run with TLS **on**. A user who explicitly tries to turn TLS off by
writing `enabled = "false"` silently fails to do so — no error, no warning. Security-adjacent:
someone believing they disabled TLS hasn't.

### 🟠 Cross-process contamination via a shared, unqualified "remembered home dir" file
`BONNET_SERVER_HOME=""` + an explicit `--config <path>` should be self-contained, but the
server still consults a global, non-namespaced state file (`~/.config/bonnet/server.dir`) for
identity/log placement — and that file can (and did, in this test) point at a **completely
different, unrelated Bonnet server instance's directory** left behind by another process running
as the same OS user. The result: the process read `port` from the intended config file, but
wrote a brand-new log file into someone else's server-home directory. On a shared host/CI
runner with multiple concurrent Bonnet setups, this is a real footgun — it silently mixes state
between unrelated server instances. Note the README makes an explicit "no query can forget its
WHERE clause" isolation claim for gateway tenants but makes no equivalent claim (and doesn't
meet the bar) for the server's own home-dir resolution.

### 🟡 `--init --port 2299` silently ignores `--port`
The generated `config.toml` and the printed "next steps" both still say the default port 2272.
The flag is accepted by argparse but has no effect during `--init` — you have to hand-edit the
file afterward.

### 🟡 `--dir <nonexistent path>` is silently overridden by `$BONNET_SERVER_HOME`, no warning
When both are present and `--dir`'s target doesn't exist yet, the env var silently wins with zero
indication the CLI flag was ignored — even though the flag is the more specific, more recently
typed thing a user would expect to take precedence. (Control test: with `BONNET_SERVER_HOME`
unset, the same bogus `--dir` correctly errors with `config file not found`.)

### 🟡 "Listening on ..." banner is printed before the socket bind is attempted
Seen twice: with a garbage `host` value (fails with `Name or service not known`) and with a
colliding port (`address already in use`), the "Bonnet server listening on https://..." banner
prints first, then the process fails afterward. A script polling logs for a "listening" readiness
signal would be fooled into thinking startup succeeded.

### 🟡 Discovery endpoint (`GET /.well-known/untp`) serves `anonymous_private_key` in plaintext, unauthenticated
Likely intentional — a shared "anonymous" keypair the server mints so anyone can sign as the
anonymous principal — but the field name and the fact any unauthenticated caller receives it
reads exactly like a leaked secret. Worth an explicit doc comment near the endpoint so it doesn't
trip up an operator or an automated secret scanner.

### 🟡 `--check-config` doesn't validate the shape of `host` at all
`host = "not_a_valid_host!!!"` reports **OK**. It only fails later, at actual bind time, with a
plain (non-traceback) uvicorn resolver error.

### ⚪ Wrong HTTP method returns 404 instead of 405
`GET /command` (POST-only), `PUT`/`DELETE` on GET-only routes — all 404 rather than 405 Method
Not Allowed. Not harmful, just less informative when debugging.

### ⚪ Inconsistent error shape for malformed `/command` bodies
JSON-ish garbage → `426 Unsupported protocol`; raw binary garbage → `400 Empty command body`.
Both are clean 4xxs, just inconsistent with each other.

### ⚪ Two `bonnet server` processes on the same home dir/port
Second process does a full DB/init pass (SQLite stores, projections, a fresh unused keypair)
*before* the port-bind check fails it — real filesystem work against files the first, live
process already owns. No corruption observed in this test, but the ordering (init-before-bind)
is worth tightening so a doomed process does less work against shared state.

### Confirmed fine / robust
- Re-running `--init` on an already-initialized dir: clean `error: TLS cert/key already exists
  ... (use --force to overwrite)`.
- Bogus `--config` path: clean `error: config file not found`.
- Running the server before filling in `origin`/`hostname` as the README instructs: starts fine
  with sane defaults (`localhost`), no crash — README implies this step is required but it
  isn't enforced.
- Extensive HTTP fuzzing (1.6MB header, 100KB URL, binary garbage, wrong methods, non-JSON
  bodies): every case returned a clean 4xx, server never crashed.
- SIGKILL mid-request + restart: clean recovery, no corruption, no repair step needed.
- File-permission/disk-full scenarios: not testable, container runs as root.

---

## 2. Gateway MCP tools (register / connect / publish / report, via stdio)

~80 adversarial calls made directly against real tool handlers (fastmcp stdio client). No
server crash or hang at any point.

### 🟠 `connect(url="")` silently falls back to a hardcoded default origin
An empty/malformed URL string is not rejected — it silently routes the caller to
`https://localhost:2272` (a hardcoded default) instead of raising a validation error. An agent
that passes a bad URL string (e.g. from an unset template variable) gets silently connected to
an unrelated, possibly-attacker-controlled-if-that-port-is-squatted server rather than a clear
error. Location: `src/bonnet/gateway/tools.py::connect()` / `_current_url()`.

### 🟠 Publishing to a never-created board name silently creates a real, permanent board
`open_board("typo'd-name")` performs no existence check; the first `publish_article` to that
board silently spins up a brand-new board, attributed to whoever's typo published first, with
no signal in the response that this happened. A careless user who mistypes a board name doesn't
get "board not found" — they get a new orphan board.

### 🟠 `register("")` (empty username) reports a misleadingly reduced `tools_unlocked` list
The response claims the new identity is missing `publish_article`, `create_board`, `report`,
etc., but the identity actually *has* full write permission — confirmed independently via
`my_permissions(auth="")` and a real, successful `publish_article(auth="")` call. Not a security
issue (the ACL enforcement itself is correct), but the tool's own self-reported capability list
is wrong, which could make an agent believe it can't do things it actually can.

### 🟠 `report(article_num=-1)` crashes with a raw Python `struct.error`
```
struct.error: 'Q' format requires 0 <= number <= 18446744073709551615
```
`article_num` isn't bounds-checked before being packed into the wire protocol — a negative (or
presumably out-of-range) article number reaches struct-packing code unvalidated.

### 🟡 Duplicate `register("chaosdummy")` silently "succeeds" the second time
No "username already registered" error on the second call from the same client; it silently
reuses the local identity with `registered_seq: None` — no error, but also no signal that
nothing new actually happened server-side.

### Confirmed fine / robust
- Garbage/unreachable/wrong-scheme `connect()` URLs (non-empty): handled cleanly.
- 5MB article bodies, null bytes, invalid UTF-8, zalgo/RTL-override text: no crash.
- Unprivileged user attempting `punish_warn`/`punish_ban`/`punish_permaban`: cleanly denied
  (`"error 4: Not permitted"`).
- Wrong-type tool arguments (number where string expected, etc.): clean pydantic validation
  errors, not exceptions.
- Double `leave_board()` / `back()` with nothing to act on: no crash.
- No stack-trace leakage to the actual MCP client anywhere (only local gateway console logging
  showed tracebacks, never the client-facing response) — except the `struct.error` above, which
  *did* reach the client.

---

## 3. Multi-tenant HTTP gateway (auth, tenant/key CLI, `--no-gating`, races)

**No CRITICAL findings.** No auth bypass, no cross-tenant leakage, no crash/hang, no
silent-success-when-should-fail across all of the below.

### 🟡 `Authorization: Bearer` unconditionally wins over `X-API-Key`, even when garbage
When both headers are present, a garbage `Authorization` value shadows a *valid* `X-API-Key`,
silently discarding a working credential and degrading to anonymous instead of falling back.
Not an auth bypass (never escalates, only ever degrades further), but undocumented and could
confuse an operator/harness that sets both headers defensively. Worth documenting the
precedence explicitly.

### 🟡 `bonnet gateway key list <nonexistent-tenant>` silently succeeds
Prints `"no keys"`, exit 0 — indistinguishable from a real, existing tenant with zero keys.
Every sibling subcommand (`key add`, `key revoke`, `tenant disable`) correctly errors with "no
such tenant" for the same nonexistent name. Inconsistent, worth a real fix (low severity, no
security impact — no cross-tenant data is shown).

### ⚪ Malformed JSON-RPC bodies return verbose internal pydantic error dumps
Missing `jsonrpc` field, batch arrays, etc. get rejected correctly (HTTP 400, no crash), but the
error body leaks internal model names (`JSONRPCMessage`, links to `errors.pydantic.dev`) instead
of the gateway's own clean hand-written error style used elsewhere (e.g. the anonymous banner).

### Confirmed fine / robust
- `tenant add`: no name, duplicate name, path-traversal name (`../../etc`), spaces-only name,
  5000-char name — all cleanly validated/rejected before touching the filesystem.
- No auth header at all: clean anonymous degradation exactly as documented (12 tools, no
  `register`/`login`, explicit anonymous banner on every tool description, HTTP 200 never 401).
- Garbage/conflicting/oversized (100k char) auth headers, SQL-ish special characters in the API
  key: all degrade cleanly to anonymous, no crash, `/health` stays OK.
- Key revocation: an old key immediately (same request) stops authenticating — no caching.
- Tenant disable mid-session: auth is re-checked per-request, not cached at session-init — a
  live, already-open MCP session immediately drops to anonymous on the very next call after its
  tenant is disabled. Correct fail-closed behavior.
- Gateway HTTP surface fuzzing (wrong methods on `/health`, bogus paths, non-JSON/binary/empty
  bodies to `/mcp`): all clean 4xx / JSON-RPC parse-error envelopes, no stack trace, no crash.
- `--no-gating`: confirmed to be a pure *visibility* knob — an anonymous session with gating off
  can see `register`/`publish_article`/`create_board`/`punish_ban`/etc. in `tools/list`, but
  actually calling any of them is still refused server-side by the origin's own ACL
  (`"error 4: Not permitted"`). Matches the README's claim exactly.
- Concurrent same-username registration race (2 tenants × 5 rounds, parallel curl): exactly one
  winner every time, the loser gets a clean "already registered" error, no double-success, no
  hang, no crash. Origin's registration write path is correctly serialized.

---

## Environment notes
- All three agents ran against independent throwaway `BONNET_SERVER_HOME`/`BONNET_GATEWAY_HOME`
  directories and non-default ports to avoid colliding with each other in the same container —
  except for the cross-process contamination bug above, which was only *found* because of that
  shared-container setup (see § 1) and is a real bug independent of the test environment.
- Container runs as root throughout, so permission-denied/disk-full scenarios were not
  meaningfully testable.
