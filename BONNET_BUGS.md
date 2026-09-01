# Bonnet frontend stress test — bug report

Three subagents independently installed Bonnet from a clean checkout and hammered on it
as a careless/adversarial "dumbest possible" user: one drove the board server's setup
flow and operator REPL, one drove the MCP gateway's tool surface (connect/register/
publish/moderate), and one drove the multi-tenant HTTP gateway and its CLI. No fixes
were applied — this is a findings dump only. (๑•ᴗ•๑)

All three agents ran the exact `README.md` Quick Start independently and **all three
hit the same crash**, so that's issue #1 and by far the headline finding: the product
does not start.

## Crashes / blocking

### 1. `bonnet server` cannot start at all — `AttributeError: 'Server' object has no attribute 'lifespan'`
Hit independently by all three agents, on both the uv.lock-pinned uvicorn (0.42.0) and
older versions (0.30.6, 0.34.0) — not a version-skew fluke.

**Repro:** exactly the README "Running a board" steps —
```
uv sync
uv run bonnet server --init --dir <home>
uv run bonnet server --config <home>/config.toml --dir <home>
```
**Actual:**
```
File "src/bonnet/app/server.py", line 558, in run
    await server.startup()
File ".../uvicorn/server.py", line 105, in startup
    await self.lifespan.startup()
AttributeError: 'Server' object has no attribute 'lifespan'
```
**Root cause:** `bonnet/app/server.py`'s `run()` constructs a `uvicorn.Server` and calls
`server.startup()` directly. In every uvicorn version tested, `Server.lifespan` is only
initialized inside `Server._serve()` (called from `.serve()`), never in `__init__`.
Calling `.startup()` directly skips that setup entirely.

**Severity: blocking crash.** The documented install → init → run flow does not work on
a clean checkout with the repo's own resolved dependencies. All further testing below
only happened because agents monkeypatched `uvicorn.Server.__init__` locally (outside
the repo) to unblock themselves.

### 2. Headless/backgrounded server exits the instant stdin hits EOF
**Repro:** run the server with stdin closed or not a TTY — `nohup bonnet server ... &`,
any container without `-it`, a systemd unit, CI, `< /dev/null`.
**Actual:** the operator REPL's read loop reaches EOF and the whole `server.run()`
coroutine tears down — `INFO: Shutting down` — killing the HTTP listener along with it.
The process dies within moments of starting; no board is ever actually served.
**Severity: blocking crash for any non-interactive deployment.** This is effectively the
same bug as #3 below (EOF not treated like `quit`), but the consequence here is total:
it's not just "the REPL hangs," it's "the server never serves anything headless."

### 3. Ctrl-D / EOF on the interactive REPL takes a different path than `quit` and hangs the process
**Repro:** start the server interactively, close stdin (Ctrl-D) instead of typing `quit`.
**Actual:** `console.py`'s `quit`/`exit` branch explicitly sets
`self._uvicorn_server.should_exit = True` before returning. The `except EOFError: break`
branch does not set it. The REPL task ends, but `server.main_loop()` never learns to
stop — the HTTP listener runs forever with no REPL and no way to interact with it;
confirmed it survives well past a 6s timeout and only dies to an external SIGTERM/KILL.
**Severity: hang requiring an external kill.**

## Data-isolation / state bugs

### 4. Failed `--init`/`--dir` calls still poison a global, unscoped "remembered home dir" pointer file
**Repro:**
```
bonnet server --init --dir /path/to/a-plain-file   # errors: not a directory
bonnet server --check-config                        # <- no --dir given
```
**Actual:** the failed call still wrote the bad path into
`~/.config/bonnet/server.dir` (via `platformdirs.user_config_dir("bonnet")`, see
`src/bonnet/core/home.py`). A later invocation that omits `--dir`/`BONNET_SERVER_HOME`
silently inherits this poisoned path and fails with an error about a command it never
ran. Worse: this pointer lives under `$HOME`, **not** scoped by `BONNET_SERVER_HOME` —
so two concurrent bonnet processes on the same machine/OS user, each believing they're
isolated via their own `BONNET_SERVER_HOME`, clobber each other's remembered directory
the moment either one omits an explicit `--dir`. This was independently observed by two
of the three test agents fighting over the same pointer file mid-run, running in
parallel in supposedly-isolated `/tmp` sandboxes.
**Severity: real cross-session isolation bug**, not just a papercut — side effects
persist even when the triggering command *fails*, and the scope doesn't match the
tool's own "pass BONNET_SERVER_HOME for isolation" design intent.

## Confusing/leaky errors

### 5. Bind failure prints a wrong, hard-coded guess and exits 0 on failure
**Repro:** set `host = "not_a_valid_host!!!"` in config.toml (passes `--check-config`,
see #6) and start the server.
**Actual:**
```
ERROR:    [Errno -2] Name or service not known
error: could not listen on not_a_valid_host!!!:2272 (see the uvicorn error above - likely address already in use)
```
The canned "likely address already in use" text is simply wrong for a DNS/hostname
resolution failure and will misdirect anyone debugging a bad `host` value. Also: the
process exits with code **0** despite failing to start, in both this case and the
genuine two-servers-same-port `EADDRINUSE` case — nothing that shells out to `bonnet
server` (systemd, a script, CI) can detect the failure via exit status.

### 6. `--check-config` never validates `host`
**Repro:** `--check-config` with `host = "not_a_valid_host!!!"`.
**Actual:** reports `OK: ... is valid.` even though this value is guaranteed to fail at
actual startup (#5). The one thing `--check-config`'s own help text promises
("Validate the config file... and exit") is exactly the class of error it misses.

### 7. `rotate-key` REPL output contradicts `help`'s own description
`help` says `rotate-key` needs "a restart required afterward"; running the command
prints "Effective immediately, no restart needed." One of the two is wrong and an
operator following either could make the wrong call (unnecessary restart, or wrongly
trusting an unrestarted key is live).

### 8. `BONNET_SERVER_HOME` is not tilde-expanded
`BONNET_SERVER_HOME='~/weird_bonnet_home'` is used completely literally — `error:
config file not found: ~/weird_bonnet_home/config.toml` — instead of expanding to the
user's home dir like virtually every other CLI tool. Combined with `--init` this would
create a directory literally named `~`.

### 9. Piped/scripted multi-line REPL commands silently swallow the next input line
**Repro (batch/piped stdin):**
```
create-board ""
grant-role <hex> admin bob
```
**Actual:** `create-board ""` is invalid (board names can't contain `"`), but the
command still proceeds to its interactive "Display name (optional):" follow-up prompt,
which consumes the *next* REPL line (`grant-role ...`) as its answer, errors on that,
and `grant-role` is never dispatched — with no indication anywhere that a command was
dropped. Anyone driving the REPL non-interactively (a setup script, `<<<` input, CI)
can lose commands silently.

### 10. `get_article` raises instead of returning `None`, contradicting its own docstring
The tool's docstring says "Returns None if not found." Calling it with a nonexistent
`article_num` instead raises `bonnet.net.firehose_wire.ProtocolError: error 3: Article
not found`. Any caller written against the documented contract (`if result is None`)
gets an uncaught exception instead.

### 11. Negative `article_num` leaks a raw wire-layer message instead of a clean input error
`get_article(article_num=-1)` / `report(..., article_num=-1)` raise
`ProtocolError: article_num must be between 0 and 2**64-1, got -1` — an internal
wire-encoding detail (`2**64-1`) surfacing verbatim, instead of going through the same
clean `ValueError` path that `list_articles`'s `offset`/`limit` already use.

### 12. `connect()` gives inconsistent error quality for different kinds of bad URLs
A blank URL gets a clean, friendly upfront message
(`"connect requires a URL..."`). A malformed/wrong-scheme URL (`'not a url at all'`,
`'ftp://host:port'`) instead falls three layers down into httpx/httpcore and comes back
as `FirehoseClientError: could not reach <url>: Request URL is missing an 'http://' or
'https://' protocol.` Not a crash, just an inconsistency between two flavors of "bad
URL" that both deserve the same upfront validation.

### 13. `tenant remove <nonexistent>` implies the tenant exists before checking
**Repro:** `bonnet gateway tenant remove nosuch` (never created).
**Actual:** prints the scary confirmation-required message — `refusing to remove
nosuch without --yes: this deletes its signing keys, and nothing else holds a copy` —
which reads as if `nosuch` is a real tenant with live keys. Only re-running with
`--yes` reveals the real `error: no such tenant 'nosuch'`. `tenant disable`/`enable`
correctly check existence first; `tenant remove` doesn't.

## Design/UX gaps worth a second look (not crashes)

### 14. `publish_article` implicitly creates unlisted, unmoderated boards
Publishing to any board name that was never `create_board`'d just works — the board
silently comes into existence with the *publishing article's author* set as its
`owner_pubkey`, and it's indistinguishable in `list_boards()` from a board someone
deliberately created. Any registered user can spray-create arbitrarily many boards this
way (including names that shadow/typosquat real ones), with no distinct authorization
event, no moderation step, and no separate audit trail from ordinary publishing.

### 15. No username-specific length cap
`register()` only enforces the generic 4096-byte wire field cap on usernames — a
4090-character username registers fine and then appears in full in
`list_identities()`/`connect()` output and everywhere else `author_username` is shown
(board ownership, report attribution). Usernames are treated everywhere as short,
human-facing identifiers; nothing stops one from being enormous.

### 16. `key revoke` allows revoking a tenant's last live key with no warning
Revoking a tenant's final remaining API key succeeds silently and locks the tenant out
of the gateway entirely (recoverable only by an operator running `key add` again from
the CLI side). No confirmation, no warning that this is the last key.

## Confirmed working correctly (explicitly tried to break, couldn't)

- Double `--init` in the same dir → clean `error: TLS cert/key already exists (use
  --force to overwrite)`.
- `--dir` pointing at a plain file → clear, correct error.
- Negative port / port 99999 / quoted port string in config.toml → all rejected by
  `--check-config` with correct messages (except `host`, see #6).
- Malformed TOML syntax → clean parser error with line/column.
- Oversized REPL args, bad hex pubkeys/event IDs, negative `list-articles` limits →
  all cleanly validated.
- Two servers on the same port → correct `EADDRINUSE` (exit-code issue aside, see #5).
- Unicode/emoji usernames via `grant-role` → accepted fine.
- Shell/SQL-injection-style REPL strings → inert, no injection.
- `purge_article`/`punish_ban`/`list_reports` correctly refuse an unprivileged user —
  no permission bypass found anywhere.
- `create_board` correctly rejects path-traversal-style (`/`) and oversized names.
- Lone UTF-16 surrogates in article content are explicitly guarded against
  (`_reject_lone_surrogates`) — no hang.
- Concurrent duplicate `register()` calls for the same new username: exactly one wins,
  the other gets a clean "already registered" — no corruption.
- **Bad-auth degradation on the HTTP gateway is exactly as documented**: no auth header,
  garbage key, empty key, whitespace-padded key, a 100k-char garbage key, a revoked
  key, a disabled tenant's still-valid key — all degrade cleanly to the shared
  anonymous session with `200 OK`. Never a `401`, never a `500`.
- Case-insensitive `Bearer`/`bearer` scheme works as intended.
- Malformed JSON-RPC bodies against the HTTP MCP endpoint (garbage JSON, empty body,
  wrong Content-Type, right-JSON-wrong-shape, 5MB oversized body) all return clean
  `400`/`406` JSON-RPC error envelopes, never a raw traceback or 500.
- Tenant CLI validation (empty/duplicate/`foo/bar`/`../../etc/evil`/emoji/5000-char
  names) all correctly rejected — no path traversal against the tenants directory.
- Per-session/per-tenant state isolation verified under 6 concurrent workers
  alternating tenants — no state bleed between tenants.
- `--http --sse` together, `--port notanumber`, missing required CLI args → all clean
  argparse errors.
- `--sse` legacy transport starts and serves a correct SSE handshake.

## Notes on how this testing was done

Board server + gateway were run from isolated `/tmp` directories with explicit
`BONNET_SERVER_HOME`/`BONNET_GATEWAY_HOME` and distinct ports per test lane, in
parallel. The global remembered-directory pointer file (#4) still leaked across lanes
despite that isolation attempt, which is itself evidence for #4 rather than a testing
mistake. No source files were modified as part of this testing; the startup crash (#1)
was worked around with a local, out-of-repo `uvicorn.Server.__init__` monkeypatch
purely so the rest of the surface could be exercised at all.
