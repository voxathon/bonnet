# Code Review Brief

Reference material for review agents working on this codebase.
Written 2026-08-31, verified against `staging` at `e340d1d`.

Line numbers drift, and several in earlier revisions of this file had
already gone stale. Citations below name the code by grep-able text wherever
one exists. Re-verify any citation against the current tree before acting on
it — including the ones in this file.

---

## READ THIS FIRST: five findings you must not make

All five are documented decisions. Four of them are things a previous review
already got wrong. Do not spend a finding on any of these.

1. **There are no users.** Backward compatibility, migration paths,
   deprecation windows and "user-facing break" are never costs in this repo.
   The clean cutover is always the right answer. Do not hedge about it.

2. **`anonymous_private_key` in the discovery manifest is deliberate and
   correct.** The key is a *principal*, not a credential — a well-known
   constant, the same category as a published test vector. A shared key
   everyone holds is identical in security to a per-client ephemeral key;
   publishing it is honesty, not leakage.

   Related: do **not** propose collapsing this to "one uniform code path."
   Signature *verification* is uniform; *policy* branches: replay-ledger
   admission, rate-limit keying, and principal resolution each branch on
   `is_anonymous` in `firehose_http_server.py`. Confirm with
   `grep -n is_anonymous src/bonnet/net/firehose_http_server.py` rather than
   from a line number here. A reviewer who claims otherwise gets grepped and
   disbelieved.

3. **Skipping replay checks for anonymous requests is safe.** It is safe
   because of the idempotency check in `core/firehose.py` — the
   `SELECT encoded_record FROM events WHERE origin=? AND event_id=?` whose
   hit re-encodes the stored intent and returns the existing record when the
   bytes match. A replayed request is byte-identical by definition and lands
   there as a no-op. It is *not* safe because anonymous is read-only:
   anonymous writes are a legitimate operator choice.

4. **Mechanism, not policy.** The relay is a neutral transport. It does not
   adjudicate content and does not restrict operator choices. Do not propose
   trust envelopes around bodies, forbidding anonymous writes, or any other
   policy pushed down into the substrate.

5. **`internal/*.md` is not a specification.** The implementation and its
   executable tests are the only baseline. `internal/BUGS.md` in particular
   has drifted: its line numbers are stale and at least two of its eight
   findings are already fixed. Re-verify anything you cite from it against
   current source first.

   Note that `internal/` is gitignored (`.gitignore:33`). It is present in a
   local working tree and absent from any clone or cloud checkout. If you
   cannot see it, that is expected — work from the source and the tests, and
   do not report the directory as missing.

**If you get `--fix`:** every behavioral fix needs a regression test, and you
must show the test failing without the fix. Do not combine a correctness fix
with unrelated formatting. Small, reviewable commits.

---

## Lane 1 — The codec is forked three ways, and one fork has no bounds checks

Highest value lane. Give it your deepest attention.

`_read_text16` / `_enc_text16` / `_read_u16` / `_read_id32` exist as three
independent copies:

| copy | location | bounds-checked |
|---|---|---|
| server | `src/bonnet/net/firehose_commands.py:147` | yes, raises `ValueError` |
| client | `src/bonnet/net/firehose_wire.py:83` | **no** |
| REPL | `src/bonnet/app/console.py:531` (as methods) | unchecked |

They have already diverged:

```python
# firehose_commands.py:187 — server
def _read_id32(data, offset):
    if offset + 32 > len(data):
        raise ValueError("truncated id32")
    return data[offset:offset+32], offset + 32

# firehose_wire.py:115 — client
def _read_id32(data, offset):
    return data[offset:offset+32], offset + 32
```

Python slicing does not raise. A truncated response therefore yields a
silently *short* event_id, blob, or body rather than an error, and
`_read_text16` decodes fewer bytes than its own length prefix claims without
complaint. Where the client copy does fail it raises `struct.error`,
`IndexError`, or `UnicodeDecodeError` — none of which is a `ProtocolError`,
and a grep finds zero handlers for those three outside `core/record.py`.

This is the parser facing bytes from a remote origin.

**What to do:** for every decoder in the tree, read the encoder and the
decoder side by side and check truncation, over-long length prefixes, and
trailing garbage. Do not trust either half alone — the only two real bugs
found while writing the spec came from exactly this method.

---

## Lane 2 — Which opcodes bypass the board ACL dimension

Deep attention. This is a question to answer, not a confirmed bug.

`handle()` at `firehose_commands.py:376` checks only the **command**
dimension; the board is not known at that point. Board scoping is enforced
per handler by `_board_read_allowed` (`firehose_commands.py:309`), whose own
docstring states that skipping it makes an ACL rule scoped to
`boards = [...]` a no-op.

Current coverage:

| read handler | board filter | returns |
|---|---|---|
| `board_list`, `article_get`, `article_list` | applied | projections |
| `article_search`, `article_query`, `article_body` | applied | projections |
| `report_list` | applied | moderation queue |
| `event_get` (`:841`) | **none** | full encoded record |
| `event_range` | **none** | record ranges |
| `event_body` (`:1423`) | **none** | raw body bytes |

Records carry a `board` field. So a caller granted the substrate opcodes can
read barred boards by walking the log and fetching bodies by event id — the
exact failure the application opcodes defend against, one layer down.

This may be deliberate: the substrate is a log, and a log is transparent by
design. But it is undocumented either way, and notebook §6 already flags the
shape — *check ACL coverage on any opcode added after `8f4b592`*.

**What to do:** enumerate every read handler and state, per opcode, which ACL
dimension gates it and what it returns. Then say whether the substrate gap is
intended, and what the spec should say about it.

---

## Lane 3 — Machinery with no consumer

Mechanical sweep. This is the author's stated cruft pattern #3.

25 functions are defined and never referenced anywhere in `src/` or `tests/`.
After removing decorator-registered false positives (MCP tools, resources,
middleware hooks), the genuine ones:

- `BodyStore.cleanup_staging` — `core/bodies.py:400`. The startup sweep at
  `app/server.py:304` uses `list_staged_article_bodies` +
  `delete_staged_article_body` instead. Dead sibling.
- `FirehoseClient.publish_record` — `gateway/firehose_client.py:192`. The
  gateway's only write wrapper, uncalled.
- `decode_unsigned_head` (`core/record.py:847`),
  `decode_unsigned_witness` (`:926`),
  `metadata_field_bytes` (`:335`) — decoders with no decode site.
- `Firehose.get_next_article_num` — `core/firehose.py:1048`
- `PermissionSet.may_publish` — `net/firehose_models.py:273`
- `logging.is_initialized` — `core/logging.py:84`
- `caller_is_ready` — `gateway/gating.py:226`
- `Cursor.at_end` — `core/record.py:244`
- `FirehoseHTTPServer.anonymous_public_key` (property) — `:569`

**What to do:** redo this sweep properly rather than trusting the list, then
for each one decide: delete it, or wire it up. Note which are reachable only
through a decorator registry before calling anything dead.

---

## Lane 4 — The untested half of the MCP surface

Mechanical. 14 of 45 `@mcp.tool` functions in `gateway/tools.py` are never
named in `tests/`:

```
purge_article    restore_article  supersede_article
pin_article      unpin_article    rotate_identity_key
report           punish_warn      punish_ban       punish_permaban
punish_revoke    acknowledge_punishment            my_punishments
```

That is 13 of 45, and it is every moderation tool plus every destructive
tool except `cancel_article`.

`cancel_article` is *not* in the list: `tests/test_gateway_cursor.py` drives
it three times, including a full publish → cancel → assert-cancelled
round-trip. That matters beyond the one name, because it shows how tests
reach these tools — **by attribute access on the tools module, not by string
name through `call_tool`**. Grep for the bare identifier, both ways, before
you believe any entry above is uncovered.

Given the threat model in notebook §14 (agent-authored content arriving over
federation), the moderation surface being the untested one is the wrong way
round.

**What to do:** confirm the list, then write the missing end-to-end tests,
highest-consequence first: `purge_article`, `punish_permaban`,
`rotate_identity_key`.

---

## Lane 5 — Three different SQLite disciplines in one tree

| modules | connect | WAL / busy_timeout | lock |
|---|---|---|---|
| `core/firehose`, `core/board_projection`, `core/global_projections` | `check_same_thread=False, isolation_level=None` | yes | yes (23–35 sites) |
| `core/trust`, `net/replay` | `check_same_thread=False` | partial | yes |
| `gateway/origins`, `gateway/registry` | `check_same_thread=False` | **no** | **none** |
| `gateway/identity` | thread-local connections | no | n/a |

The `core/` trio is coherent: `asyncio.to_thread` at
`net/firehose_http_server.py:418` means real thread concurrency, and the
explicit `BEGIN IMMEDIATE` / `ROLLBACK` / `raise` blocks match it.

The gateway stores are a shared connection using **implicit** transactions
with no lock, reached from `async` MCP tools that `await` between statements.

**What to do:** establish whether two concurrent tool calls can interleave
statements inside one implicit transaction on the shared gateway connection.
Answer with a test if the answer is yes.

Cleanup while you are in there: the `BEGIN IMMEDIATE` / `try` / `ROLLBACK;
raise` block is copy-pasted verbatim ten times in `core/board_projection.py`,
nine more in `core/firehose.py`, and again in `core/global_projections.py`.
One context manager replaces all of it. Enumerate the sites with
`grep -rn "BEGIN IMMEDIATE" src/` — do not work from a line list, and do not
stop at the run of adjacent ones: `board_projection.py` has an outlier near
the top of the file and another past line 1000.

---

## Lane 6 — Small, real, cheap

- **Rate limiter uses the wall clock.** `net/rate_limiter.py:28,52` takes
  `time.time()` for bucket windows; a backwards NTP step widens the window.
  Use `time.monotonic()`.

  `net/replay.py:126` also uses `time.time()` and that is **correct** — it
  compares against signed timestamps from the wire. Do not "fix" it.

- **No SSRF in the on-read sync trigger.** `_maybe_queue_remote_sync`
  (`firehose_commands.py:302`) takes a caller-supplied origin but
  `queue_sync_threadsafe` allowlists it with `origin not in self._clients`.
  Stated here so nobody spends a finding on it.

  The real question there is `_inflight` in `net/firehose_sync.py:260-272`:
  read unlocked from a worker thread while mutated on the loop thread, and an
  origin that dies between `add` and its removal appears to be permanently
  un-syncable. Check the failure path.

- **Orphan bodies are swept only at startup** (`app/server.py:291-323`). A
  long-lived process accumulates staged orphans until restart.

- **One dynamic SQL site**, `core/firehose.py:1325`, interpolating a table
  name into `DELETE FROM {table} WHERE {col}=?`. Looks constant-driven —
  confirm the set of table/column values is closed.

---

## Suggested fan-out

| agent | lanes | model |
|---|---|---|
| wire codec | 1 | deepest |
| ACL & opcode coverage | 2 | deepest |
| dead code & test gaps | 3, 4 | cheap; mechanical |
| concurrency & storage | 5, 6 | mid |

Every agent gets the anti-lane section at the top of its prompt.

---

## Background reading

`internal/NOTEBOOK.md` is the working record for this codebase and is far more
complete than this file. Read at minimum:

- §0 — the docs are hidden and stale; what each one is worth
- §1 — the UNTP / Bonnet two-layer split, and where the seam falls
- §2 — the eight domain separation tags (load-bearing constants)
- §3 — record vs. event; they are not the same bytes
- §5 — the auth model and the anonymous key
- §6 — opcodes and status codes
- §12 — how the author works; what gets shot down and why
