# Venue adapters

Every adapter Bonnet ships lives here, one folder per venue type. The
runtime never knows which venue it's talking to: it polls, fetches and posts
through the `VenueAdapter` interface in `bonnet/bridges/adapter.py`, and
branches only on the capabilities an adapter declares.

```
adapters/
  __init__.py      BUILTIN_ADAPTERS and BUILTIN_FAKES: the registry
  <type>/
    __init__.py    exports the adapter class
    adapter.py     the adapter
    fake.py        an in-memory fake of the venue (shipped, not test-only)
    README.md      the venue's quirks: limits, accounts, what it can't do
    fixtures/      responses captured from the real venue
```

## Adding a venue

1. **Copy `flatboard/`** to `<type>/`. The type is the venue name's prefix
   (`<type>@<host>`): lowercase, no `~` or `.`.
2. **Implement the adapter.** Import only `bonnet.bridges.adapter` and
   `bonnet.bridges.venue`: an adapter runs next to the puppet secret and
   never touches server internals. Set `protocol = 1`, `type`, `limits`,
   `options`, and `capabilities`, claiming only what the venue really does:

   | capability | means | needs |
   |---|---|---|
   | `read` | posts can be polled and fetched (required) | `poll`, `fetch`, `cursor_after`, `cursor_from_ids`, `close` |
   | `threads` | posts carry `reply_to` | |
   | `write` | accounts can post | `post`, `render_outbound`, `max_text_bytes` |
   | `idempotent_post` | posting twice with one key posts once | `write` |
   | `edit` | posts change; `fetch` shows the new text | |
   | `deletion_log` | the venue lists deletions | `deletions` |
   | `signup` | reserved for account linking | `signup_instructions`, `register` |

   The loader checks all of this before a venue starts, and refuses an
   adapter that claims a capability it doesn't implement.
3. **Write `fake.py`** from the venue's API docs: a `VenueFake`
   (`bonnet/bridges/conformance.py`) that serves the endpoints your adapter
   calls, through `httpx.MockTransport` or whatever your transport is.
4. **Capture fixtures** from the real venue: a page, a single post, a
   missing post, a post response. Trim them and check them in. A test in
   `tests/adapters/test_<type>.py` should pin your parsing to them, and the
   fake's response shape to theirs.
5. **Register it** in `BUILTIN_ADAPTERS` and `BUILTIN_FAKES`. That's all it
   takes for `tests/adapters/test_conformance.py` to run every check
   against it.
6. **Write `README.md`**: rate limits, text limits, how accounts work, what
   gets an account or an IP locked out, and anything the adapter can't do.

An adapter doesn't merge without passing the conformance suite. It never
runs against a live venue: fakes and fixtures only.

## Third-party libraries

An adapter that needs one gets an extra of its own in `pyproject.toml`
(`bonnet[<type>]`, also listed in `bonnet[venues]`) and imports it only in
its own folder. Adapters load lazily, so a missing extra fails startup only
for servers that configure that venue.

## Adapters outside this repo

The entry point group `bonnet.bridges.adapters` still loads adapters from
other installed packages, for types no built-in covers (built-ins can't be
replaced). They get the same interface checks, and can run the same suite:

```python
from bonnet.bridges.conformance import CHECKS, run

for check in CHECKS:
    await run(check, MyFakeVenue)  # raises on failure; False if skipped
```
