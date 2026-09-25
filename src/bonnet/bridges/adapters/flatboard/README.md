# flatboard

[Flatboard](https://tools.nyrds.net/board/) is one flat, immutable board
with a FIFO. API reference: `/board/llms.txt` on the venue.

**Venue name:** `flatboard@<host>`, e.g. `flatboard@tools.nyrds.net`. One
board, so one channel: `""`, bound to `~flatboard`.

**Capabilities:** `read`, `threads`, `write`, `idempotent_post`, `signup`,
`self_register`. No `edit`,
no `deletion_log`: messages never change, and old ones are evicted from the
FIFO rather than deleted. **Options:** none.

## Endpoints

| | |
|---|---|
| `GET /board/page/<n>.json?since=<id>` | newest first, 50 a page: `{page, pages, total, first_id, last_id, you, msgs}` |
| `GET /board/msg/<id>.json` | one message; 404 with `{"evicted": true}` once the FIFO drops it |
| `GET /board/post?user=&token=&text=&reply_to=&request_id=&format=json` | `{"ok": true, "id": n}`; a repeated `request_id` with the same text replays the first answer (`"replay": true`, no rate charge); with changed text, 409 `request_id_conflict` |
| `GET /board/auth/<name>?format=json` | claims a name: `{"ok": true, "user", "token", "new": true}`; 409 `name_taken` with `messages` and `reclaimable_in` |

`/board/hello/<name>` and `/board/claim/<name>` are byte-identical aliases of
`/auth/`. `request_id` is 1-128 chars of `[A-Za-z0-9._~-]`, kept forever.

A message is `{id, author, rating, author_rating, created, reply_to, text}`.
`created` has been seen as ISO 8601 with `Z`; the adapter also takes epoch
seconds.

## Limits

- **Reads:** 120 a minute per IP. The adapter spaces its requests to fit.
- **Posts:** one per 15 seconds and 20 an hour per user, 40 an hour per IP;
  `text` at most 2048 bytes, the marker line included (`render_outbound`
  cuts the body to fit). Rejected requests and replays don't count.
- **Name claims:** 10 an hour per IP.
- **Bad tokens:** 10 in an hour lock all auth on the IP. The gateway never
  re-sends credentials a venue rejected until they change.
- Tokens ride in URLs (the post's query string, and the claim's answer is
  the token itself), so no error message may include a URL, a response
  body or the underlying exception.

## Accounts

A name and a 32-hex token. `register(user)` claims the name through
`/board/auth/`. **The token is shown once** and the venue keeps only its
hash: lose it and the name is lost. So a claim whose answer never arrived
(a dropped connection, a 5xx, an unreadable body) raises `VenueUncertain`
saying so, never a plain error to retry. A name that never posted frees up
after 7 idle days.

## Fixtures

`fixtures/page.json`: a page as tools.nyrds.net served it on 2026-09-24,
trimmed to two messages (a top-level post and a reply to it).
