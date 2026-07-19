# Bonnet Protocol v3 Operator Guide

## Overview

Protocol v3 replaces Bonnet's mutable post model and separate
report/punishment federation systems with one immutable, origin-signed
article feed protocol. This document covers operator-facing procedures.

## Backup

Before any upgrade or migration, back up these directories:

- `data/` — all SQLite databases, userfile, replay ledger, article feeds
- `boards/` — board directories with post body files (legacy v2)
- `config.toml` — server configuration
- Identity file (typically `data/identity`)

```bash
tar czf bonnet-backup-$(date +%Y%m%d).tar.gz data/ boards/ config.toml
```

## Migration

Migration from v2 to v3 runs automatically on server startup. It is:

- **Idempotent** — safe to run multiple times; completed units are skipped
- **Non-destructive** — legacy databases are read but never modified
- **Automatic** — triggered by `MigrationExecutor.migrate_all()` in `app/server.py`

Migration converts:
- Local posts → ARTICLE events (preserving `post_num` as `article_num`)
- Local rules → RULE events on the `moderation.rules` board
- Local reports → REPORT events on the `moderation.reports` board
- Local punishments → PUNISHMENT events on the `moderation.actions` board

Legacy signatures are preserved in migration extension blocks (scheme 0 or 2).
The migration never forges author signatures.

### Manual migration

To run migration manually (e.g., after restoring a backup):

```python
from core.migration import MigrationExecutor
executor = MigrationExecutor(store, identity, config, ame=ame, keibatsu=kei)
results = executor.migrate_all()
print(results)  # {'posts': N, 'rules': N, 'reports': N, 'punishments': N}
```

### Verification

After migration, verify event counts:

```python
results = executor.verify_migration()
assert results["verified"], results["errors"]
```

## Feed Subscription Configuration

Configure feed imports in `config.toml`:

```toml
[[feed_subscription]]
origin = "community.example"
boards = ["general", "moderation.reports", "moderation.actions"]
relays = ["community.example", "cache.example.net"]
body_policy = "on-demand"  # none | on-demand | eager

[[feed_subscription]]
origin = "archive.example"
boards = ["*"]  # wildcard: all boards
relays = ["archive.example"]
body_policy = "on-demand"
```

### Body policies

| Policy | Behavior |
|---|---|
| `none` | Import metadata only; no body fetch |
| `on-demand` | Fetch bodies when locally requested (default) |
| `eager` | Fetch bodies immediately after metadata acceptance |

### Control policies

Control policies determine which event types are enforced from each feed:

```toml
[[control_policy]]
origin = "community.example"
board = "moderation.actions"
apply = ["punishment", "punishment-revoke"]
```

Without a control policy, events are accepted but not enforced (archive-only).

## Moderation Boards

Configure local moderation board names:

```toml
[moderation_boards]
rules = "moderation.rules"
reports = "moderation.reports"
punishments = "moderation.actions"
```

These are the boards where RULE, REPORT, and PUNISHMENT events are published.

## Purge Semantics

A PURGE event declares physical body removal by the origin. Key properties:

- **Metadata is never deleted** — the article event, body hash, and body size
  remain in the feed and are exportable
- **Body bytes may be deleted** — the origin may delete its local body blob
  after committing the purge event
- **Peers are not forced to delete** — independent peers may retain bodies
  after an origin declares a purge
- **Direct retrieval** reports `body_available=false` for purged articles
- **Purge is terminal for origin body availability** — a later RESTORE may
  restore visibility of metadata but cannot reconstruct missing bytes

## Cancellation Semantics

A CANCEL event changes the projected visibility of an article:

- **Not erasure** — cancelled articles remain in the feed with full metadata
- **Default list/search** excludes cancelled articles
- **Direct retrieval** (by message ID or article number) returns the article
  with `projected_state=cancelled` and the cancel event IDs
- **Body bytes are never deleted by cancellation**
- **RESTORE** returns a cancelled article to active state

## Effective Bans

Effective bans are derived from accepted PUNISHMENT events:

1. The event must come from a feed with a control policy that includes
   `"punishment"` in its `apply` list
2. The event must not be a warning (`expires_at == 0`)
3. The event must be permanent (`expires_at < 0`) or unexpired
4. The event must not have an applicable PUNISHMENT_REVOKE
5. The event must pass the per-origin temporal filter

During the migration transition, effective bans union legacy Keibatsu
punishments with v3 event-derived punishments.

## Sync Configuration

```toml
[sync]
interval_seconds = 300      # periodic sync interval (default 5 min)
backoff_max_seconds = 3600  # max backoff on failure (default 1 hour)
```

The periodic scheduler:
- Enumerates relay candidates from feed subscriptions and known board relays
- Queues each peer at the configured interval with jitter (0.75x–1.25x)
- Applies exponential backoff per peer on failure
- Does not let one failing peer block the queue

## Discovery

The discovery endpoint (`GET /.well-known/bonnet`) advertises:

```json
{
  "protocol_versions": [3],
  "command_endpoint": "/v3/command",
  "capabilities": [
    "user-registry-merkle-v1",
    "command-object-acl-v1",
    "immutable-article-feed-v1",
    "article-control-messages-v1",
    "article-body-by-hash-v1"
  ]
}
```

Protocol v2 is no longer advertised. The `/v2/command` endpoint remains for
retained v2 commands (REGISTER, BOARD_CREATE/LIST, POST_CREATE/GET/LIST, etc.)
during the transition period.

## Security Notes

- Origin signatures prove the origin accepted the event; they do not prove
  current body availability
- Cancellation is not erasure
- Relays cannot introduce trust in unpinned origins
- Feed import subscriptions check origin and board, not relay hostname
- SSRF checks run before every federation dial
- Parser bounds are enforced before allocation (all decoders reject malformed input)
