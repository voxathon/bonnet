# Copyright 2026 The Bonnet Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""`bonnet bridge`: inspect and repair a server's bridge state.

  rebuild-index  rebuild the bridge index from the origin's log
  status         bindings, cursors, mirror and pending counts

Bridges run inside `bonnet server`, from the `[bridges]` table of its
`config.toml`; these commands inspect or repair a server's bridge state. Run
them against the same home (`--dir`, $BONNET_SERVER_HOME) or `--config`.
Bindings come from `[[bridges.venue]]`: the server reconciles them at
startup, binding new or changed boards and unbinding removed ones.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

_USAGE = """\
usage: bonnet bridge {rebuild-index,status} ...

commands:
  rebuild-index  rebuild the bridge index from the log (stop the server first)
  status         show bindings, cursors, and mirror/pending counts
"""


def _load_config(argv: list[str], prog: str):
    from bonnet.app.main import _load_and_validate_config
    from bonnet.core.home import SERVER, resolve_home

    parser = argparse.ArgumentParser(prog=prog)
    parser.add_argument("--dir", default=None, help="Server home directory, for this run only")
    parser.add_argument("--config", default=None, help="Path to config file (config.toml)")
    parser.add_argument("--json", action="store_true", help="Machine-readable output")
    args = parser.parse_args(argv)
    if args.dir:
        os.environ[SERVER.env_var] = os.path.expanduser(args.dir)
    home = resolve_home(SERVER.component, SERVER.env_var)
    if args.config is None:
        args.config = os.path.join(home, SERVER.config_name)
    args.host = None
    args.port = None
    config = _load_and_validate_config(args)
    if config.bridge_runtime is None:
        print(f"error: {args.config} bridges no venues ([[bridges.venue]])", file=sys.stderr)
        raise SystemExit(1)
    return config, args


def _rebuild(argv: list[str]) -> int:
    from bonnet.bridges.adapter import build_adapter, missing_adapters
    from bonnet.bridges.index import RuntimeIndex
    from bonnet.core.firehose import FirehoseStore

    config, args = _load_config(argv, "bonnet bridge rebuild-index")
    rt = config.bridge_runtime
    errors = missing_adapters(rt.venues)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    firehose = FirehoseStore(config.events_db_path)
    index = RuntimeIndex(config.bridges_state_dir)
    adapters = [build_adapter(v) for v in rt.venues]
    try:
        cursor_fns = {
            b.board: a.cursor_from_ids for v, a in zip(rt.venues, adapters) for b in v.bindings
        }
        count = index.rebuild(firehose, config.origin, set(cursor_fns), cursor_fns)
    finally:
        asyncio.run(_close_all(adapters))
        index.close()
        firehose.close()
    print(f"rebuilt index from {count} mirror record(s)")
    return 0


async def _close_all(adapters) -> None:
    for a in adapters:
        await a.close()


def _status(argv: list[str]) -> int:
    from bonnet.bridges.index import RuntimeIndex

    config, args = _load_config(argv, "bonnet bridge status")
    rt = config.bridge_runtime
    index = RuntimeIndex(config.bridges_state_dir)
    try:
        rows = [
            {
                "venue": v.venue,
                "channel": b.channel,
                "board": b.board,
                "ingest": b.ingest,
                "cursor": index.cursor(b.board),
                "mirrors": index.mirror_count(b.board),
                "pending": len(index.pending(b.board)),
            }
            for v in rt.venues
            for b in v.bindings
        ]
    finally:
        index.close()
    if args.json:
        print(json.dumps({"origin": config.origin, "bindings": rows}, indent=2))
        return 0
    print(f"origin: {config.origin}")
    for r in rows:
        print(
            f"  {r['board']:<24} {r['venue']}#{r['channel']}  "
            f"ingest={'on' if r['ingest'] else 'off'}  cursor={r['cursor'] or '-'}  "
            f"mirrors={r['mirrors']}  pending={r['pending']}"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help"):
        print(_USAGE, file=sys.stderr if not argv else sys.stdout)
        return 2 if not argv else 0
    command, rest = argv[0], argv[1:]
    if command == "rebuild-index":
        return _rebuild(rest)
    if command == "status":
        return _status(rest)
    print(f"bonnet bridge: unknown command {command!r}", file=sys.stderr)
    print(_USAGE, file=sys.stderr)
    return 2
