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

"""`bonnet bridge`: run a bridge origin and inspect its runtime state.

  run            the server plus the bridge runtime (takes `bonnet server`'s flags)
  rebuild-index  rebuild the runtime index from the origin's log
  status         bindings, cursors, mirror and pending counts

A bridge origin has its own home ($BONNET_BRIDGE_HOME, or `--dir` for one
run) and its server config is `bridge.toml`, never a homeserver's
`config.toml`. Bridges are configured in `bridges.toml` next to it. Bindings
come from its `[runtime]`: `run` reconciles them at startup, binding new or
changed boards and unbinding boards removed from config.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

_USAGE = """\
usage: bonnet bridge {run,rebuild-index,status} ...

commands:
  run            run the bridge origin (server + runtime); same flags as `bonnet server`
  rebuild-index  rebuild the runtime index from the log (stop the bridge first)
  status         show bindings, cursors, and mirror/pending counts
"""


def _load_config(argv: list[str], prog: str):
    from bonnet.app.main import _load_and_validate_config
    from bonnet.core.home import BRIDGE, home_conflict, resolve_home

    parser = argparse.ArgumentParser(prog=prog)
    parser.add_argument("--dir", default=None, help="Bridge home directory, for this run only")
    parser.add_argument("--config", default=None, help="Path to config file (bridge.toml)")
    parser.add_argument("--json", action="store_true", help="Machine-readable output")
    args = parser.parse_args(argv)
    if args.dir:
        os.environ[BRIDGE.env_var] = os.path.expanduser(args.dir)
    home = resolve_home(BRIDGE.component, BRIDGE.env_var)
    if args.config is None:
        args.config = os.path.join(home, BRIDGE.config_name)
    conflict = home_conflict(BRIDGE, args.config, home if os.environ.get(BRIDGE.env_var) else None)
    if conflict:
        print(f"error: {conflict}", file=sys.stderr)
        raise SystemExit(1)
    args.host = None
    args.port = None
    config = _load_and_validate_config(args)
    if config.bridge_runtime is None:
        from bonnet.bridges.config import bridges_path

        print(f"error: {bridges_path(args.config)} has no [runtime] table", file=sys.stderr)
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
    index = RuntimeIndex(rt.state_dir)
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
    index = RuntimeIndex(rt.state_dir)
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
    print(f"bridge origin: {config.origin}")
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
    if command == "run":
        from bonnet.app.main import main as server_main

        return server_main(rest, bridge=True) or 0
    if command == "rebuild-index":
        return _rebuild(rest)
    if command == "status":
        return _status(rest)
    print(f"bonnet bridge: unknown command {command!r}", file=sys.stderr)
    print(_USAGE, file=sys.stderr)
    return 2
