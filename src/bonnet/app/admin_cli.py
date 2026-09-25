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

"""One-shot operator console for a Bonnet server (`bonnet admin`).

The interactive `bonnet>` REPL only exists when the server process itself
has a TTY on stdin (see `BonnetServer.run`) — under systemd / Docker /
`nohup ... &` there is none, so operators of background services have no
way to act as the server identity (root).

`bonnet admin` fills that gap: it opens the same config + data files the
server uses, signs with the same server identity key, dispatches a single
REPL command headlessly, prints the result, and exits. Run it as the same
OS user the service runs as (e.g. `sudo -u bonnet bonnet admin ...`);
the identity file (`data_dir/identity`, mode 0600) is the credential.

Stores use WAL + `busy_timeout=5000`, so a brief overlap with the live
server's writes retries instead of failing. Each invocation opens,
dispatches, and closes — no daemon, no socket, no extra auth surface.
"""

from __future__ import annotations

import argparse
import os
import sys

from bonnet.app.console import OperatorConsole
from bonnet.app.server import BonnetServer
from bonnet.core.config import FirehoseConfig
from bonnet.core.home import SERVER, home_conflict, resolve_home


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bonnet admin",
        description=(
            "Run one operator-console command against this server's data "
            "files (same commands as the interactive bonnet> REPL). "
            "Run as the service user so data_dir/identity is readable."
        ),
    )
    parser.add_argument(
        "--dir",
        default=None,
        help=(
            "This server's home directory, for this run only (wins over "
            "$BONNET_SERVER_HOME; not remembered). For a bridge origin, pass "
            "--config <its home>/bridge.toml."
        ),
    )
    parser.add_argument(
        "--config", default=None, help="Path to config file (default: <home>/config.toml)"
    )
    parser.add_argument(
        "--log-level",
        default=None,
        help="Log verbosity: DEBUG, INFO, WARNING or ERROR",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help=(
            "REPL command and args, e.g. `whoami`, `ban <key> 7d spam`, "
            "`publish-article general --subject=Hi --body-file=./body.txt`. "
            "Quoting follows your shell, not the REPL: prefer one argv item "
            "per flag (`--subject=Hello world` as a single quoted arg)."
        ),
    )
    return parser


def _resolve_config_path(args) -> str:
    if args.dir:
        args.dir = os.path.expanduser(args.dir)
        os.environ[SERVER.env_var] = args.dir
    server_home = resolve_home(SERVER.component, SERVER.env_var)
    if os.path.exists(server_home) and not os.path.isdir(server_home):
        print(
            f"error: server home '{server_home}' exists but is not a directory "
            "(check BONNET_SERVER_HOME / --dir)",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if args.config is None:
        config_path = os.path.join(server_home, SERVER.config_name)
        conflict = home_conflict(
            SERVER, config_path, server_home if os.environ.get(SERVER.env_var) else None
        )
        if conflict:
            print(f"error: {conflict}", file=sys.stderr)
            raise SystemExit(1)
        return config_path
    # An explicit --config names the server outright, a bridge's bridge.toml
    # included; core.config reads the matching home env var from its name.
    return args.config


def main(argv: list[str] | None = None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        print(
            "\nExamples:\n"
            "  bonnet admin whoami\n"
            "  bonnet admin list-boards\n"
            "  bonnet admin grant-role <pubkey-hex> moderator <name>\n"
            "  bonnet admin ban <pubkey-hex> 7d spam\n"
            "  bonnet admin create-board general --display-name=General\n"
            "  bonnet admin publish-article general --subject=Hello --body-file=./body.txt\n",
        )
        return 2
    # argparse.REMAINDER keeps a leading `--` separator when callers use
    # `bonnet admin -- <command>` to protect a leading dash; drop it.
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
        if not args.command:
            parser.print_help()
            return 2

    config_path = _resolve_config_path(args)

    try:
        config = FirehoseConfig.load(config_path)
    except FileNotFoundError:
        print(f"error: config file not found: {config_path}", file=sys.stderr)
        print("run 'bonnet server --init' to generate a config and get started", file=sys.stderr)
        raise SystemExit(1)
    except IsADirectoryError:
        print(f"error: config path is a directory, not a file: {config_path}", file=sys.stderr)
        raise SystemExit(1)
    except Exception as exc:
        print(f"error: could not parse {config_path}: {exc}", file=sys.stderr)
        raise SystemExit(1)

    for key in config.unknown_keys:
        print(f"warning: unrecognized config key '{key}' (ignored)", file=sys.stderr)

    try:
        config.validate()
    except ValueError as exc:
        print(f"error: invalid configuration: {exc}", file=sys.stderr)
        raise SystemExit(1)

    if args.log_level is not None and args.log_level.upper() not in FirehoseConfig.LOG_LEVELS:
        print(
            f"error: --log-level must be one of "
            f"{', '.join(FirehoseConfig.LOG_LEVELS)}, got {args.log_level!r}",
            file=sys.stderr,
        )
        raise SystemExit(1)

    identity_path = config.identity_path
    if not os.path.exists(identity_path):
        print(
            f"error: server identity not found at {identity_path} "
            "(is this the server's home? run `bonnet server` once first)",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if not os.access(identity_path, os.R_OK):
        print(
            f"error: cannot read server identity at {identity_path} "
            "(run as the service user, e.g. `sudo -u bonnet bonnet admin ...`)",
            file=sys.stderr,
        )
        raise SystemExit(1)

    server = BonnetServer(config, config_path=config_path)
    try:
        console = OperatorConsole(server, headless=True)
        try:
            result = console.dispatch_argv(args.command)
        except Exception as e:
            result = f"Error: {e}"
        if result is None:
            # quit/exit: nothing to do one-shot.
            return 0
        if result:
            print(result)
        if result.startswith("Error:") or result.startswith("Unknown command"):
            return 1
        return 0
    finally:
        server.close()


if __name__ == "__main__":
    raise SystemExit(main())
