"""The `bonnet` entry point: dispatches to `server` and `gateway`.

Deliberately not a merged argparse tree. `bonnet.gateway.server.build_parser`
already owns a real subcommand tree of its own (`tenant add/list/...`, `key
add/list/...`), and both `bonnet.app.main.main` and `bonnet.gateway.server.run`
already accept `argv: list[str] | None` — this just slices `sys.argv` and
delegates, unchanged, to those two existing, already-tested parsers.

`argparse.REMAINDER` is deliberately avoided here — it has a known footgun
where a leading `-` in the remainder confuses the outer parser's own
tokenizer before it reaches the REMAINDER positional. A plain slice sidesteps
that and is easier to read besides.

`--version`/`-h` live here exclusively, not duplicated per subcommand.
"""

from __future__ import annotations

import sys

from bonnet import __version__

_USAGE = """\
usage: bonnet [--version] [-h] {server,gateway} ...

commands:
  server   run a Bonnet board server (see `bonnet server -h`)
  gateway  run the MCP gateway to a board server (see `bonnet gateway -h`)
"""


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv

    if argv and argv[0] in ("--version", "-V"):
        print(f"bonnet {__version__}")
        return 0

    if not argv:
        print(_USAGE, file=sys.stderr)
        return 2

    if argv[0] in ("-h", "--help"):
        print(_USAGE)
        return 0

    command, rest = argv[0], argv[1:]

    if command == "server":
        from bonnet.app.main import main as server_main

        return server_main(rest) or 0

    if command == "gateway":
        from bonnet.gateway.server import run as gateway_run

        return gateway_run(rest) or 0

    print(f"bonnet: unknown command {command!r} (expected 'server' or 'gateway')", file=sys.stderr)
    print(_USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
