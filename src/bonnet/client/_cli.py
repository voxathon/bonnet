"""Entry point shim for bonnet-mcp with a friendly missing-extra error."""

import sys


def run():
    try:
        from bonnet.client.server import run as server_run
    except ImportError as exc:
        print(f"error: bonnet-mcp requires optional dependencies: {exc}", file=sys.stderr)
        print("install them with: pip install 'bonnet[client]'", file=sys.stderr)
        raise SystemExit(1)
    server_run()
