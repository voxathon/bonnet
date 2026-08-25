"""Entry point for the Bonnet firehose server."""

import argparse
import asyncio
import signal
import sys
import tomllib

from bonnet import __version__
from bonnet.app.server import BonnetFirehoseServer
from bonnet.core.config import FirehoseConfig
from bonnet.core.logging import init_logging


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description="Bonnet firehose server")
    parser.add_argument("--version", action="version", version=f"bonnet-server {__version__}")
    parser.add_argument("--config", default="config.toml", help="Path to config file")
    parser.add_argument("--port", type=int, default=None, help="Override listen port")
    parser.add_argument("--host", default=None, help="Override bind host")
    parser.add_argument("--cert", default=None, help="TLS certificate path")
    parser.add_argument("--key", default=None, help="TLS key path")
    parser.add_argument(
        "--create-config", action="store_true", help="Write a sample config file and exit"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="With --create-config, overwrite an existing config file",
    )
    args = parser.parse_args(argv)

    if args.create_config:
        try:
            FirehoseConfig.create_default_config(args.config, force=args.force)
        except FileExistsError as exc:
            print(f"error: {exc}", file=sys.stderr)
            raise SystemExit(1)
        print(f"Wrote sample config to {args.config}")
        return

    init_logging()

    try:
        config = FirehoseConfig.load(args.config)
    except FileNotFoundError:
        print(f"error: config file not found: {args.config}", file=sys.stderr)
        print("run 'bonnet-server --create-config' to generate a sample", file=sys.stderr)
        raise SystemExit(1)
    except tomllib.TOMLDecodeError as exc:
        print(f"error: could not parse {args.config}: {exc}", file=sys.stderr)
        raise SystemExit(1)
    for key in config.unknown_keys:
        print(f"warning: unrecognized config key '{key}' (ignored)", file=sys.stderr)
    if args.host:
        config.host = args.host
    try:
        config.validate()
    except ValueError as exc:
        print(f"error: invalid configuration: {exc}", file=sys.stderr)
        raise SystemExit(1)
    server = BonnetFirehoseServer(config)

    def handle_sigterm(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, handle_sigterm)

    try:
        asyncio.run(server.run(port=args.port, ssl_certfile=args.cert, ssl_keyfile=args.key))
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.close()


if __name__ == "__main__":
    main()
