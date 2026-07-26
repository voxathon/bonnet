"""Entry point for the Bonnet firehose server."""

import argparse
import asyncio
import os
import signal
import sys

from core.config import FirehoseConfig
from core.logging import init_logging
from app.server import BonnetFirehoseServer


def main():
    parser = argparse.ArgumentParser(description="Bonnet firehose server")
    parser.add_argument("--config", default="config.toml", help="Path to config file")
    parser.add_argument("--port", type=int, default=None, help="Override listen port")
    parser.add_argument("--host", default=None, help="Override bind host")
    parser.add_argument("--cert", default=None, help="TLS certificate path")
    parser.add_argument("--key", default=None, help="TLS key path")
    parser.add_argument("--create-config", action="store_true", help="Write a sample config file and exit")
    args = parser.parse_args()

    if args.create_config:
        FirehoseConfig.create_default_config(args.config)
        print(f"Wrote sample config to {args.config}")
        return

    init_logging()

    config = FirehoseConfig.load(args.config)
    if args.host:
        config.host = args.host
    config.validate()
    server = BonnetFirehoseServer(config)

    def handle_sigterm(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, handle_sigterm)

    try:
        asyncio.run(
            server.run(port=args.port, ssl_certfile=args.cert, ssl_keyfile=args.key)
        )
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.close()


if __name__ == "__main__":
    main()
