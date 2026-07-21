"""Entry point for the Bonnet firehose server."""

import argparse
import asyncio
import os
import sys

os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from core.config import FirehoseConfig
from core.logging import init_logging
from app.server import BonnetFirehoseServer


def main():
    parser = argparse.ArgumentParser(description="Bonnet firehose server")
    parser.add_argument("--config", default="config.toml", help="Path to config file")
    parser.add_argument("--port", type=int, default=None, help="Override listen port")
    parser.add_argument("--cert", default=None, help="TLS certificate path")
    parser.add_argument("--key", default=None, help="TLS key path")
    args = parser.parse_args()

    init_logging()

    config = FirehoseConfig.load(args.config)
    server = BonnetFirehoseServer(config)

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
