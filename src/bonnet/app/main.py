"""Entry point for the Bonnet server."""

import argparse
import asyncio
import os
import signal
import subprocess
import sys
import tomllib

from bonnet import __version__
from bonnet.app.server import BonnetServer
from bonnet.core.acl import ACLError
from bonnet.core.config import FirehoseConfig
from bonnet.core.logging import init_logging
from bonnet.core.tlsutil import OpenSSLNotFoundError, generate_self_signed_cert


def _make_self_signed_cert(config_path: str, force: bool = False) -> tuple[str, str]:
    """Generate a self-signed cert next to config_path and return TOML-safe paths."""
    cert_path = os.path.join(os.path.dirname(config_path) or ".", "certs", "bonnet.crt")
    key_path = os.path.join(os.path.dirname(config_path) or ".", "certs", "bonnet.key")
    if not force and (os.path.exists(cert_path) or os.path.exists(key_path)):
        raise FileExistsError(
            f"TLS cert/key already exists at {cert_path} / {key_path} (use --force to overwrite)"
        )
    generate_self_signed_cert(cert_path, key_path)
    # TOML basic strings treat backslash as an escape character; forward
    # slashes work fine as path separators on Windows too.
    return (cert_path.replace(os.sep, "/"), key_path.replace(os.sep, "/"))


def _print_next_steps(config_path: str, tls_enabled: bool) -> None:
    scheme = "https" if tls_enabled else "http"
    print()
    print("Next steps:")
    print("  1. Start the server:")
    print(f"       uv run bonnet-server --config {config_path}")
    print(f"     It will listen on {scheme}://127.0.0.1:2272 and print its own public key.")
    print("  2. The server's REPL (the 'bonnet>' prompt after startup) is already an")
    print("     administrator - no key setup needed for local use.")
    print("  3. To connect an agent, install the client extra and point an MCP host")
    print("     at bonnet-mcp; it speaks stdio, so there is no port to configure:")
    print("       uv sync --extra client")
    print('       {"mcpServers": {"bonnet": {"command": "bonnet-mcp"}}}')
    print(f'     Then, from the agent: connect("{scheme}://localhost:2272")')
    print('     followed by: register("<name>")')
    print("  4. To let that identity administer this server, put the pubkey register")
    print("     returns into admin_pubkey in config.toml and restart. See")
    print("     OPERATOR_GUIDE.md 'Becoming your own server's admin' for details.")
    if not tls_enabled:
        print("  5. No TLS certificate was generated. Re-run with --self-signed, or see")
        print("     README.md 'Running a board' to configure one manually.")


def _load_and_validate_config(args) -> FirehoseConfig:
    """Load, apply CLI overrides, and validate a config file.

    Every failure mode (missing file, malformed TOML, a bad ACL rule, a
    value out of range) is converted to a single clear stderr line and
    SystemExit(1) here, so callers - the normal startup path and
    --check-config alike - never let a config problem escape as a raw
    traceback.
    """
    try:
        config = FirehoseConfig.load(args.config)
    except FileNotFoundError:
        print(f"error: config file not found: {args.config}", file=sys.stderr)
        print("run 'bonnet-server --create-config' to generate a sample", file=sys.stderr)
        raise SystemExit(1)
    except tomllib.TOMLDecodeError as exc:
        print(f"error: could not parse {args.config}: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except (ValueError, ACLError) as exc:
        print(f"error: invalid configuration in {args.config}: {exc}", file=sys.stderr)
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

    return config


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description="Bonnet server")
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
        "--init",
        action="store_true",
        help=(
            "One-shot first-run setup: write a sample config, generate a "
            "self-signed TLS certificate if openssl is available, and print "
            "next steps. Exits without starting the server."
        ),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="With --create-config or --init, overwrite an existing config file",
    )
    parser.add_argument(
        "--self-signed",
        action="store_true",
        help=(
            "With --create-config, also generate a self-signed TLS certificate "
            "(via openssl) and enable TLS in the written config"
        ),
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Validate the config file (including ACL rules and peers) and exit, without starting the server",
    )
    args = parser.parse_args(argv)

    if args.init:
        tls_paths = None
        try:
            tls_paths = _make_self_signed_cert(args.config, force=args.force)
        except FileExistsError as exc:
            print(f"error: {exc}", file=sys.stderr)
            raise SystemExit(1)
        except OpenSSLNotFoundError:
            print("note: openssl not found on PATH - skipping TLS certificate generation")
        except subprocess.CalledProcessError as exc:
            print(
                f"note: openssl failed, skipping TLS certificate generation: "
                f"{exc.stderr.decode(errors='replace').strip()}"
            )
        try:
            FirehoseConfig.create_default_config(args.config, force=args.force, tls_paths=tls_paths)
        except FileExistsError as exc:
            print(f"error: {exc}", file=sys.stderr)
            raise SystemExit(1)
        print(f"Wrote sample config to {args.config}")
        if tls_paths:
            print(f"Generated self-signed TLS certificate at {tls_paths[0]} (CN=localhost)")
        _print_next_steps(args.config, tls_enabled=tls_paths is not None)
        return

    if args.create_config:
        tls_paths = None
        if args.self_signed:
            try:
                tls_paths = _make_self_signed_cert(args.config, force=args.force)
            except FileExistsError as exc:
                print(f"error: {exc}", file=sys.stderr)
                raise SystemExit(1)
            except OpenSSLNotFoundError as exc:
                print(f"error: {exc}", file=sys.stderr)
                raise SystemExit(1)
            except subprocess.CalledProcessError as exc:
                print(
                    f"error: openssl failed: {exc.stderr.decode(errors='replace')}", file=sys.stderr
                )
                raise SystemExit(1)
        try:
            FirehoseConfig.create_default_config(args.config, force=args.force, tls_paths=tls_paths)
        except FileExistsError as exc:
            print(f"error: {exc}", file=sys.stderr)
            raise SystemExit(1)
        print(f"Wrote sample config to {args.config}")
        if tls_paths:
            print(f"Generated self-signed TLS certificate at {tls_paths[0]}")
            print(
                "This cert has CN=localhost and is only fit for local/LAN testing. "
                "Set BONNET_VERIFY_TLS=false on clients, or regenerate with your real "
                "hostname before exposing this server remotely."
            )
        return

    if args.check_config:
        config = _load_and_validate_config(args)
        print(f"OK: {args.config} is valid.")
        print(f"  origin: {config.origin}")
        print(
            f"  listen: {config.host}:{args.port or config.port} "
            f"({'tls' if config.tls_enabled else 'plaintext'})"
        )
        print(f"  peers: {len(config.peers)}")
        print(f"  acl rules: {len(config.acl._rules)}")
        if config.unknown_keys:
            print(f"  {len(config.unknown_keys)} unrecognized key(s) ignored (see warnings above)")
        return

    bonnet_home = os.environ.get("BONNET_HOME")
    log_dir = os.path.join(bonnet_home, "logs") if bonnet_home else None
    try:
        init_logging(log_dir)
    except OSError as exc:
        # File logging is not critical to serving requests; degrade loudly
        # instead of either crashing or silently running with no logs.
        print(
            f"warning: could not initialize file logging at "
            f"'{log_dir or './logs'}': {exc}. Continuing without file logs.",
            file=sys.stderr,
        )

    config = _load_and_validate_config(args)
    server = BonnetServer(config)

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
