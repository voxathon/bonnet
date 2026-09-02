"""Entry point for the Bonnet server."""

import argparse
import asyncio
import os
import signal
import socket
import subprocess
import sys
import tomllib

from bonnet.app.server import BonnetServer
from bonnet.core.acl import ACLError
from bonnet.core.config import FirehoseConfig
from bonnet.core.home import resolve_home, set_home
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
    print(f"       uv run bonnet server --config {config_path}")
    print(f"     It will listen on {scheme}://127.0.0.1:2272 and print its own public key.")
    print("  2. The server's REPL (the 'bonnet>' prompt after startup) is already an")
    print("     administrator - no key setup needed for local use.")
    print("  3. To connect an agent, point an MCP host at `bonnet gateway`;")
    print("     it speaks stdio, so there is no port to configure:")
    print('       {"mcpServers": {"bonnet": {"command": "bonnet", "args": ["gateway"]}}}')
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
        print("run 'bonnet server --create-config' to generate a sample", file=sys.stderr)
        raise SystemExit(1)
    except IsADirectoryError:
        print(f"error: config path is a directory, not a file: {args.config}", file=sys.stderr)
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
    if args.port is not None:
        config.port = args.port

    try:
        config.validate()
    except ValueError as exc:
        print(f"error: invalid configuration: {exc}", file=sys.stderr)
        raise SystemExit(1)

    for warning in _acl_rule_warnings(config):
        print(f"warning: {warning}", file=sys.stderr)

    return config


def _preflight_bind(host: str, port: int) -> None:
    """Fail fast on an unbindable host:port before BonnetServer's __init__
    does its side-effectful init pass - opening/creating the SQLite stores,
    generating a server keypair if none exists yet, etc.

    A second `bonnet server` pointed at a home dir/port a live process
    already owns used to run that whole init pass first and only discover
    the collision when uvicorn itself tried to bind, doing real filesystem
    work against files the live process owns for nothing. This is a
    best-effort check - there's an inherent bind-time race between this and
    the real bind in BonnetServer.run() - but it catches the common case
    (wrong host, or a port already in use) before any state is touched.
    """
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise OSError(f"cannot resolve {host!r}: {exc}") from exc
    family, socktype, proto, _, sockaddr = infos[0]
    sock = socket.socket(family, socktype, proto)
    try:
        sock.bind(sockaddr)
    finally:
        sock.close()


def _acl_rule_warnings(config: FirehoseConfig) -> list[str]:
    """Flag ACL rule commands/kinds that can never match anything.

    A rule's `commands`/`kinds` are free-form strings (acl.py has no
    reference back to the real command/kind name sets - see ACLRule.from_dict),
    so a typo silently produces a rule that never fires: on an allow it grants
    nothing, on a deny it blocks nothing, and --check-config previously
    reported the config fully valid either way. This is advisory, not fatal -
    a newer command/kind name this build doesn't know about yet is not
    actually wrong - so it warns rather than failing validation.
    """
    from bonnet.core.kinds import ALL_KNOWN_KINDS
    from bonnet.net.firehose_commands import CMD_NAMES

    known_commands = set(CMD_NAMES.values()) | {"*"}
    known_kinds = set(ALL_KNOWN_KINDS) | {"*"}

    warnings = []
    for i, rule in enumerate(config.acl._rules):
        for command in rule.commands or []:
            if command not in known_commands:
                warnings.append(
                    f"acl rule [{i}] references unknown command '{command}' "
                    "(this rule can never match anything)"
                )
        for kind in rule.kinds or []:
            if kind not in known_kinds:
                warnings.append(
                    f"acl rule [{i}] references unknown kind '{kind}' "
                    "(this rule can never match anything)"
                )
    return warnings


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(prog="bonnet server", description="Bonnet server")
    parser.add_argument(
        "--dir",
        default=None,
        help=(
            "This server's home directory (config.toml, and data/boards/event_bodies "
            "defaults). Remembered for future runs — see BONNET_SERVER_HOME below."
        ),
    )
    parser.add_argument(
        "--config", default=None, help="Path to config file (default: <home>/config.toml)"
    )
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

    if args.dir:
        args.dir = os.path.expanduser(args.dir)
    server_home = args.dir or resolve_home("server", "BONNET_SERVER_HOME")
    if os.path.exists(server_home) and not os.path.isdir(server_home):
        print(
            f"error: server home '{server_home}' exists but is not a directory "
            "(check BONNET_SERVER_HOME / --dir)",
            file=sys.stderr,
        )
        raise SystemExit(1)
    # Only remember --dir for future runs that omit it entirely. A process
    # with BONNET_SERVER_HOME set always resolves via that override anyway
    # (see resolve_home) - writing to the pointer file here would only
    # leak this run's --dir into other processes on the same machine that
    # rely on their *own* BONNET_SERVER_HOME for isolation, since the
    # pointer file isn't scoped by that env var.
    if args.dir and not os.environ.get("BONNET_SERVER_HOME"):
        set_home("server", args.dir)
    if args.config is None:
        args.config = os.path.join(server_home, "config.toml")

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
        except NotADirectoryError:
            print(
                f"error: cannot create {args.config} - a path component "
                "already exists as a file, not a directory (check BONNET_SERVER_HOME / --dir)",
                file=sys.stderr,
            )
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
        except NotADirectoryError:
            print(
                f"error: cannot create {args.config} - a path component "
                "already exists as a file, not a directory (check BONNET_SERVER_HOME / --dir)",
                file=sys.stderr,
            )
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
            f"  listen: {config.host}:{config.port} "
            f"({'tls' if config.tls_enabled else 'plaintext'})"
        )
        print(f"  peers: {len(config.peers)}")
        print(f"  acl rules: {len(config.acl._rules)}")
        if config.unknown_keys:
            print(f"  {len(config.unknown_keys)} unrecognized key(s) ignored (see warnings above)")
        return

    log_dir = os.path.join(server_home, "logs")
    try:
        init_logging(log_dir)
    except OSError as exc:
        # File logging is not critical to serving requests; degrade loudly
        # instead of either crashing or silently running with no logs.
        print(
            f"warning: could not initialize file logging at "
            f"'{log_dir}': {exc}. Continuing without file logs.",
            file=sys.stderr,
        )

    config = _load_and_validate_config(args)

    try:
        _preflight_bind(config.host, config.port)
    except OSError as exc:
        print(f"error: could not listen on {config.host}:{config.port}: {exc}", file=sys.stderr)
        raise SystemExit(1)

    server = BonnetServer(config)

    def handle_sigterm(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, handle_sigterm)

    started = False
    try:
        started = asyncio.run(
            server.run(port=args.port, ssl_certfile=args.cert, ssl_keyfile=args.key)
        )
    except KeyboardInterrupt:
        print("\nShutting down...")
        started = True
    finally:
        server.close()
    if not started:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
