"""Why the gateway's shared SQLite connections are safe, as an executable claim.

`gateway/origins.py` and `gateway/registry.py` each hold ONE sqlite3
connection, opened `check_same_thread=False`, with sqlite3's default
implicit transactions and no lock. `core/` does the opposite — explicit
`BEGIN IMMEDIATE` under a lock — because `net/firehose_http_server.py`
hands work to `asyncio.to_thread` and really does run concurrently.

The gateway stores are safe without any of that, but not by accident and
not robustly: they are safe because nothing in the gateway ever suspends or
switches threads between two statements of the same implicit transaction.
That rests on three properties, none of which the code enforces:

  1. every MCP entry point is `async def`, so it runs on the event loop
     thread — a sync `def` tool would be handed to a worker thread by
     anyio, and two of those on one connection could interleave inside a
     single implicit transaction;
  2. no store method is `async` or awaits between statements;
  3. no gateway code offloads a store call to a thread.

`check_same_thread=False` disables the one runtime check that would catch a
violation of (1) or (3), so a regression would corrupt quietly rather than
raise. These tests are the replacement for that check.
"""

import ast
import inspect
import pathlib

import pytest

GATEWAY = pathlib.Path("src/bonnet/gateway")
STORE_MODULES = ["origins.py", "registry.py"]


def _tree(path):
    return ast.parse(path.read_text(encoding="utf-8"))


def _decorated_with(node, needle):
    return any(needle in ast.unparse(d) for d in node.decorator_list)


def test_every_mcp_entry_point_is_async():
    """A sync def would be run in a worker thread by anyio.

    Two such calls sharing one connection could interleave statements inside
    a single implicit transaction: one's commit would publish the other's
    half-written work, or its rollback would discard it.
    """
    offenders = []
    for name, needle in (
        ("tools.py", "mcp.tool"),
        ("resources.py", "mcp.resource"),
        ("server.py", "custom_route"),
    ):
        for node in ast.walk(_tree(GATEWAY / name)):
            if isinstance(node, ast.FunctionDef) and _decorated_with(node, needle):
                offenders.append(f"{name}:{node.lineno} {node.name}")
    assert not offenders, (
        "sync MCP entry points run in a worker thread; the gateway stores "
        f"are not safe for that: {offenders}"
    )


@pytest.mark.parametrize("module", STORE_MODULES)
def test_no_store_method_is_async(module):
    """An await between two statements is a suspension point mid-transaction."""
    offenders = [
        f"{module}:{node.lineno} {node.name}"
        for node in ast.walk(_tree(GATEWAY / module))
        if isinstance(node, ast.AsyncFunctionDef)
    ]
    assert not offenders, offenders


def test_the_gateway_never_offloads_to_a_thread():
    """No to_thread / run_in_executor / Thread anywhere under gateway/."""
    offenders = []
    for path in GATEWAY.rglob("*.py"):
        for node in ast.walk(_tree(path)):
            if not isinstance(node, ast.Call):
                continue
            call = ast.unparse(node.func)
            if call.endswith(("to_thread", "run_in_executor")) or call.endswith("Thread"):
                offenders.append(f"{path.name}:{node.lineno} {call}")
    assert not offenders, (
        "the gateway stores share one connection with no lock; moving a "
        f"store call off the loop thread breaks that: {offenders}"
    )


@pytest.mark.parametrize("module", STORE_MODULES)
def test_store_writes_commit_before_returning(module):
    """No implicit transaction may outlive the method that opened it.

    Every method that executes a write statement must also commit. A write
    left uncommitted would still be open when the next tool call ran on the
    same connection, which is the interleave this module rules out.
    """
    tree = _tree(GATEWAY / module)
    writes = ("INSERT", "UPDATE", "DELETE", "REPLACE")
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name.startswith("_init"):
            continue
        body = ast.unparse(node)
        if any(w in body.upper() for w in writes) and "commit()" not in body:
            offenders.append(f"{module}:{node.lineno} {node.name}")
    assert not offenders, offenders
