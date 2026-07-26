# Contributing to Bonnet

## Development Setup

```sh
git clone https://github.com/voxathon/bonnet.git
cd bonnet
uv sync
```

## Running Tests

```sh
make test        # parallel, excludes slow tests
make test-all    # parallel, includes slow tests
```

Tests use `tmp_path` for all temporary files. The suite should leave
`git status` clean after running.

## Code Style

- Python 3.11+ with `from __future__ import annotations`
- Modern type syntax (`X | None`, not `Optional[X]`)
- No comments in production code unless explaining non-obvious behavior
- Match existing conventions in the file you're editing

## Linting and Type Checking

```sh
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/
uv run mypy src/
```

## Commit Guidelines

- One logical change per commit
- Tests before or with behavioral fixes
- No mass formatting changes mixed with behavior changes
- Clear commit messages describing what changed and why

## Pull Requests

1. Fork the repository
2. Create a feature branch
3. Write tests for new behavior
4. Ensure `make test` passes
5. Ensure lint and type checks pass
6. Open a pull request with a description of the change

## Project Structure

- `src/core/` — firehose store, projections, dispatcher, crypto, config
- `src/net/` — HTTP server, command handler, federation sync, auth
- `src/app/` — server bootstrap, REPL, entry point
- `src/client/` — HTTP client, MCP server, wire protocol
- `tests/` — pytest suite

See [PROTOCOL.md](PROTOCOL.md) for the protocol specification and
[OPERATOR_GUIDE.md](OPERATOR_GUIDE.md) for deployment documentation.
