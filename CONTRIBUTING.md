# Contributing to GlassBox

Thank you for helping build trustworthy agent infrastructure.

## Before changing code

1. Read `AGENTS.md` and the relevant sections of `plan.md`.
2. Read applicable ADRs under `docs/adr/`.
3. Verify DataHub claims against the pinned Core version and primary documentation.
4. Keep changes focused on provenance, invalidation, replay safety, or a supporting primitive.

## Local checks

```bash
uv sync --all-extras
uv run python -m scripts.repository_preflight --root .
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
```

Integration tests must be explicitly selected and must never target a production
DataHub instance. A test that mutates DataHub must use the synthetic `glassbox.probe`
namespace and verify every write through a direct entity read.

PostgreSQL integration tests require a disposable PostgreSQL 14+ database. Set
`GLASSBOX_TEST_POSTGRES_DSN` to synthetic test credentials; every test creates and
drops only a randomized `gbx_test_*` schema. CI supplies PostgreSQL 16 automatically.

## Pull requests

- Explain the user problem and trust boundary.
- Include tests for success, failure, uncertainty, and idempotency where relevant.
- Update the schema and compatibility fixtures for contract changes.
- Add an ADR for significant persistence, security, event, or public-API decisions.
- Never hide an unverified integration behind a mock or screenshot.

By contributing, you agree that your contributions are licensed under Apache-2.0.
