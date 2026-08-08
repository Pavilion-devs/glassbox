"""Validate the exact public GlassBox source set before publication."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tomllib
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

CANONICAL_REPOSITORY = "https://github.com/Pavilion-devs/glassbox"
PREFLIGHT_CONTRACT = "glassbox.repository-preflight.v1"
MAX_PUBLIC_FILE_BYTES = 1_048_576

_GENERATED_PARTS = frozenset(
    {
        ".hypothesis",
        ".mypy_cache",
        ".pytest_cache",
        ".release-venv",
        ".ruff_cache",
        ".venv",
        ".wrangler",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "reproducibility-dist",
    }
)
_GENERATED_SUFFIXES = (".pyc", ".pyo", ".tsbuildinfo")
_FORBIDDEN_FILENAMES = frozenset({".DS_Store", ".env", "id_rsa", "id_ed25519"})
_SENTINEL_FIXTURE_PATHS = frozenset(
    {
        "scripts/upstream_packet.py",
        "tests/unit/test_capability_probe.py",
        "tests/unit/test_flagship_report.py",
        "tests/unit/test_repository_preflight.py",
        "tests/unit/test_upstream_packet.py",
    }
)
_PRIVATE_KEY_MARKERS = (
    b"-----BEGIN " + b"PRIVATE KEY-----",
    b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----",
)
_PERSONAL_PATH_MARKERS = (b"/" + b"Users/", b"/" + b"home/")
_CREDENTIAL_PATTERNS = (
    re.compile(rb"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(rb"AIza[0-9A-Za-z_-]{30,}"),
)


class RepositoryPreflightError(ValueError):
    """Raised when the prospective public source tree is unsafe or ambiguous."""


def inspect_repository(root: Path, *, require_clean: bool = False) -> dict[str, object]:
    """Return a deterministic raw-free inventory of the prospective public tree."""

    source_root = root.resolve(strict=True)
    if not (source_root / ".git").exists():
        raise RepositoryPreflightError("source root is not a Git repository")
    if require_clean and _git(source_root, "status", "--porcelain", "--untracked-files=all"):
        raise RepositoryPreflightError("repository is not clean")

    paths = _candidate_paths(source_root)
    if not paths:
        raise RepositoryPreflightError("repository contains no public source files")
    folded: set[str] = set()
    total_bytes = 0
    tree = hashlib.sha256()
    for relative in paths:
        _validate_path(relative, folded=folded)
        candidate = source_root / relative
        if candidate.is_symlink() or not candidate.is_file():
            raise RepositoryPreflightError(f"public path is not a regular file: {relative}")
        content = candidate.read_bytes()
        if len(content) > MAX_PUBLIC_FILE_BYTES:
            raise RepositoryPreflightError(f"public file exceeds size limit: {relative}")
        _validate_content(relative, content)
        if relative.endswith(".json"):
            _validate_json(relative, content)
        digest = hashlib.sha256(content).digest()
        encoded = relative.encode("utf-8")
        tree.update(len(encoded).to_bytes(4, "big"))
        tree.update(encoded)
        tree.update(digest)
        total_bytes += len(content)

    _validate_project_metadata(source_root)
    _validate_publication_documents(source_root)
    return {
        "contract": PREFLIGHT_CONTRACT,
        "valid": True,
        "canonical_repository": CANONICAL_REPOSITORY,
        "files": len(paths),
        "bytes": total_bytes,
        "source_tree_sha256": tree.hexdigest(),
        "clean_required": require_clean,
        "raw_content_returned": False,
    }


def _candidate_paths(root: Path) -> list[str]:
    raw = _git_bytes(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    try:
        paths = [item.decode("utf-8") for item in raw.split(b"\0") if item]
    except UnicodeDecodeError as exc:
        raise RepositoryPreflightError("public path is not valid UTF-8") from exc
    return sorted(set(paths))


def _validate_path(relative: str, *, folded: set[str]) -> None:
    path = PurePosixPath(relative)
    if path.is_absolute() or not path.parts or ".." in path.parts or "\\" in relative:
        raise RepositoryPreflightError(f"public path is unsafe: {relative}")
    if any(part in _GENERATED_PARTS for part in path.parts) or relative.endswith(
        _GENERATED_SUFFIXES
    ):
        raise RepositoryPreflightError(f"generated path is public: {relative}")
    if path.name in _FORBIDDEN_FILENAMES or path.suffix.lower() in {".key", ".pem", ".p12"}:
        raise RepositoryPreflightError(f"secret-bearing filename is public: {relative}")
    normalized = relative.casefold()
    if normalized in folded:
        raise RepositoryPreflightError(f"case-insensitive path collision: {relative}")
    folded.add(normalized)


def _validate_content(relative: str, content: bytes) -> None:
    if relative not in _SENTINEL_FIXTURE_PATHS:
        if any(marker in content for marker in _PRIVATE_KEY_MARKERS):
            raise RepositoryPreflightError(f"private-key material is public: {relative}")
        if any(marker in content for marker in _PERSONAL_PATH_MARKERS) or re.search(
            rb"[A-Za-z]:\\\\Users\\\\", content
        ):
            raise RepositoryPreflightError(f"personal machine path is public: {relative}")
    if any(pattern.search(content) for pattern in _CREDENTIAL_PATTERNS):
        raise RepositoryPreflightError(f"credential-like material is public: {relative}")


def _validate_json(relative: str, content: bytes) -> None:
    try:
        json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RepositoryPreflightError(f"public JSON is invalid: {relative}") from exc


def _validate_project_metadata(root: Path) -> None:
    document = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = document.get("project")
    if not isinstance(project, dict):
        raise RepositoryPreflightError("pyproject.toml has no project metadata")
    urls = project.get("urls")
    expected = {
        "Documentation": f"{CANONICAL_REPOSITORY}#readme",
        "Issues": f"{CANONICAL_REPOSITORY}/issues",
        "Source": CANONICAL_REPOSITORY,
    }
    if urls != expected:
        raise RepositoryPreflightError("pyproject.toml does not use canonical public URLs")


def _validate_publication_documents(root: Path) -> None:
    license_text = (root / "LICENSE").read_text(encoding="utf-8")
    if "Apache License" not in license_text or "Version 2.0" not in license_text:
        raise RepositoryPreflightError("LICENSE is not the Apache License 2.0 text")
    security = (root / "SECURITY.md").read_text(encoding="utf-8")
    if f"{CANONICAL_REPOSITORY}/security/advisories/new" not in security:
        raise RepositoryPreflightError("SECURITY.md has no canonical private advisory URL")
    ignore = (root / ".gitignore").read_text(encoding="utf-8").splitlines()
    if "*.tsbuildinfo" not in ignore:
        raise RepositoryPreflightError("generated TypeScript build state is not ignored")


def _git(root: Path, *args: str) -> str:
    return _git_bytes(root, *args).decode("utf-8").strip()


def _git_bytes(root: Path, *args: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
        )
    except subprocess.SubprocessError as exc:
        raise RepositoryPreflightError("Git could not inspect the repository") from exc
    return completed.stdout


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--require-clean", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = inspect_repository(args.root, require_clean=args.require_clean)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, RepositoryPreflightError):
        print(
            json.dumps(
                {
                    "contract": PREFLIGHT_CONTRACT,
                    "valid": False,
                    "reason_code": "REPOSITORY_PREFLIGHT_INVALID",
                    "raw_content_returned": False,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
