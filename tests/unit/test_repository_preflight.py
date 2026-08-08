"""Public repository preflight tests."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.repository_preflight import RepositoryPreflightError, inspect_repository


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "glassbox"
    root.mkdir()
    subprocess.run(["git", "-C", str(root), "init", "-b", "main"], check=True, capture_output=True)
    (root / ".gitignore").write_text("*.tsbuildinfo\n", encoding="utf-8")
    (root / "LICENSE").write_text("Apache License\nVersion 2.0\n", encoding="utf-8")
    (root / "README.md").write_text("# GlassBox\n", encoding="utf-8")
    (root / "SECURITY.md").write_text(
        "https://github.com/Pavilion-devs/glassbox/security/advisories/new\n",
        encoding="utf-8",
    )
    (root / "pyproject.toml").write_text(
        """
[project]
name = "glassbox-core"
version = "0.1.0"

[project.urls]
Documentation = "https://github.com/Pavilion-devs/glassbox#readme"
Issues = "https://github.com/Pavilion-devs/glassbox/issues"
Source = "https://github.com/Pavilion-devs/glassbox"
""".lstrip(),
        encoding="utf-8",
    )
    (root / "evidence.json").write_text('{"valid":true}\n', encoding="utf-8")
    return root


def test_repository_preflight_emits_deterministic_raw_free_inventory(tmp_path: Path) -> None:
    root = _repository(tmp_path)

    first = inspect_repository(root)
    second = inspect_repository(root)

    assert first == second
    assert first["valid"] is True
    assert first["files"] == 6
    assert first["raw_content_returned"] is False
    assert len(str(first["source_tree_sha256"])) == 64


@pytest.mark.parametrize(
    ("path", "content", "match"),
    [
        ("leak.txt", "/Users/alice/private\n", "personal machine path"),
        ("secret.txt", "-----BEGIN PRIVATE KEY-----\n", "private-key material"),
        ("state.tsbuildinfo", "{}\n", "generated path"),
        ("broken.json", "{\n", "public JSON is invalid"),
    ],
)
def test_repository_preflight_rejects_unsafe_public_files(
    path: str,
    content: str,
    match: str,
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path)
    if path.endswith(".tsbuildinfo"):
        (root / ".gitignore").write_text("", encoding="utf-8")
    (root / path).write_text(content, encoding="utf-8")

    with pytest.raises(RepositoryPreflightError, match=match):
        inspect_repository(root)


def test_repository_preflight_rejects_noncanonical_project_urls(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    pyproject = root / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8").replace("Pavilion-devs", "placeholder-owner"),
        encoding="utf-8",
    )

    with pytest.raises(RepositoryPreflightError, match="canonical public URLs"):
        inspect_repository(root)
