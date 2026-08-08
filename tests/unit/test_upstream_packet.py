"""Deterministic maintainer-packet tests."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import scripts.upstream_packet as packet_module
from scripts.upstream_packet import (
    PACKET_CONTRACT,
    UpstreamPacketError,
    _parse_status,
    _validate_change_path,
    build_packet,
    main,
    write_packet,
)


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _source_root(tmp_path: Path) -> Path:
    root = tmp_path / "glassbox"
    (root / "release-evidence").mkdir(parents=True)
    (root / "release-evidence" / "release-report.json").write_text(
        json.dumps(
            {
                "valid": True,
                "reproducible_build": True,
                "project": "glassbox-core",
                "version": "0.1.0",
                "artifacts": [{"filename": "glassbox.whl", "sha256": "a" * 64, "size": 7}],
            }
        ),
        encoding="utf-8",
    )
    (root / "proof.json").write_text(
        json.dumps(
            {
                "contract": "proof.v1",
                "valid": True,
                "raw_content_returned": False,
            }
        ),
        encoding="utf-8",
    )
    (root / "packet.md").write_text("# Maintainer packet\n", encoding="utf-8")
    return root


def _worktree(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "upstream"
    root.mkdir()
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.email", "glassbox-tests@example.invalid")
    _git(root, "config", "user.name", "GlassBox Tests")
    (root / "README.md").write_text("baseline\n", encoding="utf-8")
    _git(root, "add", "README.md")
    _git(root, "commit", "-m", "baseline")
    baseline = _git(root, "rev-parse", "HEAD")
    _git(root, "branch", "-m", "feature")
    (root / "README.md").write_text("changed\n", encoding="utf-8")
    (root / "skill").mkdir()
    (root / "skill" / "new.md").write_text("new\n", encoding="utf-8")
    return root, baseline


def _build(tmp_path: Path) -> tuple[dict[str, object], bytes, Path, Path, str]:
    worktree, baseline = _worktree(tmp_path)
    source = _source_root(tmp_path)
    manifest, patch = build_packet(
        worktree=worktree,
        glassbox_root=source,
        expected_baseline=baseline,
        expected_branch="feature",
        allowed_exact=frozenset({"README.md", "skill/new.md"}),
        allowed_prefixes=(),
        required_paths=frozenset({"README.md", "skill/new.md"}),
        proof_paths=("proof.json",),
        packet_documents=("packet.md",),
    )
    return manifest, patch, worktree, source, baseline


def test_packet_binds_modified_and_added_files_to_release_and_proofs(tmp_path: Path) -> None:
    manifest, patch, worktree, source, baseline = _build(tmp_path)
    second_manifest, second_patch = build_packet(
        worktree=worktree,
        glassbox_root=source,
        expected_baseline=baseline,
        expected_branch="feature",
        allowed_exact=frozenset({"README.md", "skill/new.md"}),
        allowed_prefixes=(),
        required_paths=frozenset({"README.md", "skill/new.md"}),
        proof_paths=("proof.json",),
        packet_documents=("packet.md",),
    )

    assert manifest == second_manifest
    assert patch == second_patch
    assert manifest["contract"] == PACKET_CONTRACT
    assert manifest["valid"] is True
    assert manifest["change_count"] == 2
    assert [item["change"] for item in manifest["changes"]] == ["MODIFIED", "ADDED"]
    assert manifest["implementation_proofs"][0]["contract"] == "proof.v1"
    assert b"diff --git a/README.md b/README.md" in patch
    assert b"diff --git a/skill/new.md b/skill/new.md" in patch

    output = tmp_path / "packet-output"
    write_packet(output, manifest, patch)
    written = json.loads((output / "upstream-packet.json").read_text(encoding="utf-8"))
    assert written == manifest
    assert (output / manifest["patch"]["filename"]).read_bytes() == patch


@pytest.mark.parametrize(
    ("baseline", "branch", "match"),
    [
        ("0" * 40, "feature", "baseline"),
        (None, "wrong", "branch"),
    ],
)
def test_packet_rejects_wrong_git_identity(
    baseline: str | None,
    branch: str,
    match: str,
    tmp_path: Path,
) -> None:
    worktree, actual = _worktree(tmp_path)
    source = _source_root(tmp_path)

    with pytest.raises(UpstreamPacketError, match=match):
        build_packet(
            worktree=worktree,
            glassbox_root=source,
            expected_baseline=actual if baseline is None else baseline,
            expected_branch=branch,
            allowed_exact=frozenset({"README.md", "skill/new.md"}),
            allowed_prefixes=(),
            required_paths=frozenset({"README.md", "skill/new.md"}),
            proof_paths=("proof.json",),
            packet_documents=("packet.md",),
        )


def test_packet_rejects_unexpected_or_secret_files(tmp_path: Path) -> None:
    worktree, baseline = _worktree(tmp_path)
    source = _source_root(tmp_path)
    (worktree / "unexpected.txt").write_text("not in scope\n", encoding="utf-8")

    with pytest.raises(UpstreamPacketError, match="unexpected path"):
        build_packet(
            worktree=worktree,
            glassbox_root=source,
            expected_baseline=baseline,
            expected_branch="feature",
            allowed_exact=frozenset({"README.md", "skill/new.md"}),
            allowed_prefixes=(),
            required_paths=frozenset({"README.md", "skill/new.md"}),
            proof_paths=("proof.json",),
            packet_documents=("packet.md",),
        )

    (worktree / "unexpected.txt").unlink()
    (worktree / "skill" / "new.md").write_text(
        "-----BEGIN PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    with pytest.raises(UpstreamPacketError, match="secret material"):
        build_packet(
            worktree=worktree,
            glassbox_root=source,
            expected_baseline=baseline,
            expected_branch="feature",
            allowed_exact=frozenset({"README.md", "skill/new.md"}),
            allowed_prefixes=(),
            required_paths=frozenset({"README.md", "skill/new.md"}),
            proof_paths=("proof.json",),
            packet_documents=("packet.md",),
        )


def test_packet_rejects_whitespace_missing_paths_non_files_and_large_files(tmp_path: Path) -> None:
    worktree, baseline = _worktree(tmp_path)
    source = _source_root(tmp_path)
    common = {
        "worktree": worktree,
        "glassbox_root": source,
        "expected_baseline": baseline,
        "expected_branch": "feature",
        "allowed_exact": frozenset({"README.md", "skill/new.md"}),
        "allowed_prefixes": (),
        "proof_paths": ("proof.json",),
        "packet_documents": ("packet.md",),
    }

    (worktree / "README.md").write_text("trailing space \n", encoding="utf-8")
    with pytest.raises(UpstreamPacketError, match="whitespace"):
        build_packet(**common, required_paths=frozenset({"README.md", "skill/new.md"}))

    (worktree / "README.md").write_text("changed\n", encoding="utf-8")
    with pytest.raises(UpstreamPacketError, match="missing required"):
        build_packet(**common, required_paths=frozenset({"README.md", "missing.md"}))

    (worktree / "skill" / "new.md").unlink()
    (worktree / "skill" / "new.md").symlink_to(worktree / "README.md")
    with pytest.raises(UpstreamPacketError, match="regular file"):
        build_packet(**common, required_paths=frozenset({"README.md", "skill/new.md"}))

    (worktree / "skill" / "new.md").unlink()
    (worktree / "skill" / "new.md").write_bytes(b"x" * 1_048_577)
    with pytest.raises(UpstreamPacketError, match="size limit"):
        build_packet(**common, required_paths=frozenset({"README.md", "skill/new.md"}))


def test_packet_rejects_missing_changes_patch_and_release_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worktree, baseline = _worktree(tmp_path)
    source = _source_root(tmp_path)
    common = {
        "worktree": worktree,
        "glassbox_root": source,
        "expected_baseline": baseline,
        "expected_branch": "feature",
        "allowed_exact": frozenset({"README.md", "skill/new.md"}),
        "allowed_prefixes": (),
        "required_paths": frozenset({"README.md", "skill/new.md"}),
        "proof_paths": ("proof.json",),
        "packet_documents": ("packet.md",),
    }

    monkeypatch.setattr(packet_module, "_build_patch", lambda *args, **kwargs: b"")
    with pytest.raises(UpstreamPacketError, match="patch is empty"):
        build_packet(**common)
    monkeypatch.undo()

    release_path = source / "release-evidence" / "release-report.json"
    release_path.write_text(
        json.dumps({"valid": False, "reproducible_build": False, "artifacts": []}),
        encoding="utf-8",
    )
    with pytest.raises(UpstreamPacketError, match="not valid and reproducible"):
        build_packet(**common)

    release_path.write_text(
        json.dumps({"valid": True, "reproducible_build": True, "artifacts": {}}),
        encoding="utf-8",
    )
    with pytest.raises(UpstreamPacketError, match="artifacts are unavailable"):
        build_packet(**common)


@pytest.mark.parametrize(
    "raw",
    [b"x", b"ZZ file\0", b"\xff\0"],
)
def test_status_parser_rejects_malformed_or_unsupported_entries(raw: bytes) -> None:
    with pytest.raises(UpstreamPacketError):
        _parse_status(raw)


@pytest.mark.parametrize(
    "path",
    ["../escape", "/absolute", "folder\\file", "skill/__pycache__/x.pyc", "other.txt"],
)
def test_change_path_rejects_unsafe_cache_or_unexpected_paths(path: str) -> None:
    with pytest.raises(UpstreamPacketError):
        _validate_change_path(
            path,
            allowed_exact=frozenset({"README.md"}),
            allowed_prefixes=("skill/",),
        )


def test_cli_returns_bounded_failure_without_echoing_paths(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret_path = tmp_path / "SECRET-WORKTREE"

    assert main(["--skills-worktree", str(secret_path)]) == 1
    output = capsys.readouterr().out
    report = json.loads(output)
    assert report == {
        "contract": PACKET_CONTRACT,
        "raw_content_returned": False,
        "reason_code": "UPSTREAM_PACKET_INVALID",
        "valid": False,
    }
    assert "SECRET-WORKTREE" not in output


def test_cli_success_writes_and_reports_the_bounded_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    manifest = {
        "contract": PACKET_CONTRACT,
        "valid": True,
        "patch": {"filename": "packet.patch"},
        "raw_content_returned": False,
    }
    monkeypatch.setattr(packet_module, "build_packet", lambda **kwargs: (manifest, b"patch\n"))

    output = tmp_path / "output"
    assert main(["--skills-worktree", str(tmp_path), "--output-dir", str(output)]) == 0
    assert json.loads(capsys.readouterr().out) == manifest
    assert (output / "packet.patch").read_bytes() == b"patch\n"


def test_write_packet_requires_a_bounded_patch_filename(tmp_path: Path) -> None:
    with pytest.raises(UpstreamPacketError, match="patch filename"):
        write_packet(tmp_path / "output", {"patch": {}}, b"patch")

    target = tmp_path / "real-output"
    target.mkdir()
    link = tmp_path / "linked-output"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(UpstreamPacketError, match="symbolic link"):
        write_packet(link, {"patch": {"filename": "packet.patch"}}, b"patch")


def test_packet_rejects_invalid_proof_json_and_missing_documents(tmp_path: Path) -> None:
    worktree, baseline = _worktree(tmp_path)
    source = _source_root(tmp_path)
    common = {
        "worktree": worktree,
        "glassbox_root": source,
        "expected_baseline": baseline,
        "expected_branch": "feature",
        "allowed_exact": frozenset({"README.md", "skill/new.md"}),
        "allowed_prefixes": (),
        "required_paths": frozenset({"README.md", "skill/new.md"}),
        "proof_paths": ("proof.json",),
        "packet_documents": ("packet.md",),
    }
    (source / "proof.json").write_text(json.dumps({"valid": False}), encoding="utf-8")
    with pytest.raises(UpstreamPacketError, match="proof is invalid"):
        build_packet(**common)

    (source / "proof.json").write_text("[]", encoding="utf-8")
    with pytest.raises(UpstreamPacketError, match="not an object"):
        build_packet(**common)

    (source / "proof.json").write_text(
        json.dumps({"valid": True, "raw_content_returned": False}), encoding="utf-8"
    )
    (source / "packet.md").unlink()
    with pytest.raises(UpstreamPacketError, match="unavailable"):
        build_packet(**common)


def test_packet_rejects_no_changes_and_git_inspection_failure(tmp_path: Path) -> None:
    worktree, baseline = _worktree(tmp_path)
    _git(worktree, "restore", "README.md")
    (worktree / "skill" / "new.md").unlink()
    source = _source_root(tmp_path)
    with pytest.raises(UpstreamPacketError, match="no contribution changes"):
        build_packet(
            worktree=worktree,
            glassbox_root=source,
            expected_baseline=baseline,
            expected_branch="feature",
            allowed_exact=frozenset(),
            allowed_prefixes=(),
            required_paths=frozenset(),
            proof_paths=(),
            packet_documents=(),
        )

    with pytest.raises(UpstreamPacketError, match="git could not inspect"):
        packet_module._git(tmp_path, "status")


def test_patch_builder_rejects_an_unrepresentable_added_file(tmp_path: Path) -> None:
    worktree, _ = _worktree(tmp_path)
    with pytest.raises(UpstreamPacketError, match="represent an added"):
        packet_module._build_patch(worktree, tracked=(), untracked=("missing.md",))


def test_git_text_rejects_non_utf8_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed = subprocess.CompletedProcess(["git"], 0, stdout=b"\xff", stderr=b"")
    monkeypatch.setattr(packet_module, "_git", lambda *args, **kwargs: completed)
    with pytest.raises(UpstreamPacketError, match="non-UTF-8"):
        packet_module._git_text(tmp_path, "rev-parse", "HEAD")
