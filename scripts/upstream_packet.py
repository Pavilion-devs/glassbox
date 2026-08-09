"""Build a deterministic, raw-free maintainer packet for the DataHub contributions."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

PACKET_CONTRACT = "glassbox.upstream-contribution-packet.v1"
TARGET_REPOSITORY = "https://github.com/datahub-project/datahub-skills"
TARGET_BRANCH = "feat/agent-decision-forensics"
TARGET_BASELINE = "f22f93074cf265ba6f9401947404f090c2584d9d"
TARGET_PULL_REQUEST_PREFIX = f"{TARGET_REPOSITORY}/pull/"

_ALLOWED_EXACT = frozenset(
    {
        ".claude-plugin/marketplace.json",
        ".claude-plugin/plugin.json",
        ".github/workflows/lint.yml",
        "README.md",
        "commands/catalog-agent-forensics.md",
        "skills/using-datahub/SKILL.md",
        "tests/test_agent_forensics_scripts.py",
    }
)
_ALLOWED_PREFIXES = ("skills/datahub-agent-forensics/",)
_REQUIRED_PATHS = frozenset(
    {
        *_ALLOWED_EXACT,
        "skills/datahub-agent-forensics/SKILL.md",
        "skills/datahub-agent-forensics/evaluations/preserve-dual-mcp-evidence-boundaries.json",
        "skills/datahub-agent-forensics/references/narration-contract.md",
    }
)
_PROOF_PATHS = (
    "docs/compatibility/datahub-1.6.0-dual-mcp-forensics.live.json",
    "docs/compatibility/datahub-1.6.0-dual-mcp-agent-narration.eval.json",
    "docs/compatibility/datahub-1.6.0-durable-recovery-crash.live.json",
    "docs/compatibility/datahub-1.6.0-durable-recovery-uncertain-crash.live.json",
    "docs/compatibility/datahub-1.6.0-semantic-policy.live.json",
    "docs/compatibility/datahub-1.6.0-kafka-invalidation.live.json",
    "docs/compatibility/datahub-1.6.0-pgqueue-invalidation.live.json",
)
_PACKET_DOCUMENTS = (
    "docs/upstream/agent-decision-rfc-discussion.md",
    "docs/upstream/datahub-agent-forensics-pr.md",
    "docs/upstream/datahub-actions-contribution.md",
    "docs/upstream/release-readiness.md",
)
_FORBIDDEN_BYTES = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"postgresql://",
)


class UpstreamPacketError(RuntimeError):
    """Raised when a maintainer packet cannot be built without ambiguity."""


def build_packet(
    *,
    worktree: Path,
    glassbox_root: Path,
    expected_baseline: str = TARGET_BASELINE,
    expected_branch: str = TARGET_BRANCH,
    allowed_exact: frozenset[str] = _ALLOWED_EXACT,
    allowed_prefixes: Sequence[str] = _ALLOWED_PREFIXES,
    required_paths: frozenset[str] = _REQUIRED_PATHS,
    proof_paths: Sequence[str] = _PROOF_PATHS,
    packet_documents: Sequence[str] = _PACKET_DOCUMENTS,
    pull_request_url: str | None = None,
    expected_head: str | None = None,
) -> tuple[dict[str, object], bytes]:
    """Validate contribution scope and return its manifest plus apply-ready patch."""

    root = worktree.resolve(strict=True)
    source_root = glassbox_root.resolve(strict=True)
    head = _git_text(root, "rev-parse", "HEAD")
    branch = _git_text(root, "branch", "--show-current")
    if branch != expected_branch:
        raise UpstreamPacketError("upstream worktree branch does not match the packet contract")
    status_raw = _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all").stdout
    whitespace_args: tuple[str, ...]
    target: dict[str, object] = {
        "repository": TARGET_REPOSITORY,
        "baseline": expected_baseline,
        "branch": branch,
        "baseline_verified_date": "2026-08-07",
    }
    if expected_head is None:
        if head != expected_baseline:
            raise UpstreamPacketError(
                "upstream worktree baseline does not match the packet contract"
            )
        changes = _parse_status(status_raw)
        tracked = sorted(path for change, path in changes if change != "??")
        untracked = sorted(path for change, path in changes if change == "??")
        patch = _build_patch(root, tracked=tracked, untracked=untracked)
        whitespace_args = ("diff", "--check")
    else:
        if head != expected_head:
            raise UpstreamPacketError("upstream worktree head does not match the packet contract")
        if status_raw:
            raise UpstreamPacketError("committed upstream worktree must be clean")
        ancestry = _git(
            root,
            "merge-base",
            "--is-ancestor",
            expected_baseline,
            expected_head,
            check=False,
        )
        if ancestry.returncode != 0:
            raise UpstreamPacketError("upstream baseline is not an ancestor of the committed head")
        changes = _parse_committed_changes(
            _git(
                root,
                "diff",
                "--name-status",
                "-z",
                expected_baseline,
                expected_head,
            ).stdout
        )
        patch = _git(
            root,
            "diff",
            "--binary",
            "--full-index",
            expected_baseline,
            expected_head,
        ).stdout
        whitespace_args = ("diff", "--check", expected_baseline, expected_head)
        target["head"] = expected_head

    whitespace_check = _git(root, *whitespace_args, check=False)
    if whitespace_check.stdout:
        raise UpstreamPacketError("upstream worktree has whitespace errors")
    if whitespace_check.returncode != 0:
        raise UpstreamPacketError("git could not inspect the upstream worktree")

    if not changes:
        raise UpstreamPacketError("upstream worktree has no contribution changes")
    paths = {path for _, path in changes}
    missing = required_paths - paths
    if missing:
        raise UpstreamPacketError("upstream contribution is missing required paths")

    records: list[dict[str, object]] = []
    for status, path in changes:
        _validate_change_path(path, allowed_exact=allowed_exact, allowed_prefixes=allowed_prefixes)
        candidate = root / path
        if not candidate.is_file() or candidate.is_symlink():
            raise UpstreamPacketError("upstream contribution path is not a regular file")
        content = candidate.read_bytes()
        if len(content) > 1_048_576:
            raise UpstreamPacketError("upstream contribution file exceeds the size limit")
        if any(marker in content for marker in _FORBIDDEN_BYTES):
            raise UpstreamPacketError("upstream contribution contains forbidden secret material")
        kind = "ADDED" if status in {"??", "A"} else "MODIFIED"
        records.append(
            {
                "path": path,
                "change": kind,
                "sha256": _sha256(content),
                "size": len(content),
            }
        )

    if not patch or len(patch) > 4_194_304:
        raise UpstreamPacketError("upstream patch is empty or exceeds the size limit")
    if any(marker in patch for marker in _FORBIDDEN_BYTES):
        raise UpstreamPacketError("upstream patch contains forbidden secret material")

    release = _read_object(source_root / "release-evidence" / "release-report.json")
    if release.get("valid") is not True or release.get("reproducible_build") is not True:
        raise UpstreamPacketError("GlassBox release evidence is not valid and reproducible")
    artifacts = release.get("artifacts")
    if not isinstance(artifacts, list):
        raise UpstreamPacketError("GlassBox release artifacts are unavailable")

    proofs = [_evidence_record(source_root, path) for path in proof_paths]
    documents = [_file_record(source_root, path) for path in packet_documents]
    manifest: dict[str, object] = {
        "contract": PACKET_CONTRACT,
        "valid": True,
        "target": target,
        "changes": sorted(records, key=lambda item: str(item["path"])),
        "change_count": len(records),
        "patch": {
            "filename": f"datahub-skills-agent-forensics-{expected_baseline[:7]}.patch",
            "sha256": _sha256(patch),
            "size": len(patch),
            "applies_to_exact_baseline": True,
        },
        "glassbox_release": {
            "project": release.get("project"),
            "version": release.get("version"),
            "artifacts": artifacts,
            "reproducible_build": True,
        },
        "implementation_proofs": proofs,
        "maintainer_documents": documents,
        "publication": _publication_record(pull_request_url),
        "scope": {
            "datahub_core_patch_included": False,
            "glassbox_runtime_copied_into_skill_repository": False,
            "raw_prompt_or_response_included": False,
        },
        "raw_content_returned": False,
    }
    return manifest, patch


def write_packet(output_dir: Path, manifest: Mapping[str, object], patch: bytes) -> None:
    """Write the two deterministic packet artifacts."""

    if output_dir.is_symlink():
        raise UpstreamPacketError("packet output directory cannot be a symbolic link")
    destination = output_dir.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    patch_info = manifest.get("patch")
    if not isinstance(patch_info, Mapping) or not isinstance(patch_info.get("filename"), str):
        raise UpstreamPacketError("packet manifest has no patch filename")
    patch_path = destination / str(patch_info["filename"])
    manifest_path = destination / "upstream-packet.json"
    patch_path.write_bytes(patch)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    patch_path.chmod(0o644)
    manifest_path.chmod(0o644)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build the GlassBox upstream contribution packet")
    parser.add_argument("--skills-worktree", type=Path, required=True)
    parser.add_argument("--glassbox-root", type=Path, default=Path.cwd())
    parser.add_argument("--output-dir", type=Path, default=Path("release-evidence/upstream"))
    parser.add_argument("--expected-baseline", default=TARGET_BASELINE)
    parser.add_argument("--expected-branch", default=TARGET_BRANCH)
    parser.add_argument("--expected-head")
    parser.add_argument("--pull-request-url")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest, patch = build_packet(
            worktree=args.skills_worktree,
            glassbox_root=args.glassbox_root,
            expected_baseline=args.expected_baseline,
            expected_branch=args.expected_branch,
            expected_head=args.expected_head,
            pull_request_url=args.pull_request_url,
        )
        write_packet(args.output_dir, manifest, patch)
    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError, UpstreamPacketError):
        print(
            json.dumps(
                {
                    "contract": PACKET_CONTRACT,
                    "valid": False,
                    "reason_code": "UPSTREAM_PACKET_INVALID",
                    "raw_content_returned": False,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(manifest, separators=(",", ":"), sort_keys=True))
    return 0


def _publication_record(pull_request_url: str | None) -> dict[str, object]:
    publication: dict[str, object] = {
        "discussion_posted": False,
        "pull_request_opened": False,
        "package_published": False,
        "release_created": False,
    }
    if pull_request_url is None:
        return publication
    number = pull_request_url.removeprefix(TARGET_PULL_REQUEST_PREFIX)
    if (
        not pull_request_url.startswith(TARGET_PULL_REQUEST_PREFIX)
        or not number.isascii()
        or not number.isdigit()
        or int(number) < 1
    ):
        raise UpstreamPacketError("pull request URL does not match the target repository")
    publication["pull_request_opened"] = True
    publication["pull_request_url"] = pull_request_url
    return publication


def _parse_status(raw: bytes) -> list[tuple[str, str]]:
    changes: list[tuple[str, str]] = []
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        try:
            entry = encoded.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise UpstreamPacketError("upstream status path is not UTF-8") from exc
        if len(entry) < 4 or entry[2] != " ":
            raise UpstreamPacketError("upstream status entry is malformed")
        status, path = entry[:2], entry[3:]
        if status not in {" M", "M ", "MM", "??"}:
            raise UpstreamPacketError("upstream contribution contains unsupported git changes")
        changes.append((status, path))
    return changes


def _parse_committed_changes(raw: bytes) -> list[tuple[str, str]]:
    if raw and not raw.endswith(b"\0"):
        raise UpstreamPacketError("committed upstream change list is malformed")
    encoded = [item for item in raw.split(b"\0") if item]
    if len(encoded) % 2:
        raise UpstreamPacketError("committed upstream change list is malformed")
    changes: list[tuple[str, str]] = []
    for index in range(0, len(encoded), 2):
        try:
            status = encoded[index].decode("ascii")
            path = encoded[index + 1].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise UpstreamPacketError("committed upstream change list is not UTF-8") from exc
        if status not in {"A", "M"}:
            raise UpstreamPacketError("committed upstream contribution has unsupported changes")
        changes.append((status, path))
    return changes


def _validate_change_path(
    path: str,
    *,
    allowed_exact: frozenset[str],
    allowed_prefixes: Sequence[str],
) -> None:
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts or "\\" in path:
        raise UpstreamPacketError("upstream contribution path is unsafe")
    if path not in allowed_exact and not any(
        path.startswith(prefix) for prefix in allowed_prefixes
    ):
        raise UpstreamPacketError("upstream contribution contains an unexpected path")
    if "__pycache__" in pure.parts or path.endswith((".pyc", ".pyo")):
        raise UpstreamPacketError("upstream contribution contains a Python cache file")


def _build_patch(root: Path, *, tracked: Sequence[str], untracked: Sequence[str]) -> bytes:
    chunks: list[bytes] = []
    if tracked:
        chunks.append(_git(root, "diff", "--binary", "--full-index", "HEAD", "--", *tracked).stdout)
    for path in untracked:
        completed = _git(
            root, "diff", "--no-index", "--binary", "--", "/dev/null", path, check=False
        )
        if completed.returncode != 1 or not completed.stdout:
            raise UpstreamPacketError("could not represent an added contribution file")
        chunks.append(completed.stdout)
    return b"".join(chunk if chunk.endswith(b"\n") else chunk + b"\n" for chunk in chunks)


def _evidence_record(root: Path, relative: str) -> dict[str, object]:
    record = _file_record(root, relative)
    document = _read_object(root / relative)
    if document.get("valid") is not True or document.get("raw_content_returned") is not False:
        raise UpstreamPacketError("implementation proof is invalid or not raw-free")
    record["contract"] = document.get("contract")
    record["valid"] = True
    return record


def _file_record(root: Path, relative: str) -> dict[str, object]:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise UpstreamPacketError("packet source document is unavailable")
    content = path.read_bytes()
    return {"path": relative, "sha256": _sha256(content), "size": len(content)}


def _read_object(path: Path) -> Mapping[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise UpstreamPacketError("packet JSON source is not an object")
    return value


def _git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
    )
    if check and completed.returncode != 0:
        raise UpstreamPacketError("git could not inspect the upstream worktree")
    return completed


def _git_text(root: Path, *args: str) -> str:
    try:
        return _git(root, *args).stdout.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise UpstreamPacketError("git returned non-UTF-8 metadata") from exc


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


if __name__ == "__main__":  # pragma: no cover - console module
    raise SystemExit(main())
