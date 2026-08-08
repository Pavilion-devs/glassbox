"""Release archive, checksum, and lockfile-SBOM tests."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import shutil
import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts.release_evidence import (
    EXPECTED_WHEEL_FILES,
    ReleaseEvidenceError,
    build_release_evidence,
    verify_wheel,
)

PROJECT = {
    "name": "glassbox-core",
    "version": "0.1.0",
    "requires-python": ">=3.11,<3.14",
    "scripts": {"glassbox-forensics-mcp": "glassbox_forensics.server:main"},
    "entry-points": {
        "datahub_actions.action.plugins": {
            "glassbox_invalidation": (
                "glassbox_invalidation.datahub_action:GlassBoxInvalidationAction"
            )
        }
    },
}


def test_release_evidence_verifies_archives_and_is_deterministic(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = dist / "glassbox_core-0.1.0-py3-none-any.whl"
    sdist = dist / "glassbox_core-0.1.0.tar.gz"
    _write_wheel(wheel)
    _write_sdist(sdist)
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "glassbox-core"
version = "0.1.0"
requires-python = ">=3.11,<3.14"

[project.scripts]
glassbox-forensics-mcp = "glassbox_forensics.server:main"

[project.entry-points."datahub_actions.action.plugins"]
glassbox_invalidation = "glassbox_invalidation.datahub_action:GlassBoxInvalidationAction"
""".strip()
        + "\n",
        encoding="utf-8",
    )
    lock = tmp_path / "uv.lock"
    lock.write_text(
        """
version = 1
revision = 3
requires-python = ">=3.11,<3.14"

[[package]]
name = "glassbox-core"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "rfc8785" }]

[[package]]
name = "rfc8785"
version = "0.1.4"
source = { registry = "https://pypi.org/simple" }
""".strip()
        + "\n",
        encoding="utf-8",
    )
    reproducibility_dist = tmp_path / "reproducibility-dist"
    shutil.copytree(dist, reproducibility_dist)

    first = build_release_evidence(
        dist_directory=dist,
        lock_path=lock,
        pyproject_path=pyproject,
        output_directory=tmp_path / "evidence-one",
        reproducibility_directory=reproducibility_dist,
    )
    second = build_release_evidence(
        dist_directory=dist,
        lock_path=lock,
        pyproject_path=pyproject,
        output_directory=tmp_path / "evidence-two",
        reproducibility_directory=reproducibility_dist,
    )

    assert first == second
    assert first["valid"] is True
    assert first["wheel"]["record_verified"] is True
    assert first["reproducible_build"] is True
    assert (tmp_path / "evidence-one" / "SHA256SUMS").read_bytes() == (
        tmp_path / "evidence-two" / "SHA256SUMS"
    ).read_bytes()
    sbom = json.loads((tmp_path / "evidence-one" / "glassbox_core-0.1.0.cdx.json").read_text())
    assert sbom["specVersion"] == "1.6"
    assert sbom["metadata"]["component"]["name"] == "glassbox-core"
    assert sbom["dependencies"][0]["dependsOn"]


def test_wheel_record_tampering_fails_closed(tmp_path: Path) -> None:
    wheel = tmp_path / "glassbox_core-0.1.0-py3-none-any.whl"
    _write_wheel(wheel)
    with zipfile.ZipFile(wheel) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    files["glassbox_forensics/py.typed"] = b"tampered"
    with zipfile.ZipFile(wheel, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)

    with pytest.raises(ReleaseEvidenceError):
        verify_wheel(wheel, PROJECT)


def _write_wheel(path: Path) -> None:
    dist_info = "glassbox_core-0.1.0.dist-info"
    files = dict.fromkeys(EXPECTED_WHEEL_FILES, b"")
    files[f"{dist_info}/METADATA"] = (
        b"Metadata-Version: 2.4\n"
        b"Name: glassbox-core\n"
        b"Version: 0.1.0\n"
        b"Requires-Python: >=3.11,<3.14\n"
    )
    files[f"{dist_info}/entry_points.txt"] = (
        b"[console_scripts]\n"
        b"glassbox-forensics-mcp = glassbox_forensics.server:main\n\n"
        b"[datahub_actions.action.plugins]\n"
        b"glassbox_invalidation = "
        b"glassbox_invalidation.datahub_action:GlassBoxInvalidationAction\n"
    )
    record = io.StringIO()
    writer = csv.writer(record, lineterminator="\n")
    for name, content in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        writer.writerow((name, f"sha256={digest}", len(content)))
    writer.writerow((f"{dist_info}/RECORD", "", ""))
    files[f"{dist_info}/RECORD"] = record.getvalue().encode()
    with zipfile.ZipFile(path, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)


def _write_sdist(path: Path) -> None:
    with tarfile.open(path, mode="w:gz") as archive:
        for name in (
            "LICENSE",
            "README.md",
            "pyproject.toml",
            "scripts/release_evidence.py",
            "scripts/upstream_packet.py",
        ):
            content = b"synthetic\n"
            info = tarfile.TarInfo(f"glassbox_core-0.1.0/{name}")
            info.size = len(content)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(content))
