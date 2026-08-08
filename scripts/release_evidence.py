"""Verify release archives and emit deterministic checksums and a lockfile SBOM."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import tarfile
import tomllib
import zipfile
from collections.abc import Iterable, Mapping, Sequence
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

EXPECTED_WHEEL_FILES = frozenset(
    {
        "glassbox/py.typed",
        "glassbox_compiler/py.typed",
        "glassbox_datahub/py.typed",
        "glassbox_dbom/py.typed",
        "glassbox_dbom/schemas/0.1.0/schema.json",
        "glassbox_dbom/schemas/signer-trust/0.1.0/schema.json",
        "glassbox_forensics/py.typed",
        "glassbox_invalidation/py.typed",
        "glassbox_invalidation/schemas/state-transfer/0.1.0/schema.json",
        "glassbox_policy/py.typed",
        "glassbox_policy/schemas/semantic-policy/0.1.0/schema.json",
        "glassbox_replay/py.typed",
        "glassbox_replay/schemas/0.1.0/schema.json",
        "glassbox/schemas/runtime-event/0.1.0/schema.json",
    }
)
SBOM_SCHEMA = "http://cyclonedx.org/schema/bom-1.6.schema.json"
MAX_WHEEL_BYTES = 5 * 1024 * 1024
MAX_SDIST_BYTES = 10 * 1024 * 1024
FORBIDDEN_SDIST_ROOTS = frozenset(
    {".git", ".hypothesis", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".venv", "apps"}
)


class ReleaseEvidenceError(ValueError):
    """Raised when a release artifact cannot support a truthful release claim."""


def build_release_evidence(
    *,
    dist_directory: Path,
    lock_path: Path,
    pyproject_path: Path,
    output_directory: Path,
    reproducibility_directory: Path | None = None,
) -> dict[str, object]:
    """Verify exactly one wheel and sdist, then write bounded release evidence."""

    project = _project(pyproject_path)
    distribution = _distribution_name(project)
    version = _required_string(project, "version")
    wheel = _exactly_one(dist_directory.glob(f"{distribution}-{version}-*.whl"), "wheel")
    sdist = _exactly_one(dist_directory.glob(f"{distribution}-{version}.tar.gz"), "sdist")

    wheel_report = verify_wheel(wheel, project)
    sdist_report = verify_sdist(sdist, distribution=distribution, version=version)
    artifacts = [_artifact_record(wheel), _artifact_record(sdist)]
    reproducible = None
    if reproducibility_directory is not None:
        second_wheel = _exactly_one(
            reproducibility_directory.glob(f"{distribution}-{version}-*.whl"),
            "reproducibility wheel",
        )
        second_sdist = _exactly_one(
            reproducibility_directory.glob(f"{distribution}-{version}.tar.gz"),
            "reproducibility sdist",
        )
        if (
            wheel.read_bytes() != second_wheel.read_bytes()
            or sdist.read_bytes() != second_sdist.read_bytes()
        ):
            raise ReleaseEvidenceError("independent release builds are not byte-identical")
        reproducible = True

    output_directory.mkdir(parents=True, exist_ok=True)
    checksum_path = output_directory / "SHA256SUMS"
    checksum_path.write_text(
        "".join(f"{item['sha256']}  {item['filename']}\n" for item in artifacts),
        encoding="utf-8",
    )
    sbom_path = output_directory / f"{distribution}-{version}.cdx.json"
    sbom_path.write_text(
        json.dumps(cyclonedx_sbom(lock_path), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report: dict[str, object] = {
        "valid": True,
        "project": _required_string(project, "name"),
        "version": version,
        "artifacts": artifacts,
        "wheel": wheel_report,
        "sdist": sdist_report,
        "reproducible_build": reproducible,
        "evidence": {
            "checksums": checksum_path.name,
            "cyclonedx_sbom": sbom_path.name,
        },
    }
    report_path = output_directory / "release-report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def verify_wheel(path: Path, project: Mapping[str, Any]) -> dict[str, object]:
    """Verify archive safety, RECORD integrity, metadata, entry points, and contracts."""

    if path.stat().st_size > MAX_WHEEL_BYTES:
        raise ReleaseEvidenceError("wheel exceeds the bounded release size")
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        _require_safe_unique_paths(names, label="wheel")
        dist_info = _single_dist_info(names)
        metadata = BytesParser().parsebytes(archive.read(f"{dist_info}/METADATA"))
        if metadata["Name"] != _required_string(project, "name"):
            raise ReleaseEvidenceError("wheel project name does not match pyproject.toml")
        if metadata["Version"] != _required_string(project, "version"):
            raise ReleaseEvidenceError("wheel project version does not match pyproject.toml")
        if _normalized_specifier(metadata["Requires-Python"]) != _normalized_specifier(
            _required_string(project, "requires-python")
        ):
            raise ReleaseEvidenceError("wheel Python constraint does not match pyproject.toml")

        entries = _entry_points(archive.read(f"{dist_info}/entry_points.txt"))
        expected_entries = _expected_entry_points(project)
        if entries != expected_entries:
            raise ReleaseEvidenceError("wheel entry points do not exactly match pyproject.toml")
        missing = sorted(EXPECTED_WHEEL_FILES.difference(names))
        if missing:
            raise ReleaseEvidenceError(f"wheel is missing required contracts: {', '.join(missing)}")
        _verify_record(archive, dist_info=dist_info)

    return {
        "archive_safe": True,
        "record_verified": True,
        "metadata_matches": True,
        "entry_points_match": True,
        "required_contracts_present": True,
        "files": len(names),
    }


def verify_sdist(path: Path, *, distribution: str, version: str) -> dict[str, object]:
    """Reject unsafe, link-bearing, or incorrectly rooted source archives."""

    if path.stat().st_size > MAX_SDIST_BYTES:
        raise ReleaseEvidenceError("sdist exceeds the bounded release size")
    expected_root = f"{distribution}-{version}"
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        _require_safe_unique_paths(names, label="sdist")
        if any(PurePosixPath(name).parts[0] != expected_root for name in names):
            raise ReleaseEvidenceError("sdist contains a path outside its versioned root")
        if any(member.issym() or member.islnk() for member in members):
            raise ReleaseEvidenceError("sdist must not contain symbolic or hard links")
        leaked_roots = sorted(
            {
                parts[1]
                for name in names
                if len(parts := PurePosixPath(name).parts) > 1 and parts[1] in FORBIDDEN_SDIST_ROOTS
            }
        )
        if leaked_roots:
            raise ReleaseEvidenceError(
                f"sdist contains forbidden development trees: {', '.join(leaked_roots)}"
            )
        required = {
            f"{expected_root}/LICENSE",
            f"{expected_root}/README.md",
            f"{expected_root}/pyproject.toml",
            f"{expected_root}/scripts/release_evidence.py",
            f"{expected_root}/scripts/upstream_packet.py",
        }
        missing = sorted(required.difference(names))
        if missing:
            raise ReleaseEvidenceError(f"sdist is missing required files: {', '.join(missing)}")
    return {
        "archive_safe": True,
        "versioned_root": expected_root,
        "links_present": False,
        "required_files_present": True,
        "files": len(names),
    }


def cyclonedx_sbom(lock_path: Path) -> dict[str, object]:
    """Create a deterministic CycloneDX 1.6 inventory from the complete uv lock."""

    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = lock.get("package")
    if not isinstance(packages, list) or not packages:
        raise ReleaseEvidenceError("uv.lock contains no packages")
    normalized = [_lock_package(item) for item in packages]
    by_name = {item["name"]: item for item in normalized}
    if len(by_name) != len(normalized):
        raise ReleaseEvidenceError("uv.lock contains ambiguous duplicate package names")
    if "glassbox-core" not in by_name:
        raise ReleaseEvidenceError("uv.lock does not contain the GlassBox root package")

    components = [_component(item) for item in normalized if item["name"] != "glassbox-core"]
    dependencies = [
        {
            "ref": _bom_ref(item),
            "dependsOn": sorted(
                _bom_ref(by_name[name]) for name in item["dependencies"] if name in by_name
            ),
        }
        for item in normalized
    ]
    root = by_name["glassbox-core"]
    return {
        "$schema": SBOM_SCHEMA,
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                **_component(root),
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "properties": [{"name": "glassbox:inventory.scope", "value": "uv-lock-all-extras"}],
            },
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "glassbox-release-evidence",
                        "version": "1",
                    }
                ]
            },
        },
        "components": sorted(components, key=lambda item: str(item["bom-ref"])),
        "dependencies": sorted(dependencies, key=lambda item: str(item["ref"])),
    }


def _project(path: Path) -> Mapping[str, Any]:
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    project = document.get("project")
    if not isinstance(project, Mapping):
        raise ReleaseEvidenceError("pyproject.toml has no project table")
    return project


def _distribution_name(project: Mapping[str, Any]) -> str:
    return _required_string(project, "name").lower().replace("-", "_")


def _required_string(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise ReleaseEvidenceError(f"required string is missing: {key}")
    return selected


def _exactly_one(paths: Iterable[Path], label: str) -> Path:
    selected = sorted(paths)
    if len(selected) != 1:
        raise ReleaseEvidenceError(f"expected exactly one {label}, found {len(selected)}")
    return selected[0]


def _require_safe_unique_paths(names: Sequence[str], *, label: str) -> None:
    if len(names) != len(set(names)):
        raise ReleaseEvidenceError(f"{label} contains duplicate paths")
    for name in names:
        path = PurePosixPath(name)
        if path.is_absolute() or not path.parts or ".." in path.parts or "\\" in name:
            raise ReleaseEvidenceError(f"{label} contains an unsafe path")


def _single_dist_info(names: Sequence[str]) -> str:
    directories = {
        part for name in names if (part := PurePosixPath(name).parts[0]).endswith(".dist-info")
    }
    if len(directories) != 1:
        raise ReleaseEvidenceError("wheel must contain exactly one dist-info directory")
    selected = directories.pop()
    for required in ("METADATA", "RECORD", "entry_points.txt"):
        if f"{selected}/{required}" not in names:
            raise ReleaseEvidenceError(f"wheel is missing dist-info/{required}")
    return selected


def _entry_points(raw: bytes) -> dict[str, dict[str, str]]:
    import configparser

    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(raw.decode("utf-8"))
    return {section: dict(parser.items(section)) for section in parser.sections()}


def _expected_entry_points(project: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    expected: dict[str, dict[str, str]] = {}
    scripts = project.get("scripts", {})
    if isinstance(scripts, Mapping):
        expected["console_scripts"] = {str(key): str(value) for key, value in scripts.items()}
    entry_points = project.get("entry-points", {})
    if isinstance(entry_points, Mapping):
        for group, values in entry_points.items():
            if isinstance(values, Mapping):
                expected[str(group)] = {str(key): str(value) for key, value in values.items()}
    return expected


def _verify_record(archive: zipfile.ZipFile, *, dist_info: str) -> None:
    record_name = f"{dist_info}/RECORD"
    rows = csv.reader(archive.read(record_name).decode("utf-8").splitlines())
    recorded: set[str] = set()
    for row in rows:
        if len(row) != 3:
            raise ReleaseEvidenceError("wheel RECORD contains a malformed row")
        name, digest, size = row
        recorded.add(name)
        if name == record_name:
            if digest or size:
                raise ReleaseEvidenceError("wheel RECORD must not hash itself")
            continue
        if not digest.startswith("sha256=") or not size.isdigit():
            raise ReleaseEvidenceError("wheel RECORD uses an unsupported digest or size")
        content = archive.read(name)
        encoded = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        if digest.removeprefix("sha256=") != encoded or int(size) != len(content):
            raise ReleaseEvidenceError("wheel RECORD integrity verification failed")
    if recorded != set(archive.namelist()):
        raise ReleaseEvidenceError("wheel RECORD does not cover every archive member")


def _artifact_record(path: Path) -> dict[str, object]:
    return {
        "filename": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size": path.stat().st_size,
    }


def _normalized_specifier(value: str | None) -> tuple[str, ...]:
    if value is None:
        raise ReleaseEvidenceError("wheel metadata has no Requires-Python value")
    return tuple(sorted(part.strip().replace(" ", "") for part in value.split(",") if part))


def _lock_package(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReleaseEvidenceError("uv.lock package entry is not an object")
    name = _required_string(value, "name")
    version = _required_string(value, "version")
    dependency_names: set[str] = set()
    for item in value.get("dependencies", []):
        if isinstance(item, Mapping) and isinstance(item.get("name"), str):
            dependency_names.add(item["name"])
    optional = value.get("optional-dependencies", {})
    if isinstance(optional, Mapping):
        for items in optional.values():
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, Mapping) and isinstance(item.get("name"), str):
                        dependency_names.add(item["name"])
    return {"name": name, "version": version, "dependencies": sorted(dependency_names)}


def _bom_ref(package: Mapping[str, Any]) -> str:
    name = quote(_required_string(package, "name"), safe="-._~")
    version = quote(_required_string(package, "version"), safe="-._~")
    return f"pkg:pypi/{name}@{version}"


def _component(package: Mapping[str, Any]) -> dict[str, object]:
    reference = _bom_ref(package)
    return {
        "type": "library",
        "bom-ref": reference,
        "name": _required_string(package, "name"),
        "version": _required_string(package, "version"),
        "purl": reference,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--lock", type=Path, default=Path("uv.lock"))
    parser.add_argument("--pyproject", type=Path, default=Path("pyproject.toml"))
    parser.add_argument("--output", type=Path, default=Path("release-evidence"))
    parser.add_argument(
        "--reproducibility-dist",
        type=Path,
        default=None,
        help="optional second build directory that must be byte-identical",
    )
    args = parser.parse_args()
    try:
        report = build_release_evidence(
            dist_directory=args.dist,
            lock_path=args.lock,
            pyproject_path=args.pyproject,
            output_directory=args.output,
            reproducibility_directory=args.reproducibility_dist,
        )
    except (OSError, ReleaseEvidenceError, tarfile.TarError, zipfile.BadZipFile):
        print(json.dumps({"valid": False, "error_code": "RELEASE_EVIDENCE_INVALID"}))
        raise SystemExit(1) from None
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
