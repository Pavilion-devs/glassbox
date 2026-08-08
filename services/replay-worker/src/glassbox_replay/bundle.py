"""Build and independently verify content-addressed replay bundles."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker

from glassbox_dbom import SigningKey, verify_receipt
from glassbox_dbom.canonical import canonicalize
from glassbox_replay.models import (
    ActionInputReplacement,
    ContextReplacement,
    ReplayInputError,
    ReplayMode,
    ReplaySupplement,
    _digest_object,
)

REPLAY_BUNDLE_SPEC_VERSION = "0.1.0"
_BUNDLE_DOMAIN = b"glassbox.replay.bundle.v1\0"
_ACTION_DOMAIN = b"glassbox.replay.action.v1\0"
_SIGNATURE_DOMAIN = b"glassbox.replay.bundle.signature.v1\0"
_SCHEMA_RELATIVE_PATH = Path("schemas") / REPLAY_BUNDLE_SPEC_VERSION / "schema.json"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ReplayBundleError(ValueError):
    """Raised when a replay bundle cannot be safely built or verified."""


@dataclass(frozen=True)
class BundleSignatureResult:
    """Verification result for one replay-bundle signature."""

    key_id: str
    valid: bool
    error: str | None = None


@dataclass(frozen=True)
class ReplayBundleVerification:
    """Closed verification report with no hidden exception state."""

    schema_valid: bool
    payload_digest_valid: bool
    bundle_id_valid: bool
    action_digests_valid: bool
    signatures: tuple[BundleSignatureResult, ...]
    signature_required: bool
    source_receipt_valid: bool | None
    errors: tuple[str, ...]

    @property
    def valid(self) -> bool:
        signature_gate = (not self.signature_required) or (
            bool(self.signatures) and all(item.valid for item in self.signatures)
        )
        source_gate = self.source_receipt_valid is not False
        return (
            self.schema_valid
            and self.payload_digest_valid
            and self.bundle_id_valid
            and self.action_digests_valid
            and all(item.valid for item in self.signatures)
            and signature_gate
            and source_gate
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "schema_valid": self.schema_valid,
            "payload_digest_valid": self.payload_digest_valid,
            "bundle_id_valid": self.bundle_id_valid,
            "action_digests_valid": self.action_digests_valid,
            "signature_required": self.signature_required,
            "source_receipt_valid": self.source_receipt_valid,
            "signatures": [
                {"key_id": item.key_id, "valid": item.valid, "error": item.error}
                for item in self.signatures
            ],
            "errors": list(self.errors),
        }


def load_replay_bundle_schema(path: Path | None = None) -> dict[str, Any]:
    """Load the normative replay-bundle schema from source or the wheel."""

    if path is not None:
        return _read_schema(path)
    repository = (
        Path(__file__).resolve().parents[4]
        / "schemas"
        / "replay-bundle"
        / REPLAY_BUNDLE_SPEC_VERSION
        / "schema.json"
    )
    if repository.is_file():
        return _read_schema(repository)
    packaged = resources.files("glassbox_replay").joinpath(str(_SCHEMA_RELATIVE_PATH))
    with packaged.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ReplayBundleError("replay-bundle schema root must be an object")
    return loaded


def validate_replay_bundle(
    bundle: Mapping[str, Any],
    *,
    schema: Mapping[str, Any] | None = None,
) -> None:
    """Validate a replay bundle and raise every deterministic schema failure."""

    selected = dict(schema) if schema is not None else load_replay_bundle_schema()
    validator = Draft202012Validator(selected, format_checker=FormatChecker())
    failures: list[str] = []
    for error in sorted(validator.iter_errors(bundle), key=lambda item: list(item.path)):
        location = "/" + "/".join(str(part) for part in error.absolute_path)
        failures.append(f"{location}: {error.message}")
    if failures:
        raise ReplayBundleError("; ".join(failures))


def build_replay_bundle(
    receipt: Mapping[str, Any],
    *,
    mode: ReplayMode,
    supplement: ReplaySupplement | None = None,
    context_replacements: Iterable[ContextReplacement] = (),
    action_input_replacements: Iterable[ActionInputReplacement] = (),
    signing_keys: Iterable[SigningKey] = (),
    require_source_signature: bool = True,
) -> dict[str, Any]:
    """Verify a DBOM and derive a signed digest-only replay recipe."""

    source_report = verify_receipt(receipt, require_signature=require_source_signature)
    if not source_report.valid:
        raise ReplayBundleError(
            "source receipt verification failed: " + "; ".join(source_report.errors)
        )
    replacements = tuple(context_replacements)
    _validate_replacements(receipt, mode, replacements)
    replacement_by_id = {item.evidence_id: item for item in replacements}
    input_replacements = tuple(action_input_replacements)
    _validate_action_input_replacements(receipt, mode, replacements, input_replacements)
    input_replacement_by_id = {item.action_id: item for item in input_replacements}
    selected_supplement = supplement or ReplaySupplement()

    tools = tuple(_tool_pin(item) for item in _list_of_mappings(receipt, "tools"))
    tool_by_id = {_required_text(item, "id"): item for item in tools}
    actions: list[dict[str, Any]] = []
    for original in _list_of_mappings(receipt, "actions"):
        action_id = _required_text(original, "action_id")
        tool_id = _required_text(original, "tool_id")
        tool = tool_by_id.get(tool_id)
        if tool is None:
            raise ReplayBundleError(f"action references undeclared tool {tool_id}")
        action: dict[str, Any] = {
            "action_id": action_id,
            "tool_id": tool_id,
            "effect": _required_text(original, "effect"),
            "status": _required_text(original, "status"),
            "idempotency_key": _optional_text(original, "idempotency_key"),
            "input_digest": _required_digest(original, "input_digest"),
            "output_digest": _optional_digest(original, "output_digest"),
            "approval_id": _optional_text(original, "approval_id"),
        }
        input_replacement = input_replacement_by_id.get(action_id)
        if input_replacement is not None:
            action["original_input_digest"] = action["input_digest"]
            action["input_digest"] = _digest_object(input_replacement.input_digest)
            action["input_origin"] = "CONTEXT_REPLACEMENT"
            action["input_evidence_ids"] = sorted(input_replacement.evidence_ids)
            action["input_verification_authority"] = input_replacement.verification_authority
        action["action_digest"] = _digest_object(
            _domain_digest(_ACTION_DOMAIN, {"action": action, "tool": tool})
        )
        actions.append(action)

    context: list[dict[str, Any]] = []
    for original in _list_of_mappings(receipt, "evidence"):
        evidence_id = _required_text(original, "evidence_id")
        replacement = replacement_by_id.get(evidence_id)
        original_digest = _optional_digest(original, "representation_digest")
        context.append(
            {
                "evidence_id": evidence_id,
                "datahub_urn": _optional_text(original, "datahub_urn"),
                "schema_field_urn": _optional_text(original, "schema_field_urn"),
                "state": _required_text(original, "state"),
                "role": _required_text(original, "role"),
                "original_representation_digest": original_digest,
                "active_representation_digest": (
                    _digest_object(replacement.representation_digest)
                    if replacement is not None
                    else original_digest
                ),
                "origin": (
                    "CONTEXT_REPLACEMENT" if replacement is not None else "ORIGINAL_RECEIPT"
                ),
                "verification_authority": (
                    replacement.verification_authority if replacement is not None else None
                ),
            }
        )

    integrity = _required_mapping(receipt, "integrity")
    replay = _required_mapping(receipt, "replay")
    run = _required_mapping(receipt, "run")
    output = _required_mapping(receipt, "output")
    payload: dict[str, Any] = {
        "spec_version": REPLAY_BUNDLE_SPEC_VERSION,
        "source": {
            "receipt_id": _required_text(receipt, "receipt_id"),
            "payload_digest": _required_digest(integrity, "payload_digest"),
            "replay_eligibility": _required_text(replay, "eligibility"),
        },
        "mode": mode.value,
        "recipe": {
            "environment": _required_text(run, "environment"),
            "agent": _component_pin(_required_mapping(receipt, "agent")),
            "workflow": _workflow_pin(_required_mapping(receipt, "workflow")),
            "models": [_component_pin(item) for item in _list_of_mappings(receipt, "models")],
            "skills": [_component_pin(item) for item in _list_of_mappings(receipt, "skills")],
            "tools": list(tools),
            "queries": [
                {
                    "query_id": _required_text(item, "query_id"),
                    "language": _required_text(item, "language"),
                    "statement_digest": _required_digest(item, "statement_digest"),
                    "redacted": _required_bool(item, "redacted"),
                }
                for item in _list_of_mappings(receipt, "queries")
            ],
            "actions": actions,
        },
        "execution": selected_supplement.to_dict(),
        "context": context,
        "original_output": {
            "kind": _required_text(output, "kind"),
            "mime_type": _required_text(output, "mime_type"),
            "digest": _required_digest(output, "digest"),
        },
    }
    digest = replay_bundle_payload_digest(payload)
    payload["bundle_id"] = f"gbx:replay-bundle:sha256:{digest}"
    payload["integrity"] = {
        "canonicalization": "RFC8785",
        "payload_digest": _digest_object(digest),
        "signatures": [_create_signature(digest, key) for key in signing_keys],
    }
    validate_replay_bundle(payload)
    return payload


def replay_bundle_payload_material(bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Return the exact material committed by a replay-bundle payload digest."""

    material = copy.deepcopy(dict(bundle))
    material.pop("bundle_id", None)
    material.pop("integrity", None)
    return material


def replay_bundle_payload_digest(bundle: Mapping[str, Any]) -> str:
    """Compute the domain-separated replay-bundle payload digest."""

    return _domain_digest(_BUNDLE_DOMAIN, replay_bundle_payload_material(bundle))


def verify_replay_bundle(
    bundle: Mapping[str, Any],
    *,
    require_signature: bool = True,
    source_receipt: Mapping[str, Any] | None = None,
    require_source_signature: bool = True,
) -> ReplayBundleVerification:
    """Verify bundle schema, derivations, signatures, and optional source binding."""

    errors: list[str] = []
    try:
        validate_replay_bundle(bundle)
        schema_valid = True
    except ReplayBundleError as exc:
        schema_valid = False
        errors.append(f"schema: {exc}")

    expected_digest = replay_bundle_payload_digest(bundle)
    integrity = bundle.get("integrity")
    integrity_mapping = integrity if isinstance(integrity, Mapping) else {}
    recorded_digest = _nested_digest_value(integrity_mapping, "payload_digest")
    payload_digest_valid = recorded_digest is not None and hmac.compare_digest(
        expected_digest, recorded_digest
    )
    if not payload_digest_valid:
        errors.append("integrity: replay-bundle payload digest mismatch")
    expected_id = f"gbx:replay-bundle:sha256:{expected_digest}"
    bundle_id = bundle.get("bundle_id")
    bundle_id_valid = isinstance(bundle_id, str) and hmac.compare_digest(expected_id, bundle_id)
    if not bundle_id_valid:
        errors.append("integrity: replay-bundle ID mismatch")

    action_digests_valid = _verify_action_digests(bundle)
    if not action_digests_valid:
        errors.append("integrity: replay action digest mismatch")

    signature_results = _verify_signatures(integrity_mapping, expected_digest)
    for result in signature_results:
        if not result.valid:
            errors.append(f"signature {result.key_id!r}: {result.error}")
    if require_signature and not signature_results:
        errors.append("signature: at least one replay-bundle signature is required")

    source_valid: bool | None = None
    if source_receipt is not None:
        source_report = verify_receipt(
            source_receipt,
            require_signature=require_source_signature,
        )
        source = bundle.get("source")
        source_mapping = source if isinstance(source, Mapping) else {}
        source_valid = (
            source_report.valid
            and source_mapping.get("receipt_id") == source_receipt.get("receipt_id")
            and _nested_digest_value(source_mapping, "payload_digest")
            == _nested_digest_value(
                _required_mapping(source_receipt, "integrity"), "payload_digest"
            )
        )
        if not source_valid:
            errors.append("source: replay bundle is not bound to the supplied receipt")

    return ReplayBundleVerification(
        schema_valid=schema_valid,
        payload_digest_valid=payload_digest_valid,
        bundle_id_valid=bundle_id_valid,
        action_digests_valid=action_digests_valid,
        signatures=signature_results,
        signature_required=require_signature,
        source_receipt_valid=source_valid,
        errors=tuple(errors),
    )


def _validate_replacements(
    receipt: Mapping[str, Any],
    mode: ReplayMode,
    replacements: tuple[ContextReplacement, ...],
) -> None:
    ids = [item.evidence_id for item in replacements]
    if len(ids) != len(set(ids)):
        raise ReplayInputError("context replacements must have unique evidence IDs")
    known = {_required_text(item, "evidence_id") for item in _list_of_mappings(receipt, "evidence")}
    unknown = sorted(set(ids) - known)
    if unknown:
        raise ReplayInputError(f"context replacements reference unknown evidence: {unknown}")
    if mode is ReplayMode.PINNED and replacements:
        raise ReplayInputError("PINNED replay does not permit context replacements")
    if mode is ReplayMode.CORRECTED and not replacements:
        raise ReplayInputError("CORRECTED replay requires at least one context replacement")
    if mode is ReplayMode.COUNTERFACTUAL and len(replacements) != 1:
        raise ReplayInputError("COUNTERFACTUAL replay requires exactly one context replacement")
    original_by_id = {
        _required_text(item, "evidence_id"): _optional_digest(item, "representation_digest")
        for item in _list_of_mappings(receipt, "evidence")
    }
    unchanged = sorted(
        item.evidence_id
        for item in replacements
        if original_by_id[item.evidence_id] == _digest_object(item.representation_digest)
    )
    if unchanged:
        raise ReplayInputError(
            f"context replacements must change their representation digest: {unchanged}"
        )


def _validate_action_input_replacements(
    receipt: Mapping[str, Any],
    mode: ReplayMode,
    context_replacements: tuple[ContextReplacement, ...],
    input_replacements: tuple[ActionInputReplacement, ...],
) -> None:
    action_ids = [item.action_id for item in input_replacements]
    if len(action_ids) != len(set(action_ids)):
        raise ReplayInputError("action input replacements must have unique action IDs")
    known_actions = {
        _required_text(item, "action_id") for item in _list_of_mappings(receipt, "actions")
    }
    unknown_actions = sorted(set(action_ids) - known_actions)
    if unknown_actions:
        raise ReplayInputError(
            f"action input replacements reference unknown actions: {unknown_actions}"
        )
    if mode in {ReplayMode.PINNED, ReplayMode.DRY} and input_replacements:
        raise ReplayInputError(f"{mode.value} replay does not permit action input replacements")

    original_inputs = {
        _required_text(item, "action_id"): _required_digest(item, "input_digest")
        for item in _list_of_mappings(receipt, "actions")
    }
    unchanged_actions = sorted(
        item.action_id
        for item in input_replacements
        if original_inputs[item.action_id] == _digest_object(item.input_digest)
    )
    if unchanged_actions:
        raise ReplayInputError(
            f"action input replacements must change their input digest: {unchanged_actions}"
        )

    replacement_by_id = {item.evidence_id: item for item in context_replacements}
    evidence = {
        _required_text(item, "evidence_id"): item for item in _list_of_mappings(receipt, "evidence")
    }
    referenced: set[str] = set()
    for item in input_replacements:
        unknown_evidence = sorted(set(item.evidence_ids) - set(replacement_by_id))
        if unknown_evidence:
            raise ReplayInputError(
                f"action input replacements must reference context replacements: {unknown_evidence}"
            )
        for evidence_id in item.evidence_ids:
            original = evidence[evidence_id]
            if _required_text(original, "role") != "INPUT":
                raise ReplayInputError(
                    "action input replacements may reference only INPUT evidence"
                )
            context_replacement = replacement_by_id[evidence_id]
            if context_replacement.verification_authority != item.verification_authority:
                raise ReplayInputError("action and context replacement authorities must match")
            referenced.add(evidence_id)

    replaced_inputs = {
        evidence_id
        for evidence_id, item in evidence.items()
        if evidence_id in replacement_by_id and _required_text(item, "role") == "INPUT"
    }
    if referenced != replaced_inputs:
        raise ReplayInputError(
            "every replaced INPUT evidence item must bind an action input replacement"
        )


def _verify_action_digests(bundle: Mapping[str, Any]) -> bool:
    recipe = bundle.get("recipe")
    if not isinstance(recipe, Mapping):
        return False
    raw_tools = recipe.get("tools")
    raw_actions = recipe.get("actions")
    if not isinstance(raw_tools, list) or not isinstance(raw_actions, list):
        return False
    tools = {
        item.get("id"): item
        for item in raw_tools
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }
    for raw in raw_actions:
        if not isinstance(raw, Mapping):
            return False
        tool = tools.get(raw.get("tool_id"))
        if tool is None:
            return False
        recorded = _nested_digest_value(raw, "action_digest")
        material = dict(raw)
        material.pop("action_digest", None)
        expected = _domain_digest(_ACTION_DOMAIN, {"action": material, "tool": tool})
        if recorded is None or not hmac.compare_digest(expected, recorded):
            return False
    return True


def _component_pin(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": _required_text(value, "id"),
        "version": _optional_text(value, "version"),
        "source_digest": _optional_digest(value, "source_digest"),
    }


def _workflow_pin(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": _required_text(value, "id"),
        "version": _optional_text(value, "version"),
    }


def _tool_pin(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        **_component_pin(value),
        "schema_digest": _optional_digest(value, "schema_digest"),
    }


def _read_schema(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ReplayBundleError(f"schema root at {path} must be an object")
    return loaded


def _domain_digest(domain: bytes, value: object) -> str:
    return hashlib.sha256(domain + canonicalize(value)).hexdigest()


def _create_signature(digest: str, key: SigningKey) -> dict[str, str]:
    public = key.private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = key.private_key.sign(_SIGNATURE_DOMAIN + bytes.fromhex(digest))
    return {
        "algorithm": "Ed25519",
        "key_id": key.key_id,
        "public_key": _base64url_encode(public),
        "value": _base64url_encode(signature),
    }


def _verify_signatures(
    integrity: Mapping[str, Any], digest: str
) -> tuple[BundleSignatureResult, ...]:
    raw = integrity.get("signatures", [])
    if not isinstance(raw, list):
        return (BundleSignatureResult("<malformed>", False, "must be an array"),)
    results: list[BundleSignatureResult] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, Mapping):
            results.append(BundleSignatureResult("<malformed>", False, "must be an object"))
            continue
        key_id = item.get("key_id")
        display = key_id if isinstance(key_id, str) else "<malformed>"
        if display in seen:
            results.append(BundleSignatureResult(display, False, "duplicate key_id"))
            continue
        seen.add(display)
        try:
            if item.get("algorithm") != "Ed25519":
                raise ValueError("unsupported signature algorithm")
            public = Ed25519PublicKey.from_public_bytes(
                _base64url_decode(_required_text(item, "public_key"), 32)
            )
            signature = _base64url_decode(_required_text(item, "value"), 64)
            public.verify(signature, _SIGNATURE_DOMAIN + bytes.fromhex(digest))
            results.append(BundleSignatureResult(display, True))
        except (InvalidSignature, ReplayBundleError, ValueError) as exc:
            message = (
                "signature verification failed" if isinstance(exc, InvalidSignature) else str(exc)
            )
            results.append(BundleSignatureResult(display, False, message))
    return tuple(results)


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _base64url_decode(value: str, size: int) -> bytes:
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError as exc:
        raise ReplayBundleError("invalid base64url signature material") from exc
    if len(decoded) != size:
        raise ReplayBundleError("signature material has an invalid length")
    return decoded


def _list_of_mappings(value: Mapping[str, Any], key: str) -> tuple[Mapping[str, Any], ...]:
    selected = value.get(key)
    if not isinstance(selected, list) or not all(isinstance(item, Mapping) for item in selected):
        raise ReplayBundleError(f"{key} must be an array of objects")
    return tuple(selected)


def _required_mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        raise ReplayBundleError(f"{key} must be an object")
    return selected


def _required_text(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise ReplayBundleError(f"{key} must be a non-empty string")
    return selected


def _optional_text(value: Mapping[str, Any], key: str) -> str | None:
    selected = value.get(key)
    if selected is not None and (not isinstance(selected, str) or not selected):
        raise ReplayBundleError(f"{key} must be null or a non-empty string")
    return selected


def _required_bool(value: Mapping[str, Any], key: str) -> bool:
    selected = value.get(key)
    if not isinstance(selected, bool):
        raise ReplayBundleError(f"{key} must be a boolean")
    return selected


def _required_digest(value: Mapping[str, Any], key: str) -> dict[str, str]:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        raise ReplayBundleError(f"{key} must be a digest object")
    algorithm = selected.get("algorithm")
    digest = selected.get("value")
    if algorithm != "sha256" or not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise ReplayBundleError(f"{key} must be a SHA-256 digest")
    return {"algorithm": "sha256", "value": digest}


def _optional_digest(value: Mapping[str, Any], key: str) -> dict[str, str] | None:
    return None if value.get(key) is None else _required_digest(value, key)


def _nested_digest_value(value: Mapping[str, Any], key: str) -> str | None:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        return None
    digest = selected.get("value")
    return digest if isinstance(digest, str) else None


__all__ = [
    "REPLAY_BUNDLE_SPEC_VERSION",
    "BundleSignatureResult",
    "ReplayBundleError",
    "ReplayBundleVerification",
    "build_replay_bundle",
    "load_replay_bundle_schema",
    "replay_bundle_payload_digest",
    "replay_bundle_payload_material",
    "validate_replay_bundle",
    "verify_replay_bundle",
]
