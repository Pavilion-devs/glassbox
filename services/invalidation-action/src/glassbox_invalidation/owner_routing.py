"""DataHub-native owner resolution and idempotent webhook dispatch."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import closing
from typing import Any, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from glassbox_dbom.canonical import canonicalize
from glassbox_policy import InvalidationCampaign

_SCHEMA_VERSION = "glassbox.owner-routing.v1"


class OwnerRoutingError(RuntimeError):
    """Raised when ownership cannot be resolved or a webhook does not accept routing."""


class _Response(Protocol):
    status: int

    def read(self, size: int = -1) -> bytes: ...

    def close(self) -> None: ...


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        del request, file_pointer, code, message, headers, new_url
        return None


def _open_without_redirects(request: Request, *, timeout: float) -> _Response:
    return cast(_Response, build_opener(_NoRedirectHandler).open(request, timeout=timeout))


class DataHubOwnershipWebhookRouter:
    """Resolve native DataHub owners and POST a bounded notification manifest."""

    def __init__(
        self,
        graph: Any,
        *,
        webhook_url: str,
        bearer_token: str | None = None,
        timeout_seconds: float = 10.0,
        allow_insecure_http: bool = False,
        opener: Callable[..., _Response] = _open_without_redirects,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        _validate_webhook_url(webhook_url, allow_insecure_http=allow_insecure_http)
        if bearer_token is not None and not bearer_token:
            raise ValueError("bearer_token must be non-empty when configured")
        self._graph = graph
        self._webhook_url = webhook_url
        self._bearer_token = bearer_token
        self._timeout_seconds = timeout_seconds
        self._opener = opener

    def route(
        self,
        campaign: InvalidationCampaign,
        *,
        idempotency_key: str,
    ) -> tuple[str, ...]:
        if idempotency_key != campaign.campaign_id:
            raise OwnerRoutingError("owner-routing idempotency key must equal the campaign ID")
        owners = self._resolve_owners(campaign.change.entity_urn)
        body = canonicalize(_notification_manifest(campaign, owners))
        headers = {
            "Content-Type": "application/json",
            "Idempotency-Key": idempotency_key,
            "User-Agent": "glassbox-owner-routing/0.1",
        }
        if self._bearer_token is not None:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        request = Request(
            self._webhook_url,
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with closing(self._opener(request, timeout=self._timeout_seconds)) as response:
                if response.status < 200 or response.status >= 300:
                    raise OwnerRoutingError("owner webhook returned a non-success status")
                response.read(4_097)
        except OwnerRoutingError:
            raise
        except (HTTPError, URLError, OSError, TimeoutError) as exc:
            raise OwnerRoutingError("owner webhook request failed") from exc
        return owners

    def _resolve_owners(self, entity_urn: str) -> tuple[str, ...]:
        from datahub.metadata.schema_classes import OwnershipClass

        try:
            ownership = self._graph.get_aspect(entity_urn, OwnershipClass)
        except Exception as exc:
            raise OwnerRoutingError("DataHub ownership read failed") from exc
        if ownership is None:
            return ()
        raw_owners = getattr(ownership, "owners", None)
        if not isinstance(raw_owners, list):
            raise OwnerRoutingError("DataHub ownership aspect has an invalid shape")
        owners: set[str] = set()
        for item in raw_owners:
            owner = getattr(item, "owner", None)
            if not isinstance(owner, str) or not owner.startswith("urn:li:"):
                raise OwnerRoutingError("DataHub ownership entry has an invalid owner URN")
            owners.add(owner)
        if len(owners) > 256:
            raise OwnerRoutingError("DataHub ownership exceeds the bounded routing limit")
        return tuple(sorted(owners))


def _notification_manifest(
    campaign: InvalidationCampaign,
    owners: tuple[str, ...],
) -> dict[str, object]:
    counts: dict[str, int] = {}
    for assessment in campaign.assessments:
        counts[assessment.state.value] = counts.get(assessment.state.value, 0) + 1
    return {
        "schema_version": _SCHEMA_VERSION,
        "idempotency_key": campaign.campaign_id,
        "campaign_id": campaign.campaign_id,
        "incident_urn": campaign.incident_urn,
        "changed_entity_urn": campaign.change.entity_urn,
        "change_event_id": campaign.change.event_id,
        "change_kind": campaign.change.kind.value,
        "occurred_at": campaign.change.occurred_at,
        "policy_version": campaign.policy_version,
        "impact_counts": counts,
        "quarantined_receipt_count": len(campaign.quarantined),
        "owner_urns": list(owners),
    }


def _validate_webhook_url(value: str, *, allow_insecure_http: bool) -> None:
    if not value:
        raise ValueError("webhook_url must be non-empty")
    parsed = urlsplit(value)
    allowed_schemes = {"https"}
    if allow_insecure_http:
        allowed_schemes.add("http")
    if parsed.scheme not in allowed_schemes:
        raise ValueError("webhook_url must use HTTPS")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("webhook_url must have a host and no embedded credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("webhook_url must not contain a query string or fragment")


__all__ = ["DataHubOwnershipWebhookRouter", "OwnerRoutingError"]
