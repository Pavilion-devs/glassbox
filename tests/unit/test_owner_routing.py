"""DataHub owner-resolution and webhook-routing tests."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from urllib.error import URLError
from urllib.request import Request

import pytest

from glassbox_invalidation import DataHubOwnershipWebhookRouter, OwnerRoutingError
from glassbox_policy import (
    ChangeKind,
    EvidenceDependency,
    EvidenceRole,
    EvidenceState,
    NormalizedChange,
    ReceiptDependencyProfile,
    create_campaign,
)

DATASET = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"


def _campaign() -> Any:
    profile = ReceiptDependencyProfile(
        receipt_id="gbx:receipt:sha256:" + "a" * 64,
        document_urn="urn:li:document:glassbox.receipt." + "a" * 64,
        ended_at="2026-08-06T00:00:02Z",
        dependencies=(
            EvidenceDependency(
                evidence_id="evidence-orders-001",
                datahub_urn=DATASET,
                schema_field_urn=f"urn:li:schemaField:({DATASET},revenue)",
                state=EvidenceState.OBSERVED,
                role=EvidenceRole.INPUT,
                observed_at="2026-08-06T00:00:01Z",
                representation_digest="b" * 64,
            ),
        ),
    )
    change = NormalizedChange(
        event_id="mcl-owner-routing-001",
        entity_urn=DATASET,
        aspect_name="schemaMetadata",
        kind=ChangeKind.SCHEMA_FIELD_TYPE_CHANGED,
        occurred_at="2026-08-07T00:00:00Z",
        schema_field_urn=f"urn:li:schemaField:({DATASET},revenue)",
    )
    return create_campaign(change, (profile,))


class FakeGraph:
    def __init__(self, owners: object, *, fail: bool = False) -> None:
        self.owners = owners
        self.fail = fail
        self.reads: list[str] = []

    def get_aspect(self, entity_urn: str, aspect_type: object) -> object:
        del aspect_type
        self.reads.append(entity_urn)
        if self.fail:
            raise ConnectionError("synthetic private graph details")
        return self.owners


class FakeResponse:
    def __init__(self, status: int = 202) -> None:
        self.status = status
        self.closed = False
        self.read_sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return b"accepted"

    def close(self) -> None:
        self.closed = True


def test_router_resolves_native_owners_and_posts_bounded_idempotent_manifest() -> None:
    ownership = SimpleNamespace(
        owners=[
            SimpleNamespace(owner="urn:li:corpuser:zeta"),
            SimpleNamespace(owner="urn:li:corpGroup:commerce"),
            SimpleNamespace(owner="urn:li:corpuser:zeta"),
        ]
    )
    graph = FakeGraph(ownership)
    response = FakeResponse()
    requests: list[tuple[Request, float]] = []

    def open_request(request: Request, *, timeout: float) -> FakeResponse:
        requests.append((request, timeout))
        return response

    campaign = _campaign()
    router = DataHubOwnershipWebhookRouter(
        graph,
        webhook_url="https://notifications.example.test/glassbox",
        bearer_token="private-token",
        timeout_seconds=3.5,
        opener=open_request,
    )
    destinations = router.route(campaign, idempotency_key=campaign.campaign_id)

    assert destinations == (
        "urn:li:corpGroup:commerce",
        "urn:li:corpuser:zeta",
    )
    assert graph.reads == [DATASET]
    request, timeout = requests[0]
    assert timeout == 3.5
    assert request.method == "POST"
    assert request.get_header("Idempotency-key") == campaign.campaign_id
    assert request.get_header("Authorization") == "Bearer private-token"
    payload = json.loads(request.data or b"")
    assert payload["schema_version"] == "glassbox.owner-routing.v1"
    assert payload["owner_urns"] == list(destinations)
    assert payload["quarantined_receipt_count"] == 1
    assert payload["impact_counts"] == {"STALE": 1}
    assert "private-token" not in (request.data or b"").decode()
    assert "receipt_id" not in payload
    assert response.read_sizes == [4_097]
    assert response.closed


def test_router_sends_unowned_campaign_without_inventing_an_owner() -> None:
    request_count = 0

    def open_request(request: Request, *, timeout: float) -> FakeResponse:
        nonlocal request_count
        del request, timeout
        request_count += 1
        return FakeResponse(204)

    campaign = _campaign()
    router = DataHubOwnershipWebhookRouter(
        FakeGraph(None),
        webhook_url="http://localhost:9999/owner-events",
        allow_insecure_http=True,
        opener=open_request,
    )
    assert router.route(campaign, idempotency_key=campaign.campaign_id) == ()
    assert request_count == 1


@pytest.mark.parametrize(
    ("url", "allow_http", "message"),
    [
        ("", False, "non-empty"),
        ("http://example.test/hook", False, "HTTPS"),
        ("https:///hook", False, "host"),
        ("https://user:pass@example.test/hook", False, "credentials"),
        ("https://example.test/hook?secret=x", False, "query"),
        ("https://example.test/hook#fragment", False, "fragment"),
    ],
)
def test_router_rejects_unsafe_webhook_configuration(
    url: str,
    allow_http: bool,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        DataHubOwnershipWebhookRouter(
            FakeGraph(None),
            webhook_url=url,
            allow_insecure_http=allow_http,
        )
    with pytest.raises(ValueError, match="timeout"):
        DataHubOwnershipWebhookRouter(
            FakeGraph(None),
            webhook_url="https://example.test/hook",
            timeout_seconds=0,
        )
    with pytest.raises(ValueError, match="bearer_token"):
        DataHubOwnershipWebhookRouter(
            FakeGraph(None),
            webhook_url="https://example.test/hook",
            bearer_token="",
        )


def test_router_fails_closed_on_identity_ownership_and_transport_errors() -> None:
    campaign = _campaign()
    valid_url = "https://example.test/hook"
    router = DataHubOwnershipWebhookRouter(FakeGraph(None), webhook_url=valid_url)
    with pytest.raises(OwnerRoutingError, match="idempotency"):
        router.route(campaign, idempotency_key="wrong")

    failing_graph = DataHubOwnershipWebhookRouter(FakeGraph(None, fail=True), webhook_url=valid_url)
    with pytest.raises(OwnerRoutingError, match="ownership read"):
        failing_graph.route(campaign, idempotency_key=campaign.campaign_id)

    invalid_shape = DataHubOwnershipWebhookRouter(
        FakeGraph(SimpleNamespace(owners="invalid")), webhook_url=valid_url
    )
    with pytest.raises(OwnerRoutingError, match="invalid shape"):
        invalid_shape.route(campaign, idempotency_key=campaign.campaign_id)

    invalid_owner = DataHubOwnershipWebhookRouter(
        FakeGraph(SimpleNamespace(owners=[SimpleNamespace(owner="email@example.test")])),
        webhook_url=valid_url,
    )
    with pytest.raises(OwnerRoutingError, match="owner URN"):
        invalid_owner.route(campaign, idempotency_key=campaign.campaign_id)

    def reject(request: Request, *, timeout: float) -> FakeResponse:
        del request, timeout
        return FakeResponse(503)

    rejected = DataHubOwnershipWebhookRouter(FakeGraph(None), webhook_url=valid_url, opener=reject)
    with pytest.raises(OwnerRoutingError, match="non-success"):
        rejected.route(campaign, idempotency_key=campaign.campaign_id)

    def unavailable(request: Request, *, timeout: float) -> FakeResponse:
        del request, timeout
        raise URLError("synthetic private endpoint")

    broken = DataHubOwnershipWebhookRouter(
        FakeGraph(None), webhook_url=valid_url, opener=unavailable
    )
    with pytest.raises(OwnerRoutingError, match="request failed"):
        broken.route(campaign, idempotency_key=campaign.campaign_id)


def test_router_enforces_bounded_owner_cardinality() -> None:
    owners = [SimpleNamespace(owner=f"urn:li:corpuser:owner-{index}") for index in range(257)]
    router = DataHubOwnershipWebhookRouter(
        FakeGraph(SimpleNamespace(owners=owners)),
        webhook_url="https://example.test/hook",
    )
    campaign = _campaign()
    with pytest.raises(OwnerRoutingError, match="bounded routing limit"):
        router.route(campaign, idempotency_key=campaign.campaign_id)
