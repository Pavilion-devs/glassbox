from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_oauth_identity_bridge_preserves_security_order() -> None:
    caddyfile = (ROOT / "deploy" / "production" / "Caddyfile").read_text()
    fallback = caddyfile[caddyfile.index("\thandle @console_host {") :]

    assert "\t\troute {" in fallback
    assert fallback.index("request_header -X-Auth-Request-User") < fallback.index(
        "forward_auth oauth2-proxy:4180"
    )
    assert fallback.index("forward_auth oauth2-proxy:4180") < fallback.index(
        "reverse_proxy console:3000"
    )
    assert "copy_headers X-Auth-Request-User X-Auth-Request-Email" in fallback


def test_non_human_endpoints_bypass_oauth() -> None:
    caddyfile = (ROOT / "deploy" / "production" / "Caddyfile").read_text()
    oauth_fallback = caddyfile.index("forward_auth oauth2-proxy:4180")

    assert caddyfile.index("handle /healthz") < oauth_fallback
    assert caddyfile.index("@otlp path /v1/traces") < oauth_fallback
    assert "redir * /oauth2/sign_in?rd={uri}" in caddyfile


def test_public_surface_is_allowlisted_away_from_operator_and_control_routes() -> None:
    caddyfile = (ROOT / "deploy" / "production" / "Caddyfile").read_text()
    public_surface = caddyfile[
        caddyfile.index("\t@public_surface {") : caddyfile.index("\t@public_unknown")
    ]

    assert "host {$GLASSBOX_PUBLIC_DOMAIN}" in public_surface
    assert "/docs /docs/* /architecture" in public_surface
    assert "/api" not in public_surface
    assert "/settings" not in public_surface
    assert "request_header -X-Auth-Request-User" in public_surface
    assert "@public_unknown host {$GLASSBOX_PUBLIC_DOMAIN}" in caddyfile
    assert "@console_host host {$GLASSBOX_CONSOLE_DOMAIN}" in caddyfile
    assert caddyfile.rstrip().endswith("}")
    assert "respond 421" in caddyfile


def test_receiver_reads_the_control_plane_organization() -> None:
    compose = (ROOT / "deploy" / "production" / "compose.yml").read_text()
    receiver = compose[compose.index("  receiver:\n") :]

    assert "- --control-database" in receiver
    assert "- --control-organization" in receiver
    assert "- ${GLASSBOX_ORGANIZATION:-default}" in receiver


def test_compose_binds_public_and_console_hosts_to_distinct_boundaries() -> None:
    compose = (ROOT / "deploy" / "production" / "compose.yml").read_text()

    assert (
        "GLASSBOX_PUBLIC_DOMAIN: ${GLASSBOX_PUBLIC_DOMAIN:?set GLASSBOX_PUBLIC_DOMAIN}" in compose
    )
    assert (
        "GLASSBOX_CONSOLE_DOMAIN: ${GLASSBOX_CONSOLE_DOMAIN:?set GLASSBOX_CONSOLE_DOMAIN}"
        in compose
    )
    assert "GLASSBOX_PUBLIC_HOSTS: ${GLASSBOX_PUBLIC_DOMAIN:?set GLASSBOX_PUBLIC_DOMAIN}" in compose
    assert (
        "https://${GLASSBOX_CONSOLE_DOMAIN:?set GLASSBOX_CONSOLE_DOMAIN}/oauth2/callback" in compose
    )
