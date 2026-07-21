"""Target endpoint aliases and bounded runtime-version discovery."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urljoin, urlparse

import httpx

from agentforge.security.allowlist import TargetRejected, require_allowed_url
from agentforge.target.profile import ResolvedTargetAlias, TargetProfileV1

EndpointSurface = Literal["status", "ui"]


@dataclass(frozen=True, slots=True)
class ResolvedEndpoint:
    endpoint_id: str
    method: str
    surface: EndpointSurface
    path: str
    url: str


@dataclass(frozen=True, slots=True)
class DiscoveredTargetVersion:
    version: str
    endpoint_id: str
    status_code: int


_ENDPOINT_ALIASES: dict[str, tuple[str, EndpointSurface, str]] = {
    "status_health": ("GET", "status", "/health"),
    "status_ready": ("GET", "status", "/ready"),
    "copilot_chat_proxy": (
        "POST",
        "ui",
        "/interface/patient_file/clinical_copilot/proxy.php",
    ),
    "document_stage": (
        "POST",
        "ui",
        "/interface/patient_file/clinical_copilot/ingestion_stage.php",
    ),
    "document_reject": (
        "POST",
        "ui",
        "/interface/patient_file/clinical_copilot/ingestion_reject.php",
    ),
}


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlparse(url)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port


def same_origin(left: str, right: str) -> bool:
    """Return whether two absolute HTTP URLs share an exact browser origin."""

    return _origin(left) == _origin(right)


def resolve_endpoint(
    *,
    profile: TargetProfileV1,
    target_alias: ResolvedTargetAlias,
    endpoint_id: str,
    requested_method: str | None = None,
) -> ResolvedEndpoint:
    """Resolve an allowlisted symbolic endpoint; raw URL input is never accepted."""

    definition = _ENDPOINT_ALIASES.get(endpoint_id)
    if definition is None:
        raise TargetRejected("unknown target endpoint alias")
    method, surface, path = definition
    if requested_method is not None and requested_method != method:
        raise TargetRejected("requested method does not match the endpoint alias")
    if path in profile.prohibited_endpoints:
        raise TargetRejected("endpoint is prohibited by the target profile")
    if not any(
        rule.method == method and rule.surface == surface and rule.path == path
        for rule in profile.allowed_endpoints
    ):
        raise TargetRejected("endpoint alias is not enabled by the target profile")

    base_url = target_alias.status_url if surface == "status" else target_alias.base_url
    url = require_allowed_url(
        path,
        target_alias.expected_hosts,
        base_url=base_url,
        allow_http=True,
    )
    if not same_origin(url, base_url):
        raise TargetRejected("resolved endpoint does not remain on its approved origin")
    return ResolvedEndpoint(endpoint_id, method, surface, path, url)


async def discover_target_version(
    *,
    client: httpx.AsyncClient,
    profile: TargetProfileV1,
    target_alias: ResolvedTargetAlias,
    max_response_bytes: int = 65_536,
) -> DiscoveredTargetVersion:
    """Read the configured version field from the approved health endpoint only."""

    source = profile.runtime_version_source
    endpoint = resolve_endpoint(
        profile=profile,
        target_alias=target_alias,
        endpoint_id="status_health",
        requested_method=source.method,
    )
    if not 0 < max_response_bytes <= 1_000_000:
        raise TargetRejected("target version byte limit is invalid")
    raw = bytearray()
    async with client.stream(source.method, endpoint.url, follow_redirects=False) as response:
        if 300 <= response.status_code < 400:
            raise TargetRejected("target version endpoint attempted a redirect")
        if response.status_code >= 400:
            raise TargetRejected("target version endpoint returned an unsuccessful status")
        if not same_origin(str(response.url), endpoint.url):
            raise TargetRejected("target version response changed origin")
        async for chunk in response.aiter_bytes():
            if len(raw) + len(chunk) > max_response_bytes:
                raise TargetRejected("target version response exceeded the configured byte limit")
            raw.extend(chunk)
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TargetRejected("target version response was not valid JSON") from exc
    value = payload.get(source.json_field) if isinstance(payload, dict) else None
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise TargetRejected("target version field was missing or invalid")
    return DiscoveredTargetVersion(value.strip(), endpoint.endpoint_id, response.status_code)


def approved_browser_url(url: str, *, target_alias: ResolvedTargetAlias) -> bool:
    """Allow browser-local schemes or the exact OpenEMR UI origin."""

    parsed = urlparse(url)
    if parsed.scheme in {"about", "blob", "data"}:
        return True
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
        return False
    return same_origin(url, target_alias.base_url)


def join_profile_path(base_url: str, path: str) -> str:
    """Join a profile-owned path while preserving its configured origin."""

    joined = urljoin(f"{base_url.rstrip('/')}/", path.lstrip("/"))
    if not same_origin(joined, base_url):
        raise TargetRejected("profile path escaped the target origin")
    return joined


__all__ = [
    "DiscoveredTargetVersion",
    "ResolvedEndpoint",
    "approved_browser_url",
    "discover_target_version",
    "join_profile_path",
    "resolve_endpoint",
    "same_origin",
]
