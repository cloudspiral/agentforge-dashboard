"""Target endpoint aliases and bounded runtime-version discovery."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from time import monotonic
from typing import Literal
from urllib.parse import urljoin, urlparse, urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field

from agentforge.security.allowlist import TargetRejected, require_allowed_url
from agentforge.settings import Settings
from agentforge.target.profile import LoadedTargetProfile, ResolvedTargetAlias, TargetProfileV1

EndpointSurface = Literal["status", "ui", "agent_service"]
PENDING_TARGET_VERSION = "pending-discovery"
LOCAL_UNKNOWN_TARGET_VERSION = "local-unknown"
UNRESOLVED_TARGET_VERSIONS = (
    LOCAL_UNKNOWN_TARGET_VERSION,
    PENDING_TARGET_VERSION,
)


def target_version_is_resolved(value: str | None) -> bool:
    return bool(value and value not in UNRESOLVED_TARGET_VERSIONS)


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


class TargetProbeResult(BaseModel):
    """Sanitized, typed outcome from one bounded read-only target request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_alias: str
    reachable: bool
    sanitized_base_url: str | None
    http_status: int | None
    target_version: str | None
    latency_ms: float = Field(ge=0)
    timestamp: datetime
    error_code: str | None
    error_message: str | None


@dataclass(frozen=True, slots=True)
class _BoundedVersionResponse:
    endpoint_id: str
    status_code: int
    body: bytes


class _TargetResponseRejected(TargetRejected):
    def __init__(self, code: str, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


_ENDPOINT_ALIASES: dict[str, tuple[str, EndpointSurface, str]] = {
    "status_health": ("GET", "status", "/health"),
    "status_ready": ("GET", "status", "/ready"),
    "agent_metrics": ("GET", "agent_service", "/metrics"),
    "agent_openapi": ("GET", "agent_service", "/openapi.json"),
    "agent_chat": ("POST", "agent_service", "/agent/chat"),
    "agent_document_extract": (
        "POST",
        "agent_service",
        "/agent/document-ingestions/extract",
    ),
    "agent_document_validate_confirmation": (
        "POST",
        "agent_service",
        "/agent/document-ingestions/validate-confirmation",
    ),
    "agent_evidence_retrieve": (
        "POST",
        "agent_service",
        "/agent/evidence/retrieve",
    ),
    "agent_document_outcome": (
        "POST",
        "agent_service",
        "/agent/document-ingestions/outcome",
    ),
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
    "copilot_source": (
        "POST",
        "ui",
        "/interface/patient_file/clinical_copilot/source.php",
    ),
    "copilot_evidence_region": (
        "POST",
        "ui",
        "/interface/patient_file/clinical_copilot/evidence_region.php",
    ),
    "document_status": (
        "POST",
        "ui",
        "/interface/patient_file/clinical_copilot/ingestion_status.php",
    ),
    "document_confirm": (
        "POST",
        "ui",
        "/interface/patient_file/clinical_copilot/ingestion_confirm.php",
    ),
    "staged_document": (
        "POST",
        "ui",
        "/interface/patient_file/clinical_copilot/staged_document.php",
    ),
    "staged_evidence_region": (
        "POST",
        "ui",
        "/interface/patient_file/clinical_copilot/staged_evidence_region.php",
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

    base_url = (
        target_alias.status_url if surface in {"status", "agent_service"} else target_alias.base_url
    )
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

    response = await _read_bounded_version_response(
        client=client,
        profile=profile,
        target_alias=target_alias,
        max_response_bytes=max_response_bytes,
    )
    try:
        payload = json.loads(response.body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TargetRejected("target version response was not valid JSON") from exc
    value = (
        payload.get(profile.runtime_version_source.json_field)
        if isinstance(payload, dict)
        else None
    )
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise TargetRejected("target version field was missing or invalid")
    return DiscoveredTargetVersion(value.strip(), response.endpoint_id, response.status_code)


async def _read_bounded_version_response(
    *,
    client: httpx.AsyncClient,
    profile: TargetProfileV1,
    target_alias: ResolvedTargetAlias,
    max_response_bytes: int,
    timeout_seconds: float | None = None,
) -> _BoundedVersionResponse:
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
    request_options: dict[str, object] = {"follow_redirects": False}
    if timeout_seconds is not None:
        request_options["timeout"] = timeout_seconds
    async with client.stream(source.method, endpoint.url, **request_options) as response:
        if 300 <= response.status_code < 400:
            location = response.headers.get("location")
            if location and not same_origin(urljoin(endpoint.url, location), endpoint.url):
                raise _TargetResponseRejected(
                    "cross_host_redirect",
                    "target probe rejected a redirect to a different host",
                    status_code=response.status_code,
                )
            raise _TargetResponseRejected(
                "redirect_rejected",
                "target probe rejected an unexpected redirect",
                status_code=response.status_code,
            )
        if response.status_code >= 400:
            if response.status_code in {401, 403}:
                raise _TargetResponseRejected(
                    "authentication_required",
                    "target health endpoint requires authentication",
                    status_code=response.status_code,
                )
            raise _TargetResponseRejected(
                "http_error",
                "target health endpoint returned an unsuccessful status",
                status_code=response.status_code,
            )
        if not same_origin(str(response.url), endpoint.url):
            raise _TargetResponseRejected(
                "cross_host_response",
                "target probe response changed host",
                status_code=response.status_code,
            )
        async for chunk in response.aiter_bytes():
            if len(raw) + len(chunk) > max_response_bytes:
                raise _TargetResponseRejected(
                    "response_too_large",
                    "target health response exceeded the configured byte limit",
                    status_code=response.status_code,
                )
            raw.extend(chunk)
    return _BoundedVersionResponse(endpoint.endpoint_id, response.status_code, bytes(raw))


def _extract_version(raw: bytes, json_field: str) -> str | None:
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    value = payload.get(json_field) if isinstance(payload, dict) else None
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        return None
    return value.strip()


def _sanitized_origin(url: str) -> str | None:
    """Return only scheme, host, and port; credentials, paths, and queries are omitted."""

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        return None
    display_host = f"[{hostname}]" if ":" in hostname else hostname
    port_suffix = f":{port}" if port is not None else ""
    return f"{parsed.scheme.lower()}://{display_host}{port_suffix}"


async def probe_target(
    *,
    loaded_profile: LoadedTargetProfile,
    settings: Settings,
    target_alias: str,
    timeout_seconds: float,
    max_response_bytes: int = 65_536,
    transport: httpx.AsyncBaseTransport | None = None,
) -> TargetProbeResult:
    """Resolve and probe one configured target without credentials, redirects, or mutation."""

    timestamp = datetime.now(UTC)
    started = monotonic()
    sanitized_base_url: str | None = None

    def outcome(
        *,
        reachable: bool,
        http_status: int | None = None,
        target_version: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> TargetProbeResult:
        return TargetProbeResult(
            target_alias=target_alias,
            reachable=reachable,
            sanitized_base_url=sanitized_base_url,
            http_status=http_status,
            target_version=target_version,
            latency_ms=round((monotonic() - started) * 1000, 3),
            timestamp=timestamp,
            error_code=error_code,
            error_message=error_message,
        )

    if not 0.1 <= timeout_seconds <= 30:
        return outcome(
            reachable=False,
            error_code="target_configuration_error",
            error_message="target probe timeout is outside the approved range",
        )
    if target_alias not in loaded_profile.profile.aliases:
        return outcome(
            reachable=False,
            error_code="target_alias_not_found",
            error_message="target alias is not present in the configured target profile",
        )
    try:
        resolved_alias = loaded_profile.resolve_alias(target_alias, settings)
    except (AttributeError, ValueError):
        return outcome(
            reachable=False,
            error_code="target_configuration_error",
            error_message="required target URL configuration is missing or invalid",
        )

    sanitized_base_url = _sanitized_origin(resolved_alias.base_url)
    try:
        require_allowed_url(
            resolved_alias.base_url,
            resolved_alias.expected_hosts,
            allow_http=True,
        )
        sanitized_base_url = _sanitized_origin(resolved_alias.status_url)
        require_allowed_url(
            resolved_alias.status_url,
            resolved_alias.expected_hosts,
            allow_http=True,
        )
    except TargetRejected:
        return outcome(
            reachable=False,
            error_code="target_url_rejected",
            error_message="configured target URL was rejected by approved-target validation",
        )

    try:
        async with httpx.AsyncClient(
            transport=transport,
            timeout=timeout_seconds,
            verify=resolved_alias.verify_tls,
            follow_redirects=False,
            trust_env=False,
            headers={"accept": "application/json"},
        ) as client:
            response = await _read_bounded_version_response(
                client=client,
                profile=loaded_profile.profile,
                target_alias=resolved_alias,
                max_response_bytes=max_response_bytes,
                timeout_seconds=timeout_seconds,
            )
    except _TargetResponseRejected as exc:
        return outcome(
            reachable=False,
            http_status=exc.status_code,
            error_code=exc.code,
            error_message=str(exc),
        )
    except httpx.TimeoutException:
        return outcome(
            reachable=False,
            error_code="timeout",
            error_message="target probe timed out",
        )
    except httpx.ConnectError:
        return outcome(
            reachable=False,
            error_code="connection_failed",
            error_message="target connection failed",
        )
    except httpx.RequestError:
        return outcome(
            reachable=False,
            error_code="request_failed",
            error_message="target probe request failed",
        )
    except TargetRejected:
        return outcome(
            reachable=False,
            error_code="target_endpoint_rejected",
            error_message="configured target health endpoint was rejected",
        )

    return outcome(
        reachable=True,
        http_status=response.status_code,
        target_version=_extract_version(
            response.body,
            loaded_profile.profile.runtime_version_source.json_field,
        ),
    )


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
    "TargetProbeResult",
    "approved_browser_url",
    "discover_target_version",
    "join_profile_path",
    "probe_target",
    "resolve_endpoint",
    "same_origin",
]
