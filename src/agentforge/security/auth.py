from __future__ import annotations

import hmac

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import SecretStr

_dashboard_basic = HTTPBasic(auto_error=False)


def _matches(candidate: str | None, expected: SecretStr | None) -> bool:
    return bool(
        candidate
        and expected
        and expected.get_secret_value()
        and hmac.compare_digest(candidate, expected.get_secret_value())
    )


def require_bearer(expected: SecretStr | None):
    def dependency(authorization: str | None = Header(default=None)) -> None:
        candidate = None
        if authorization and authorization.lower().startswith("bearer "):
            candidate = authorization[7:].strip()
        if not _matches(candidate, expected):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")

    return dependency


def require_webhook(expected: SecretStr | None):
    def dependency(x_agentforge_webhook_secret: str | None = Header(default=None)) -> None:
        if not _matches(x_agentforge_webhook_secret, expected):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid webhook")

    return dependency


def require_dashboard_auth(
    request: Request,
    credentials: HTTPBasicCredentials | None = Depends(_dashboard_basic),
) -> None:
    settings = request.app.state.settings
    if getattr(settings, "environment", "development") != "production":
        return

    expected_username = getattr(settings, "dashboard_auth_username", None)
    expected_password = getattr(settings, "dashboard_auth_password", None)
    username_matches = bool(
        credentials
        and expected_username
        and hmac.compare_digest(credentials.username, expected_username)
    )
    password_matches = bool(
        credentials
        and expected_password
        and hmac.compare_digest(
            credentials.password,
            expected_password.get_secret_value(),
        )
    )
    if not username_matches or not password_matches:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid dashboard credentials",
            headers={"WWW-Authenticate": 'Basic realm="AgentForge"'},
        )
