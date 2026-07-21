from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, status
from pydantic import SecretStr


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
