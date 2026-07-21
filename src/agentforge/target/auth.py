"""Bounded test-identity resolution for target runners."""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import SecretStr

from agentforge.settings import Settings
from agentforge.target.profile import TargetProfileV1


class TargetAuthenticationError(ValueError):
    """Raised before browser activity when test authentication is not authorized."""


@dataclass(frozen=True, slots=True)
class TargetCredentials:
    """An in-memory credential pair whose representation never exposes the password."""

    identity_alias: str
    username: str
    password: SecretStr
    role: str

    def __repr__(self) -> str:
        return (
            "TargetCredentials("
            f"identity_alias={self.identity_alias!r}, username={self.username!r}, "
            "password=SecretStr('**********'), "
            f"role={self.role!r})"
        )


APPROVED_TEST_IDENTITY_ALIASES = frozenset({"physician_test"})


def credentials_from_settings(
    *,
    profile: TargetProfileV1,
    settings: Settings,
    identity_alias: str,
    expected_role: str,
) -> TargetCredentials:
    """Resolve the single approved synthetic-test identity without accepting credentials."""

    if identity_alias not in APPROVED_TEST_IDENTITY_ALIASES:
        raise TargetAuthenticationError("unknown test identity alias")
    if (
        profile.authentication.username_env != "TARGET_TEST_USERNAME"
        or profile.authentication.password_env != "TARGET_TEST_PASSWORD"  # noqa: S105
    ):
        raise TargetAuthenticationError("target profile references unsupported credential fields")
    if expected_role not in profile.authentication.supported_roles:
        raise TargetAuthenticationError("requested role is not authorized by the target profile")
    if settings.target_test_role != expected_role:
        raise TargetAuthenticationError("configured test role does not match the requested role")
    username = settings.target_test_username
    password = settings.target_test_password
    if not username or password is None or not password.get_secret_value():
        raise TargetAuthenticationError("target test credentials are not configured")
    return TargetCredentials(
        identity_alias=identity_alias,
        username=username,
        password=password,
        role=expected_role,
    )


__all__ = [
    "APPROVED_TEST_IDENTITY_ALIASES",
    "TargetAuthenticationError",
    "TargetCredentials",
    "credentials_from_settings",
]
