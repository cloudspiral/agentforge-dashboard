from __future__ import annotations

from agentforge.security.redaction import redact


def test_redaction_preserves_authorization_result_but_not_authorization_secret() -> None:
    payload = {
        "authorization_result": "allowed",
        "Authorization": "Bearer private-value",
        "nested": {"api_key": "private-key"},
    }

    assert redact(payload) == {
        "authorization_result": "allowed",
        "Authorization": "[REDACTED]",
        "nested": {"api_key": "[REDACTED]"},
    }
