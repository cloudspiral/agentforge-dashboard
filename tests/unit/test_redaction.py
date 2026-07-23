from __future__ import annotations

from agentforge.security.redaction import redact


def test_redaction_treats_authorization_shaped_fields_as_sensitive() -> None:
    payload = {
        "authorization_result": "allowed",
        "Authorization": "Bearer private-value",
        "nested": {"api_key": "private-key"},
    }

    assert redact(payload) == {
        "authorization_result": "[REDACTED]",
        "Authorization": "[REDACTED]",
        "nested": {"api_key": "[REDACTED]"},
    }
