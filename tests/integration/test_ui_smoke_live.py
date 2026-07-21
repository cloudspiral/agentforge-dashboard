from __future__ import annotations

from pathlib import Path

import pytest

from agentforge.runners.playwright_runner import run_ui_smoke
from agentforge.settings import get_settings
from agentforge.target.profile import load_target_profile

ROOT = Path(__file__).parents[2]

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not get_settings().run_live_e2e,
        reason="set RUN_LIVE_E2E=1 to opt in to the local browser smoke test",
    ),
]


@pytest.mark.asyncio
async def test_local_authenticated_ui_smoke() -> None:
    settings = get_settings()
    profile_path = (
        settings.target_profile_path
        if settings.target_profile_path.is_absolute()
        else ROOT / settings.target_profile_path
    )
    artifacts_dir = (
        settings.artifacts_dir
        if settings.artifacts_dir.is_absolute()
        else ROOT / settings.artifacts_dir
    )

    result = await run_ui_smoke(
        loaded_profile=load_target_profile(profile_path),
        settings=settings,
        target_alias="local",
        repository_root=ROOT,
        artifacts_dir=artifacts_dir,
        timeout_seconds=settings.target_ui_smoke_timeout_seconds,
        headless=settings.target_ui_smoke_headless,
        screenshot_on_failure=settings.target_ui_smoke_screenshot_on_failure,
    )

    assert result.failed_step is None, result.model_dump_json()
    assert result.navigation_succeeded is True
    assert result.login_succeeded is True
    assert result.patient_selected is True
    assert result.copilot_opened is True
