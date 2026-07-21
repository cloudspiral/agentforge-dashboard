from pathlib import Path

import pytest

from agentforge.evaluation import load_judge_rubric, load_seed_cases, load_taxonomy
from agentforge.settings import Settings
from agentforge.target import load_target_profile

ROOT = Path(__file__).parents[2]


def test_checked_in_configuration_validates() -> None:
    taxonomy = load_taxonomy(ROOT / "config/attack-taxonomy.yaml")
    rubric = load_judge_rubric(ROOT / "config/judge-rubric.yaml")
    profile = load_target_profile(ROOT / "config/target-profile.yaml")
    seeds = load_seed_cases(ROOT / "evals/seed-cases")

    assert len(taxonomy.categories) == 6
    assert set(rubric.categories) == {
        "prompt_injection",
        "data_exfiltration",
        "tool_misuse",
    }
    assert len(profile.profile_hash) == 64
    assert len(seeds) == 6


def test_local_alias_resolves_only_from_settings() -> None:
    profile = load_target_profile(ROOT / "config/target-profile.yaml")
    settings = Settings(
        target_base_url="http://localhost:8300",
        target_api_base_url="http://localhost:8001",
        target_verify_tls=False,
    )

    alias = profile.resolve_alias("local", settings)

    assert alias.base_url == "http://localhost:8300"
    assert alias.status_url == "http://localhost:8001"
    assert alias.verify_tls is False


def test_unknown_target_alias_is_rejected() -> None:
    profile = load_target_profile(ROOT / "config/target-profile.yaml")
    with pytest.raises(ValueError, match="unknown target alias"):
        profile.resolve_alias("arbitrary-host", Settings())
