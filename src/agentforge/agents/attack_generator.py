"""Authorized synthetic-system attack-proposal role."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agentforge.contracts.v1 import ProposedAttackV1
from agentforge.settings import Settings, get_settings

from .base import BaseAgentAdapter


class AttackGeneratorAgent(BaseAgentAdapter[ProposedAttackV1]):
    """Propose a typed action sequence without receiving execution authority."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        prompt_path: Path | str = "prompts/attack-generator.md",
        **adapter_options: Any,
    ) -> None:
        configured = settings or get_settings()
        super().__init__(
            role="attack_generator",
            agent_name="AgentForge Attack Generator",
            output_type=ProposedAttackV1,
            model=configured.openai_attack_model,
            prompt_path=prompt_path,
            max_output_tokens=1200,
            max_turns=1,
            strict_json_schema=False,
            settings=configured,
            **adapter_options,
        )


__all__ = ["AttackGeneratorAgent"]
