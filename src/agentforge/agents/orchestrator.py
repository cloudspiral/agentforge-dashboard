"""Campaign-objective recommendation role."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agentforge.contracts.v1 import OrchestratorDecisionV2
from agentforge.settings import Settings, get_settings

from .base import BaseAgentAdapter


class OrchestratorAgent(BaseAgentAdapter[OrchestratorDecisionV2]):
    """Choose the next objective or stop within controller-supplied bounds."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        prompt_path: Path | str = "prompts/orchestrator.md",
        **adapter_options: Any,
    ) -> None:
        configured = settings or get_settings()
        super().__init__(
            role="orchestrator",
            agent_name="AgentForge Orchestrator",
            output_type=OrchestratorDecisionV2,
            model=configured.openai_orchestrator_model,
            prompt_path=prompt_path,
            max_output_tokens=900,
            max_turns=1,
            strict_json_schema=False,
            settings=configured,
            **adapter_options,
        )


__all__ = ["OrchestratorAgent"]
