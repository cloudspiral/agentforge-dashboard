"""Frozen-finding documentation role."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agentforge.contracts.v1 import VulnerabilityReportV1
from agentforge.settings import Settings, get_settings

from .base import BaseAgentAdapter


class DocumentationAgent(BaseAgentAdapter[VulnerabilityReportV1]):
    """Create the canonical initial report without target or lifecycle authority."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        prompt_path: Path | str = "prompts/documentation.md",
        **adapter_options: Any,
    ) -> None:
        configured = settings or get_settings()
        super().__init__(
            role="documentation",
            agent_name="AgentForge Documentation",
            output_type=VulnerabilityReportV1,
            model=configured.openai_documentation_model,
            prompt_path=prompt_path,
            max_output_tokens=1800,
            max_turns=1,
            strict_json_schema=False,
            settings=configured,
            **adapter_options,
        )


__all__ = ["DocumentationAgent"]
