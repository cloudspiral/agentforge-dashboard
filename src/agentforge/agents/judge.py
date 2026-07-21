"""Independent evidence-evaluation role with controller-gated escalation."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from agentforge.contracts.v1 import JudgeVerdictV1
from agentforge.settings import Settings, get_settings

from .base import AgentInvocationResult, BaseAgentAdapter


class JudgeAgent(BaseAgentAdapter[JudgeVerdictV1]):
    """Judge frozen evidence with Terra unless the controller explicitly selects Sol."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        prompt_path: Path | str = "prompts/judge.md",
        **adapter_options: Any,
    ) -> None:
        configured = settings or get_settings()
        self.escalation_model = configured.openai_judge_escalation_model
        super().__init__(
            role="judge",
            agent_name="AgentForge Judge",
            output_type=JudgeVerdictV1,
            model=configured.openai_judge_model,
            prompt_path=prompt_path,
            max_output_tokens=1000,
            max_turns=1,
            settings=configured,
            **adapter_options,
        )

    async def run(
        self,
        payload: BaseModel | Mapping[str, Any],
        *,
        campaign_id: str,
        attempt_id: str,
        correlation_id: str | None = None,
        category: str | None = None,
        target_version: str | None = None,
        escalate_to_sol: bool = False,
    ) -> AgentInvocationResult[JudgeVerdictV1]:
        """Evaluate evidence, honoring only the controller's explicit escalation flag."""

        model = self.escalation_model if escalate_to_sol is True else self.model
        return await self._invoke_with_model(
            payload,
            model=model,
            campaign_id=campaign_id,
            attempt_id=attempt_id,
            correlation_id=correlation_id,
            category=category,
            target_version=target_version,
        )

    async def invoke(
        self,
        payload: BaseModel | Mapping[str, Any],
        *,
        campaign_id: str,
        attempt_id: str,
        correlation_id: str | None = None,
        category: str | None = None,
        target_version: str | None = None,
        escalate_to_sol: bool = False,
    ) -> AgentInvocationResult[JudgeVerdictV1]:
        return await self.run(
            payload,
            campaign_id=campaign_id,
            attempt_id=attempt_id,
            correlation_id=correlation_id,
            category=category,
            target_version=target_version,
            escalate_to_sol=escalate_to_sol,
        )


__all__ = ["JudgeAgent"]
