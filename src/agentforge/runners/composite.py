"""Deterministic selection between status HTTP and browser runners."""

from __future__ import annotations

from agentforge.contracts.v1.actions import (
    AuthenticateActionV1,
    InvokeApprovedApiRequestActionV1,
    SelectSyntheticPatientActionV1,
    SendChatMessageActionV1,
    UploadApprovedFixtureActionV1,
)
from agentforge.contracts.v1.campaign import ProposedAttackV1
from agentforge.contracts.v1.common import utc_now
from agentforge.contracts.v1.evidence import AttackEvidenceV1
from agentforge.orchestration.execution_gate import ValidatedAttackV1

from .base import (
    EvidenceRecorder,
    RunnerActionRejected,
    TargetExecutionContext,
    require_validated_attack,
)
from .http_runner import HttpAttackRunner
from .playwright_runner import PlaywrightAttackRunner


class CompositeAttackRunner:
    """Choose one runner before execution so a proposal cannot cross surfaces mid-run."""

    def __init__(
        self,
        *,
        http_runner: HttpAttackRunner | None = None,
        playwright_runner: PlaywrightAttackRunner | None = None,
    ) -> None:
        self.http_runner = http_runner or HttpAttackRunner()
        self.playwright_runner = playwright_runner or PlaywrightAttackRunner()

    async def execute(
        self,
        attack: ValidatedAttackV1,
        context: TargetExecutionContext,
    ) -> AttackEvidenceV1:
        proposal = require_validated_attack(attack, context)
        ui_actions = any(
            isinstance(
                action,
                (
                    AuthenticateActionV1,
                    SelectSyntheticPatientActionV1,
                    SendChatMessageActionV1,
                    UploadApprovedFixtureActionV1,
                ),
            )
            for action in proposal.ordered_actions
        )
        api_actions = [
            action
            for action in proposal.ordered_actions
            if isinstance(action, InvokeApprovedApiRequestActionV1)
        ]
        if ui_actions and api_actions:
            return self._rejected_mixed_surface(proposal, context)
        if api_actions:
            return await self.http_runner.execute(attack, context)
        return await self.playwright_runner.execute(attack, context)

    @staticmethod
    def _rejected_mixed_surface(
        attack: ProposedAttackV1,
        context: TargetExecutionContext,
    ) -> AttackEvidenceV1:
        recorder = EvidenceRecorder(context)
        failure = RunnerActionRejected(
            "a proposal cannot mix direct API actions with stateful browser UI actions"
        )
        first = attack.ordered_actions[0]
        timestamp = utc_now()
        recorder.add_action(
            sequence_index=0,
            action=first,
            started_at=timestamp,
            status=failure.status,
            summary=failure.public_message,
        )
        recorder.add_error(failure)
        for index, action in enumerate(attack.ordered_actions[1:], start=1):
            recorder.add_skipped(index, action)
        return recorder.finalize()


__all__ = ["CompositeAttackRunner"]
