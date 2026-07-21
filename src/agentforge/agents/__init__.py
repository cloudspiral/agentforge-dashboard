"""Four bounded OpenAI Agents SDK roles used by AgentForge's controller."""

from .attack_generator import AttackGeneratorAgent
from .base import (
    AgentInvocationResult,
    AgentUsage,
    BaseAgentAdapter,
    ModelPrice,
    PricingCatalog,
    VersionedPrompt,
    load_versioned_prompt,
)
from .documentation import DocumentationAgent
from .judge import JudgeAgent
from .orchestrator import OrchestratorAgent

__all__ = [
    "AgentInvocationResult",
    "AgentUsage",
    "AttackGeneratorAgent",
    "BaseAgentAdapter",
    "DocumentationAgent",
    "JudgeAgent",
    "ModelPrice",
    "OrchestratorAgent",
    "PricingCatalog",
    "VersionedPrompt",
    "load_versioned_prompt",
]
