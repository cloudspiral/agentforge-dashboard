"""Approved target execution adapters."""

from .base import AttackRunner, TargetExecutionContext
from .composite import CompositeAttackRunner
from .http_runner import HttpAttackRunner
from .playwright_runner import PlaywrightAttackRunner

__all__ = [
    "AttackRunner",
    "CompositeAttackRunner",
    "HttpAttackRunner",
    "PlaywrightAttackRunner",
    "TargetExecutionContext",
]
