from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)


class CatalogModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


Identifier = Annotated[
    str,
    StringConstraints(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$"),
]
BoundedText = Annotated[str, StringConstraints(min_length=1, max_length=4_000)]


class TaxonomySubcategoryV1(CatalogModel):
    id: Identifier
    description: BoundedText
    applicable_surfaces: list[str] = Field(min_length=1)
    difficulty: Literal["low", "medium", "high"]


class TaxonomyCategoryV1(CatalogModel):
    id: Identifier
    description: BoundedText
    applicable_surfaces: list[str] = Field(min_length=1)
    potential_impact: BoundedText
    exploitability: Literal["low", "medium", "high"]
    defense_assumptions: list[Identifier] = Field(min_length=1)
    coverage_priority: Literal["low", "medium", "high", "critical"]
    expected_security_invariants: list[BoundedText] = Field(min_length=1)
    owasp_web: list[str] = Field(min_length=1)
    owasp_llm: list[str] = Field(min_length=1)
    deterministic_signals: list[Identifier] = Field(min_length=1)
    human_review_common: bool
    subcategories: list[TaxonomySubcategoryV1] = Field(min_length=1)

    @field_validator("subcategories")
    @classmethod
    def subcategory_ids_are_unique(
        cls, value: list[TaxonomySubcategoryV1]
    ) -> list[TaxonomySubcategoryV1]:
        ids = [item.id for item in value]
        if len(ids) != len(set(ids)):
            raise ValueError("subcategory IDs must be unique within a category")
        return value


class TaxonomyV1(CatalogModel):
    schema_version: Literal["1.0"]
    taxonomy_version: str
    owasp_web_version: str
    owasp_llm_version: str
    categories: list[TaxonomyCategoryV1]

    @model_validator(mode="after")
    def all_assignment_families_are_present(self) -> TaxonomyV1:
        required = {
            "prompt_injection",
            "data_exfiltration",
            "state_corruption",
            "tool_misuse",
            "denial_of_service",
            "identity_role_exploitation",
        }
        found = {category.id for category in self.categories}
        if found != required:
            raise ValueError(f"taxonomy families must be exactly {sorted(required)}")
        return self


class JudgeCategoryV1(CatalogModel):
    safe_behavior: BoundedText
    exploit_confirmed: BoundedText
    partial_signal: BoundedText
    inconclusive: BoundedText
    deterministic_overrides: list[Identifier]
    severity_rules: dict[str, str]
    exploitability_rules: dict[str, str]
    human_escalation: list[Identifier]


class JudgeRubricV1(CatalogModel):
    schema_version: Literal["1.0"]
    rubric_version: str
    confidence_thresholds: dict[str, float | bool]
    default_required_reproductions: int = Field(ge=1, le=10)
    single_run_confirmation: dict[str, object]
    global_rules: list[BoundedText]
    categories: dict[str, JudgeCategoryV1]

    @model_validator(mode="after")
    def initial_categories_are_covered(self) -> JudgeRubricV1:
        required = {"prompt_injection", "data_exfiltration", "tool_misuse"}
        if set(self.categories) != required:
            raise ValueError("Judge rubric must cover exactly the initial three categories")
        return self


class SeedResetActionV1(CatalogModel):
    type: Literal["reset_session"]


class SeedAuthenticateActionV1(CatalogModel):
    type: Literal["authenticate"]


class SeedSelectPatientActionV1(CatalogModel):
    type: Literal["select_patient"]
    patient: Literal["patient_a", "patient_b"]


class SeedSendMessageActionV1(CatalogModel):
    type: Literal["send_chat_message"]
    message: BoundedText


class SeedWaitActionV1(CatalogModel):
    type: Literal["wait_for_response"]
    timeout_seconds: float = Field(gt=0, le=120)


class SeedCollectEvidenceActionV1(CatalogModel):
    type: Literal["collect_evidence"]


SeedActionV1 = Annotated[
    SeedResetActionV1
    | SeedAuthenticateActionV1
    | SeedSelectPatientActionV1
    | SeedSendMessageActionV1
    | SeedWaitActionV1
    | SeedCollectEvidenceActionV1,
    Field(discriminator="type"),
]


class SeedClassificationV1(CatalogModel):
    boundary: Identifier
    invariant: Identifier
    regression_risk: Literal["low", "medium", "high", "critical"]


class SeedSetupV1(CatalogModel):
    role: Identifier
    selected_patient: Literal["patient_a", "patient_b"]
    fresh_session: bool


class SeedAssertionV1(CatalogModel):
    kind: Identifier
    source: Identifier | None = None
    value_ref: str | None = None
    expected_ref: Identifier | None = None
    patient_ref: Identifier | None = None
    value: int | str | None = None


class SeedJudgeCriteriaV1(CatalogModel):
    confirmed_if: Identifier
    partial_if: Identifier


class SeedDefaultsV1(CatalogModel):
    severity: Literal["informational", "low", "medium", "high", "critical"]
    exploitability: Literal["low", "medium", "high"]


class SeedCaseV1(CatalogModel):
    schema_version: Literal["1.0"]
    id: Identifier
    name: BoundedText
    category: Literal["prompt_injection", "data_exfiltration", "tool_misuse"]
    subcategory: Identifier
    owasp_web: list[str] = Field(min_length=1)
    owasp_llm: list[str] = Field(min_length=1)
    surface: Literal["api", "ui"]
    classification: SeedClassificationV1
    setup: SeedSetupV1
    actions: list[SeedActionV1] = Field(min_length=1, max_length=30)
    expected_safe_behavior: BoundedText
    exploit_signals: list[Identifier] = Field(min_length=1)
    deterministic_assertions: list[SeedAssertionV1] = Field(min_length=1)
    judge: SeedJudgeCriteriaV1
    defaults: SeedDefaultsV1
    becomes_regression_if_confirmed: bool

    @model_validator(mode="after")
    def sequence_has_safety_bookends(self) -> SeedCaseV1:
        action_types = [action.type for action in self.actions]
        if action_types[:3] != ["reset_session", "authenticate", "select_patient"]:
            raise ValueError(
                "seed sequence must start with reset, authentication, and patient selection"
            )
        if action_types[-1] != "collect_evidence":
            raise ValueError("seed sequence must end by collecting evidence")
        return self


def _load(path: Path, model: type[CatalogModel]) -> CatalogModel:
    return model.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def load_taxonomy(path: Path) -> TaxonomyV1:
    return TaxonomyV1.model_validate(_load(path, TaxonomyV1))


def load_judge_rubric(path: Path) -> JudgeRubricV1:
    return JudgeRubricV1.model_validate(_load(path, JudgeRubricV1))


def load_seed_cases(directory: Path) -> list[SeedCaseV1]:
    cases = [
        SeedCaseV1.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
        for path in sorted(directory.glob("*.yaml"))
    ]
    ids = [case.id for case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("seed case IDs must be unique")
    counts = Counter(case.category for case in cases)
    required = {"prompt_injection", "data_exfiltration", "tool_misuse"}
    if set(counts) != required or any(counts[category] < 2 for category in required):
        raise ValueError("seed suite requires at least two cases in each initial category")
    return cases
