from __future__ import annotations

from collections import Counter
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import (
    AwareDatetime,
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
Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


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
    observable_signals: list[Identifier] = Field(min_length=1)
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
    attack_blocked: BoundedText
    exploit_confirmed: BoundedText
    partial_signal: BoundedText
    inconclusive: BoundedText
    severity_rules: dict[str, str]
    exploitability_rules: dict[str, str]


class JudgeRubricV1(CatalogModel):
    schema_version: Literal["1.0"]
    rubric_version: str
    confidence_thresholds: dict[str, float | bool]
    global_rules: list[BoundedText]
    categories: dict[str, JudgeCategoryV1]

    @model_validator(mode="after")
    def all_taxonomy_categories_are_covered(self) -> JudgeRubricV1:
        required = {
            "prompt_injection",
            "data_exfiltration",
            "state_corruption",
            "tool_misuse",
            "denial_of_service",
            "identity_role_exploitation",
        }
        if set(self.categories) != required:
            raise ValueError("Judge rubric must cover all six taxonomy categories")
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


class SeedInvokeApiActionV1(CatalogModel):
    type: Literal["invoke_approved_api_request"]
    endpoint_id: Identifier
    method: Literal["GET", "POST"]
    credential_mode: Literal["endpoint_default", "missing", "invalid", "valid"] = "endpoint_default"
    correlation_mode: Literal["valid", "missing", "invalid", "mismatch"] = "valid"
    query: dict[str, object] = Field(default_factory=dict, max_length=25)
    body: dict[str, object] = Field(default_factory=dict)


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
    | SeedInvokeApiActionV1
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
    category: Literal[
        "prompt_injection",
        "data_exfiltration",
        "state_corruption",
        "tool_misuse",
        "denial_of_service",
        "identity_role_exploitation",
    ]
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


class CoverageStatusV1(StrEnum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    BLOCKED = "BLOCKED"
    NOT_RUN = "NOT RUN"
    NOT_APPLICABLE = "NOT APPLICABLE"


class ControlMappingV1(CatalogModel):
    framework: Literal["owasp_web_2021", "owasp_llm_2025"]
    id: Identifier
    title: BoundedText


class ControlStepV1(CatalogModel):
    action: Identifier
    input_summary: BoundedText
    expected: BoundedText


class ControlCaseV1(CatalogModel):
    schema_version: Literal["1.0"]
    id: Identifier
    name: BoundedText
    category: Identifier
    subcategory: Identifier
    target: Literal["clinical_copilot"]
    method: Literal[
        "static_sca",
        "missing_session_http",
        "live_chat_url_sentinel",
        "live_chat_markup_canary",
    ]
    exact_sequence: list[ControlStepV1] = Field(min_length=1, max_length=12)
    expected_safe_behavior: BoundedText
    evidence_requirements: list[Identifier] = Field(min_length=1, max_length=12)
    mappings: list[ControlMappingV1] = Field(min_length=1, max_length=4)
    severity: Literal["informational", "low", "medium", "high", "critical"]
    exploitability: Literal["low", "medium", "high"]
    regression_eligible_if_failed: bool

    @field_validator("mappings")
    @classmethod
    def mappings_are_unique(cls, value: list[ControlMappingV1]) -> list[ControlMappingV1]:
        keys = [(mapping.framework, mapping.id) for mapping in value]
        if len(keys) != len(set(keys)):
            raise ValueError("control mappings must be unique")
        return value


class ControlMappingResultV1(CatalogModel):
    framework: Literal["owasp_web_2021", "owasp_llm_2025"]
    id: Identifier
    status: CoverageStatusV1
    observed: BoundedText
    evidence_paths: list[str] = Field(default_factory=list, max_length=20)


class ControlResultV1(CatalogModel):
    schema_version: Literal["1.0"]
    artifact_kind: Literal["clinical_copilot_owasp_control_result"]
    case_id: Identifier
    case_sha256: Sha256Hex
    target_version: BoundedText
    target_source_sha256: Sha256Hex | None = None
    executed_at: AwareDatetime
    execution_status: CoverageStatusV1
    observed_behavior: BoundedText
    severity: Literal["informational", "low", "medium", "high", "critical"]
    exploitability: Literal["low", "medium", "high"]
    regression_eligible: bool
    mapping_results: list[ControlMappingResultV1] = Field(min_length=1, max_length=4)
    evidence_paths: list[str] = Field(default_factory=list, max_length=20)
    limitations: list[BoundedText] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def mapping_statuses_match_execution(self) -> ControlResultV1:
        if self.execution_status == CoverageStatusV1.VERIFIED and any(
            mapping.status != CoverageStatusV1.VERIFIED for mapping in self.mapping_results
        ):
            raise ValueError("a verified control execution requires verified mapped results")
        return self


def _load(path: Path, model: type[CatalogModel]) -> CatalogModel:
    return model.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def load_taxonomy(path: Path) -> TaxonomyV1:
    return TaxonomyV1.model_validate(_load(path, TaxonomyV1))


def load_judge_rubric(path: Path) -> JudgeRubricV1:
    return JudgeRubricV1.model_validate(_load(path, JudgeRubricV1))


def load_seed_case(path: Path) -> SeedCaseV1:
    """Load one exact case without applying whole-catalog coverage rules."""

    return SeedCaseV1.model_validate(_load(path, SeedCaseV1))


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
    if not required.issubset(counts) or any(counts[category] < 2 for category in required):
        raise ValueError("seed suite requires at least two cases in each initial category")
    return cases


def load_control_case(path: Path) -> ControlCaseV1:
    return ControlCaseV1.model_validate(_load(path, ControlCaseV1))


def load_control_cases(directory: Path) -> list[ControlCaseV1]:
    cases = [load_control_case(path) for path in sorted(directory.glob("*.yaml"))]
    ids = [case.id for case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("control case IDs must be unique")
    required_ids = {"AF-SC-001", "AF-AL-001", "AF-SSRF-001", "AF-OH-001"}
    if set(ids) != required_ids:
        raise ValueError(f"control suite must contain exactly {sorted(required_ids)}")
    required_mappings = {
        ("owasp_web_2021", "A06"),
        ("owasp_web_2021", "A07"),
        ("owasp_web_2021", "A09"),
        ("owasp_web_2021", "A10"),
        ("owasp_llm_2025", "LLM03"),
        ("owasp_llm_2025", "LLM05"),
    }
    observed_mappings = {
        (mapping.framework, mapping.id) for case in cases for mapping in case.mappings
    }
    if not required_mappings.issubset(observed_mappings):
        missing = sorted(required_mappings - observed_mappings)
        raise ValueError(f"control suite is missing required mappings: {missing}")
    return cases
