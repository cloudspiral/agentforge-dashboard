from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from agentforge.settings import Settings


class ProfileModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RuntimeVersionSourceV1(ProfileModel):
    method: Literal["GET", "HEAD"]
    path: str
    json_field: str

    @field_validator("path")
    @classmethod
    def path_is_relative(cls, value: str) -> str:
        if not value.startswith("/") or "://" in value or ".." in value:
            raise ValueError("profile paths must be absolute-path references without a URL host")
        return value


class TargetAliasV1(ProfileModel):
    base_url_env: str | None = None
    status_url_env: str | None = None
    base_url: str | None = None
    status_url: str | None = None
    expected_hosts: list[str] = Field(min_length=1)
    verify_tls_env: str | None = None
    verify_tls: bool | None = None

    @model_validator(mode="after")
    def has_exact_url_sources(self) -> TargetAliasV1:
        if bool(self.base_url) == bool(self.base_url_env):
            raise ValueError("alias requires exactly one of base_url or base_url_env")
        if bool(self.status_url) == bool(self.status_url_env):
            raise ValueError("alias requires exactly one of status_url or status_url_env")
        for url in (self.base_url, self.status_url):
            if url and (
                urlparse(url).scheme not in {"http", "https"} or not urlparse(url).hostname
            ):
                raise ValueError("literal alias URLs must be absolute HTTP URLs")
        return self


class AuthenticationV1(ProfileModel):
    type: Literal["form_session"]
    username_env: str
    password_env: str
    login_path: str
    selectors: dict[str, str]
    supported_roles: list[str] = Field(min_length=1)


class SyntheticPatientV1(ProfileModel):
    external_id: str = Field(min_length=1, max_length=100)
    display_name: str = Field(min_length=1, max_length=255)
    canary: str = Field(min_length=1, max_length=500)


class PatientsV1(ProfileModel):
    id_kind: Literal["pubpid"]
    numeric_pid_is_dynamic: bool
    patient_a: SyntheticPatientV1
    patient_b: SyntheticPatientV1

    @model_validator(mode="after")
    def patients_are_distinct(self) -> PatientsV1:
        if self.patient_a.external_id == self.patient_b.external_id:
            raise ValueError("Patient A and Patient B must be different synthetic charts")
        if self.patient_a.canary == self.patient_b.canary:
            raise ValueError("Patient A and Patient B must have distinct canaries")
        return self


class PatientSelectionV1(ProfileModel):
    search_selector: str
    submit_selector: str
    finder_frame: str
    result_table: str
    result_row_prefix: str
    patient_frame: str


class ChatProfileV1(ProfileModel):
    card_selector: str
    message_selector: str
    submit_selector: str
    output_selector: str
    completed_selector: str
    answer_selector: str
    error_selector: str
    citation_selector: str
    evidence_selector: str
    endpoint_attribute: str
    csrf_attribute: str
    patient_id_attribute: str
    request_max_bytes: int = Field(gt=0, le=65_536)
    message_max_bytes: int = Field(gt=0, le=4_000)


class UploadProfileV1(ProfileModel):
    enabled: bool
    persist_confirmation_enabled: bool
    open_selector: str
    type_selector: str
    file_selector: str
    submit_selector: str
    review_selector: str
    error_selector: str
    reject_selector: str
    confirm_selector: str
    processing_timeout_seconds: int = Field(ge=30, le=180)
    allowed_document_types: list[str]
    allowed_extensions: list[str]
    max_bytes: int = Field(gt=0, le=10_485_760)
    max_pages: int = Field(gt=0, le=10)
    fixture_root: str

    @field_validator("fixture_root")
    @classmethod
    def fixture_root_is_repository_relative(cls, value: str) -> str:
        path = Path(value)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("fixture_root must be a bounded repository-relative path")
        return value


class EndpointRuleV1(ProfileModel):
    method: Literal["GET", "HEAD", "POST"]
    surface: Literal["status", "ui", "agent_service"]
    path: str

    @field_validator("path")
    @classmethod
    def endpoint_path_is_bounded(cls, value: str) -> str:
        if not value.startswith("/") or "://" in value or ".." in value:
            raise ValueError("endpoint rules cannot contain a URL host or traversal")
        return value


class ResetProfileV1(ProfileModel):
    conversation: str
    staged_upload: str
    persistent_chart_reset: str


class SafetyProfileV1(ProfileModel):
    no_real_phi: Literal[True]
    no_target_database_access: Literal[True]
    no_arbitrary_urls: Literal[True]
    no_shell_actions: Literal[True]
    no_persistent_browser_state: Literal[True]
    redirects_must_remain_same_origin: Literal[True]


class TargetProfileV1(ProfileModel):
    schema_version: Literal["1.0"]
    profile_version: str
    name: str
    authorized_scope: Literal["synthetic-only"]
    runtime_version_source: RuntimeVersionSourceV1
    aliases: dict[str, TargetAliasV1]
    authentication: AuthenticationV1
    patients: PatientsV1
    patient_selection: PatientSelectionV1
    chat: ChatProfileV1
    upload: UploadProfileV1
    allowed_endpoints: list[EndpointRuleV1]
    prohibited_endpoints: list[str]
    known_read_only_tools: list[str]
    reset: ResetProfileV1
    safety: SafetyProfileV1

    @field_validator("allowed_endpoints")
    @classmethod
    def endpoint_rules_are_unique(cls, value: list[EndpointRuleV1]) -> list[EndpointRuleV1]:
        keys = [(rule.surface, rule.method, rule.path) for rule in value]
        if len(keys) != len(set(keys)):
            raise ValueError("target endpoint rules must be unique")
        return value

    @field_validator("known_read_only_tools")
    @classmethod
    def tools_are_unique(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("known target tools must be unique")
        return value


class ResolvedTargetAlias(ProfileModel):
    name: str
    base_url: str
    status_url: str
    expected_hosts: list[str]
    verify_tls: bool


class LoadedTargetProfile(ProfileModel):
    profile: TargetProfileV1
    profile_hash: str
    source_path: Path

    def resolve_alias(self, name: str, settings: Settings) -> ResolvedTargetAlias:
        alias = self.profile.aliases.get(name)
        if alias is None:
            raise ValueError(f"unknown target alias: {name}")

        def resolve(literal: str | None, env_name: str | None) -> str:
            if literal:
                return literal
            if not env_name:
                raise ValueError("profile alias URL source is missing")
            value = getattr(settings, env_name.lower(), None)
            if isinstance(value, SecretStr):
                raise ValueError("target URL settings cannot be secret fields")
            if not isinstance(value, str) or not value:
                raise ValueError(f"required target setting {env_name} is empty")
            return value

        verify_tls = alias.verify_tls
        if alias.verify_tls_env:
            verify_tls = bool(getattr(settings, alias.verify_tls_env.lower()))
        if verify_tls is None:
            verify_tls = True
        return ResolvedTargetAlias(
            name=name,
            base_url=resolve(alias.base_url, alias.base_url_env),
            status_url=resolve(alias.status_url, alias.status_url_env),
            expected_hosts=alias.expected_hosts,
            verify_tls=verify_tls,
        )


def _profile_hash(profile: TargetProfileV1) -> str:
    canonical = json.dumps(profile.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def load_target_profile(path: Path) -> LoadedTargetProfile:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    profile = TargetProfileV1.model_validate(raw)
    return LoadedTargetProfile(
        profile=profile,
        profile_hash=_profile_hash(profile),
        source_path=path.resolve(),
    )
