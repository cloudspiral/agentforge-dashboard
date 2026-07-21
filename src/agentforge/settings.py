from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BeforeValidator, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _split_csv(value: object) -> object:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


CsvList = Annotated[list[str], BeforeValidator(_split_csv)]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=None,
        env_prefix="",
        case_sensitive=False,
        extra="ignore",
    )

    environment: Literal["development", "test", "staging", "production"] = "development"
    log_level: str = "INFO"
    database_url: str = "postgresql+psycopg://agentforge:agentforge@localhost:5433/agentforge"
    platform_api_token: SecretStr | None = None
    deploy_webhook_secret: SecretStr | None = None

    openai_api_key: SecretStr | None = None
    openai_orchestrator_model: str = "gpt-5.6-terra"
    openai_attack_model: str = "gpt-5.6-terra"
    openai_judge_model: str = "gpt-5.6-terra"
    openai_judge_escalation_model: str = "gpt-5.6-sol"
    openai_documentation_model: str = "gpt-5.6-luna"
    global_max_cost_usd: float = Field(default=10, gt=0)
    default_campaign_max_cost_usd: float = Field(default=2, gt=0)
    default_campaign_max_attempts: int = Field(default=10, ge=1, le=100)
    default_campaign_max_duration_seconds: int = Field(default=1200, ge=30, le=86_400)
    default_max_mutations: int = Field(default=3, ge=0, le=20)
    default_no_signal_limit: int = Field(default=4, ge=1, le=20)

    langfuse_public_key: SecretStr | None = None
    langfuse_secret_key: SecretStr | None = None
    langfuse_base_url: str = "https://cloud.langfuse.com"
    langfuse_enabled: bool = True

    target_profile_path: Path = Path("config/target-profile.yaml")
    attack_taxonomy_path: Path = Path("config/attack-taxonomy.yaml")
    judge_rubric_path: Path = Path("config/judge-rubric.yaml")
    model_routing_path: Path = Path("config/model-routing.yaml")
    pricing_path: Path = Path("config/pricing.yaml")
    target_base_url: str = "https://localhost:9300"
    target_api_base_url: str = "http://localhost:8001"
    target_ui_url: str = "https://localhost:9300"
    target_allowed_hosts: CsvList = ["localhost", "127.0.0.1", "host.docker.internal"]
    target_version: str = "local-unknown"
    target_test_username: str | None = None
    target_test_password: SecretStr | None = None
    target_test_role: str = "physician"
    target_test_patient_a_id: str | None = None
    target_test_patient_b_id: str | None = None
    target_agent_shared_secret: SecretStr | None = None
    target_reset_url: str | None = None
    target_reset_token: SecretStr | None = None
    target_verify_tls: bool = True
    target_probe_timeout_seconds: float = Field(default=3.0, ge=0.1, le=30.0)

    worker_enabled: bool = True
    worker_poll_seconds: float = Field(default=2, ge=0.1, le=60)
    worker_stale_after_seconds: int = Field(default=120, ge=30, le=3600)
    reports_dir: Path = Path("reports/generated")
    artifacts_dir: Path = Path("artifacts")
    max_upload_bytes: int = Field(default=1_048_576, ge=1, le=10_485_760)
    run_live_e2e: bool = False

    @field_validator("target_allowed_hosts")
    @classmethod
    def allowed_hosts_must_not_be_empty(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("TARGET_ALLOWED_HOSTS must contain at least one hostname")
        return value

    @property
    def has_openai_credentials(self) -> bool:
        return bool(self.openai_api_key and self.openai_api_key.get_secret_value())

    @property
    def has_langfuse_credentials(self) -> bool:
        return bool(
            self.langfuse_enabled
            and self.langfuse_public_key
            and self.langfuse_secret_key
            and self.langfuse_public_key.get_secret_value()
            and self.langfuse_secret_key.get_secret_value()
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
