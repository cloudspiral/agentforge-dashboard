from __future__ import annotations

import uuid
from decimal import Decimal

from sqlalchemy.orm import Session

from agentforge.api.schemas import CampaignCreateRequest, RegressionRunCreateRequest
from agentforge.evaluation import TaxonomyV1
from agentforge.persistence.models import Campaign, Finding, RegressionRun
from agentforge.persistence.repositories import (
    CampaignRepository,
    FindingRepository,
    RegressionRunRepository,
    ReportRepository,
    coverage_summary,
)
from agentforge.reports import export_stored_report
from agentforge.settings import Settings
from agentforge.target import LoadedTargetProfile


class ApplicationService:
    def __init__(
        self,
        session: Session,
        *,
        settings: Settings,
        target_profile: LoadedTargetProfile,
        taxonomy: TaxonomyV1,
    ) -> None:
        self.session = session
        self.settings = settings
        self.target_profile = target_profile
        self.taxonomy = taxonomy

    def _validate_scope(self, category: str | None, subcategory: str | None) -> None:
        if category is None:
            if subcategory is not None:
                raise ValueError("subcategory requires a category")
            return
        category_model = next(
            (item for item in self.taxonomy.categories if item.id == category),
            None,
        )
        if category_model is None:
            raise ValueError(f"unknown taxonomy category: {category}")
        if subcategory is not None and subcategory not in {
            item.id for item in category_model.subcategories
        }:
            raise ValueError(f"unknown subcategory {subcategory!r} for category {category!r}")

    def create_campaign(
        self,
        request: CampaignCreateRequest,
        *,
        trigger_type: str = "manual",
        target_version: str | None = None,
        idempotency_key: str | None = None,
    ) -> Campaign:
        if request.target_alias not in self.target_profile.profile.aliases:
            raise ValueError("target alias is not defined by the checked-in profile")
        self._validate_scope(request.category, request.subcategory)
        max_cost = request.max_cost_usd or Decimal(str(self.settings.default_campaign_max_cost_usd))
        if max_cost > Decimal(str(self.settings.default_campaign_max_cost_usd)):
            raise ValueError("requested campaign cost exceeds the configured campaign ceiling")
        if max_cost > Decimal(str(self.settings.global_max_cost_usd)):
            raise ValueError("requested campaign cost exceeds the configured global ceiling")
        return CampaignRepository(self.session).create(
            campaign_type=request.campaign_type,
            trigger_type=trigger_type,
            target_alias=request.target_alias,
            target_version=target_version or self.settings.target_version,
            category_scope=request.category,
            subcategory_scope=request.subcategory,
            max_cost_usd=max_cost,
            max_attempts=request.max_attempts or self.settings.default_campaign_max_attempts,
            max_duration_seconds=(
                request.max_duration_seconds or self.settings.default_campaign_max_duration_seconds
            ),
            priority=request.priority,
            idempotency_key=idempotency_key or request.idempotency_key,
        )

    def create_regression_run(self, request: RegressionRunCreateRequest) -> RegressionRun:
        target_version = request.target_version or self.settings.target_version
        campaign = self.create_campaign(
            CampaignCreateRequest(
                campaign_type="regression",
                target_alias=request.target_alias,
                max_attempts=100,
                idempotency_key=request.idempotency_key,
            ),
            idempotency_key=request.idempotency_key,
            target_version=target_version,
        )
        return RegressionRunRepository(self.session).create(
            target_version=target_version,
            trigger="manual",
            campaign_id=campaign.id,
        )

    def trigger_deployment_regression(
        self,
        *,
        deployment_id: str,
        target_version: str,
    ) -> Campaign:
        return self.create_campaign(
            CampaignCreateRequest(
                campaign_type="regression",
                target_alias="deployed",
                max_attempts=100,
            ),
            trigger_type="deployment",
            target_version=target_version,
            idempotency_key=f"deployment:{deployment_id}:{target_version}",
        )

    def export_report(self, finding_id: uuid.UUID) -> tuple[str, int]:
        finding = FindingRepository(self.session).get(finding_id)
        report = ReportRepository(self.session).latest_for_finding(finding_id)
        path = export_stored_report(
            report,
            vulnerability_id=finding.vulnerability_id,
            reports_dir=self.settings.reports_dir,
        )
        report.markdown_path = str(path)
        self.session.commit()
        return str(path), report.report_version

    def coverage(self) -> list[dict[str, object]]:
        return coverage_summary(self.session)


__all__ = ["ApplicationService", "Campaign", "Finding", "RegressionRun"]
