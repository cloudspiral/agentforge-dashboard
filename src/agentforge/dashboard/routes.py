from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select

from agentforge.persistence.models import (
    Campaign,
    Finding,
    JudgeVerdict,
)
from agentforge.persistence.repositories import (
    CampaignRepository,
    FindingRepository,
    RegressionRunRepository,
    coverage_summary,
)

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def overview(request: Request) -> HTMLResponse:
    with request.app.state.database.session_factory() as session:
        campaigns = dict(
            session.execute(
                select(Campaign.status, func.count(Campaign.id)).group_by(Campaign.status)
            ).all()
        )
        findings = dict(
            session.execute(
                select(Finding.severity, func.count(Finding.id))
                .where(Finding.status.in_(["open", "in_progress", "reopened"]))
                .group_by(Finding.severity)
            ).all()
        )
        verdicts = dict(
            session.execute(
                select(JudgeVerdict.verdict, func.count(JudgeVerdict.id)).group_by(
                    JudgeVerdict.verdict
                )
            ).all()
        )
        estimated_cost = session.scalar(select(func.sum(Campaign.actual_cost_usd))) or 0
        coverage = coverage_summary(session)
        recent = list(
            session.scalars(select(Campaign).order_by(Campaign.created_at.desc()).limit(8))
        )
    return templates.TemplateResponse(
        request=request,
        name="overview.html",
        context={
            "campaigns": campaigns,
            "findings": findings,
            "verdicts": verdicts,
            "estimated_cost": estimated_cost,
            "coverage": coverage,
            "recent_campaigns": recent,
        },
    )


@router.get("/dashboard/campaigns", response_class=HTMLResponse, include_in_schema=False)
def campaigns(request: Request) -> HTMLResponse:
    with request.app.state.database.session_factory() as session:
        items, total = CampaignRepository(session).list(limit=200)
    return templates.TemplateResponse(
        request=request,
        name="campaigns.html",
        context={"campaigns": items, "total": total},
    )


@router.get(
    "/dashboard/campaigns/{campaign_id}",
    response_class=HTMLResponse,
    include_in_schema=False,
)
def campaign_detail(request: Request, campaign_id: uuid.UUID) -> HTMLResponse:
    with request.app.state.database.session_factory() as session:
        campaign = CampaignRepository(session).get(campaign_id, include_attempts=True)
        attempts = sorted(campaign.attempts, key=lambda item: item.created_at)
        attempt_ids = [attempt.id for attempt in attempts]
        verdicts = {
            verdict.attempt_id: verdict
            for verdict in session.scalars(
                select(JudgeVerdict).where(JudgeVerdict.attempt_id.in_(attempt_ids))
            )
        }
    return templates.TemplateResponse(
        request=request,
        name="campaign_detail.html",
        context={"campaign": campaign, "attempts": attempts, "verdicts": verdicts},
    )


@router.get("/dashboard/findings", response_class=HTMLResponse, include_in_schema=False)
def findings(request: Request) -> HTMLResponse:
    with request.app.state.database.session_factory() as session:
        items, total = FindingRepository(session).list(limit=200)
    return templates.TemplateResponse(
        request=request,
        name="findings.html",
        context={"findings": items, "total": total},
    )


@router.get(
    "/dashboard/findings/{finding_id}",
    response_class=HTMLResponse,
    include_in_schema=False,
)
def finding_detail(request: Request, finding_id: uuid.UUID) -> HTMLResponse:
    with request.app.state.database.session_factory() as session:
        finding = FindingRepository(session).get(finding_id)
        report = finding.reports[-1] if finding.reports else None
    return templates.TemplateResponse(
        request=request,
        name="finding_detail.html",
        context={"finding": finding, "report": report},
    )


@router.get(
    "/dashboard/regression-runs",
    response_class=HTMLResponse,
    include_in_schema=False,
)
def regression_runs(request: Request) -> HTMLResponse:
    with request.app.state.database.session_factory() as session:
        items, total = RegressionRunRepository(session).list(limit=200)
    return templates.TemplateResponse(
        request=request,
        name="regressions.html",
        context={"runs": items, "total": total},
    )
