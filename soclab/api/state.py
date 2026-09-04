"""Process-wide state shared by the routes. One evidence store, one approval queue, cached campaigns."""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID

from soclab.approvals import ApprovalService
from soclab.evidence import EvidenceRepository
from soclab.scoring import AssuranceResult, CampaignResult


@dataclass
class CampaignRecord:
    result: CampaignResult
    assurance: AssuranceResult


@dataclass
class AppState:
    repository: EvidenceRepository
    approvals: ApprovalService = field(default_factory=ApprovalService)
    campaigns: dict[UUID, CampaignRecord] = field(default_factory=dict)
