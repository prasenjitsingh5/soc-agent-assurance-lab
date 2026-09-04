"""Policy decision point.

Two engines evaluate the same Rego package:

* :class:`OpaHttpPolicyEngine` talks to an OPA server. This is the Docker path.
* :class:`OpaExecPolicyEngine` shells out to the ``opa`` binary. This is the
  local and CI path and needs no running service.

Every failure mode, whether a timeout, an unreachable server, a non-zero exit
or a document that does not match the expected shape, raises
:class:`PolicyUnavailableError`. The gateway turns that into a fail-closed
result for state-changing tools. There is no in-process fallback policy.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # noqa: S404 - invoking the pinned opa binary is the point of this module
import tempfile
from pathlib import Path
from typing import Any, Protocol

import httpx
from pydantic import Field, ValidationError

from soclab.contracts import (
    ActionProposal,
    AuthorityLevel,
    DecisionOutcome,
    Obligation,
    PolicyDecision,
    RiskTier,
    StrictModel,
)
from soclab.simulator import TOOL_RISK_TIERS

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO_ROOT / "policies" / "rego"
QUERY = "data.soc.authorization.result"


class PolicyUnavailableError(Exception):
    """The decision point could not produce a trustworthy decision."""


class ToolRegistryEntry(StrictModel):
    risk_tier: RiskTier
    allowed_arguments: tuple[str, ...]


class LimitContext(StrictModel):
    calls_made: int = Field(ge=0)
    max_calls: int = Field(gt=0)
    cost_used_usd: float = Field(ge=0)
    max_cost_usd: float = Field(gt=0)
    elapsed_seconds: float = Field(ge=0)
    max_elapsed_seconds: float = Field(gt=0)


class ApprovalContext(StrictModel):
    present: bool = False
    valid: bool = False


class AuthorizationContext(StrictModel):
    """Everything the policy needs besides the proposal. Built by the gateway, never by the model."""

    incident_id: str
    authority_level: AuthorityLevel
    approved_models: tuple[tuple[str, str], ...]
    tools: dict[str, ToolRegistryEntry]
    limits: LimitContext
    approval: ApprovalContext = ApprovalContext()
    degraded: bool = False


_ALLOWED_ARGUMENTS: dict[str, tuple[str, ...]] = {
    "search_siem_events": ("query",),
    "get_identity_profile": ("user_id",),
    "get_authentication_history": ("user_id", "limit"),
    "get_endpoint_status": ("endpoint_id",),
    "lookup_indicator": ("indicator",),
    "create_incident": ("title", "severity"),
    "revoke_sessions": ("user_id",),
    "disable_account": ("user_id",),
    "isolate_endpoint": ("endpoint_id",),
    "block_indicator": ("indicator",),
}


def default_tool_registry() -> dict[str, ToolRegistryEntry]:
    """The ten simulated tools with their risk tiers and argument schemas. Default deny beyond this."""
    return {
        name: ToolRegistryEntry(risk_tier=tier, allowed_arguments=_ALLOWED_ARGUMENTS[name])
        for name, tier in TOOL_RISK_TIERS.items()
    }


def build_policy_input(proposal: ActionProposal, context: AuthorizationContext) -> dict[str, Any]:
    """The exact document the Rego package evaluates. Kept small and explicit so it can be logged."""
    return {
        "proposal": {
            "agent_id": proposal.agent_id,
            "delegated_user_id": proposal.delegated_user_id,
            "incident_id": proposal.incident_id,
            "tool_name": proposal.tool_name,
            "arguments": proposal.arguments,
            "evidence_count": len(proposal.evidence_refs),
            "provider": proposal.provider,
            "model": proposal.model,
        },
        "context": {
            "incident_id": context.incident_id,
            "authority_level": context.authority_level.value,
            "approved_models": [{"provider": p, "model": m} for p, m in context.approved_models],
            "tools": {
                name: {"risk_tier": entry.risk_tier.value, "allowed_arguments": list(entry.allowed_arguments)}
                for name, entry in context.tools.items()
            },
            "limits": context.limits.model_dump(),
            "approval": context.approval.model_dump(),
            "degraded": context.degraded,
        },
    }


def _to_decision(proposal: ActionProposal, document: Any) -> PolicyDecision:
    if not isinstance(document, dict):
        msg = f"policy result is not an object: {type(document).__name__}"
        raise PolicyUnavailableError(msg)
    try:
        obligations = tuple(
            Obligation(name=o["name"], parameters=dict(o.get("parameters", {})))
            for o in document["obligations"]
        )
        reason_codes = tuple(str(r) for r in document["reason_codes"])
        return PolicyDecision(
            proposal_id=proposal.proposal_id,
            outcome=DecisionOutcome(document["decision"]),
            reason_codes=reason_codes,
            obligations=obligations,
            risk_tier=RiskTier(document["risk_tier"]),
            policy_version=str(document["policy_version"]),
            explanation=f"{document['decision']}: {', '.join(reason_codes)}",
        )
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        msg = f"policy result failed validation: {exc}"
        raise PolicyUnavailableError(msg) from exc


class PolicyEngine(Protocol):
    async def decide(self, proposal: ActionProposal, context: AuthorizationContext) -> PolicyDecision: ...


class OpaHttpPolicyEngine:
    """Queries an OPA server's data API. Any transport problem is a PolicyUnavailableError."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 2.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._url = base_url.rstrip("/") + "/v1/data/soc/authorization/result"
        self._timeout = timeout_seconds
        self._transport = transport

    async def decide(self, proposal: ActionProposal, context: AuthorizationContext) -> PolicyDecision:
        payload = {"input": build_policy_input(proposal, context)}
        try:
            async with httpx.AsyncClient(timeout=self._timeout, transport=self._transport) as client:
                response = await client.post(self._url, json=payload)
                response.raise_for_status()
                body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            msg = f"OPA unavailable: {type(exc).__name__}: {exc}"
            raise PolicyUnavailableError(msg) from exc
        if not isinstance(body, dict) or "result" not in body:
            msg = "OPA returned no result document (policy not loaded?)"
            raise PolicyUnavailableError(msg)
        return _to_decision(proposal, body["result"])


def find_opa_binary() -> Path | None:
    """Locate opa: SOCLAB_OPA_BIN, then PATH, then the repo-local tools folder."""
    env = os.environ.get("SOCLAB_OPA_BIN")
    if env and Path(env).exists():
        return Path(env)
    found = shutil.which("opa")
    if found:
        return Path(found)
    for candidate in (REPO_ROOT / "tools" / "opa.exe", REPO_ROOT / "tools" / "opa"):
        if candidate.exists():
            return candidate
    return None


class OpaExecPolicyEngine:
    """Evaluates the policy with the opa binary. No server required."""

    def __init__(
        self, binary: Path | None = None, *, policy_dir: Path = POLICY_DIR, timeout_seconds: float = 10.0
    ) -> None:
        resolved = binary or find_opa_binary()
        if resolved is None:
            msg = "opa binary not found; set SOCLAB_OPA_BIN or place it in tools/"
            raise PolicyUnavailableError(msg)
        self._binary = resolved
        self._policy_dir = policy_dir
        self._timeout = timeout_seconds

    async def decide(self, proposal: ActionProposal, context: AuthorizationContext) -> PolicyDecision:
        document = build_policy_input(proposal, context)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
            json.dump(document, handle)
            input_path = Path(handle.name)
        try:
            completed = subprocess.run(  # noqa: S603 - fixed binary, fixed arguments, no shell
                [
                    str(self._binary),
                    "eval",
                    "--format",
                    "json",
                    "--data",
                    str(self._policy_dir),
                    "--input",
                    str(input_path),
                    QUERY,
                ],
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            msg = f"opa eval failed to run: {type(exc).__name__}: {exc}"
            raise PolicyUnavailableError(msg) from exc
        finally:
            input_path.unlink(missing_ok=True)
        if completed.returncode != 0:
            msg = f"opa eval exited {completed.returncode}: {completed.stderr.strip()[:300]}"
            raise PolicyUnavailableError(msg)
        try:
            parsed = json.loads(completed.stdout)
            value = parsed["result"][0]["expressions"][0]["value"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            msg = f"opa eval produced no value: {exc}"
            raise PolicyUnavailableError(msg) from exc
        return _to_decision(proposal, value)
