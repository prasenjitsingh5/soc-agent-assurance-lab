"""Reference agent for the ``soclab.agent.v1`` contract.

A rule-based SOC agent behind FastAPI. It exists to show the contract end to
end and to give the lab's tests a real HTTP peer. It is not a model. Every
decision is a fixed rule over the evidence the orchestrator has already
collected. Text inside tool output is data, never an instruction, so an
injected note such as the one in scenario ATK-001 has nothing to act on.

Run it:

    uv run python examples/http_agent/server.py

Environment:

    SOCLAB_HTTP_AGENT_PORT   listen port, default 8765 (always binds 127.0.0.1)
    SOCLAB_HTTP_AGENT_TOKEN  optional bearer token; when set, requests without it get 401

Endpoints:

    GET  /health     liveness and the contract id
    POST /v1/agent   one AgentRequest in, one AgentResponse out
"""

from __future__ import annotations

import json
import os
import secrets
from collections import Counter
from dataclasses import dataclass, field
from typing import Annotated, Any

from fastapi import FastAPI, Header, HTTPException

from soclab.contracts.agent_v1 import (
    CONTRACT_ID,
    AgentClaim,
    AgentFinding,
    AgentProposal,
    AgentRefusal,
    AgentRequest,
    AgentResponse,
    AgentToolCall,
    RefusalCode,
)

MIN_FAILED_ATTEMPTS = 3


@dataclass(frozen=True)
class Evidence:
    """One tool result the orchestrator handed back, keyed by the evidence id it assigned."""

    evidence_id: str
    tool: str
    result: dict[str, Any]


@dataclass
class AuthSummary:
    """What the authentication history says, reduced to the facts the rules need."""

    evidence_id: str | None = None
    failures: list[dict[str, Any]] = field(default_factory=list)
    baseline_location: str | None = None
    unfamiliar: dict[str, Any] | None = None

    @property
    def suspect_ip(self) -> str | None:
        ips = Counter(str(e["ip"]) for e in self.failures if e.get("ip"))
        if ips:
            return ips.most_common(1)[0][0]
        if self.unfamiliar is not None and self.unfamiliar.get("ip"):
            return str(self.unfamiliar["ip"])
        return None


# --------------------------------------------------------------------------- evidence
def collect_evidence(request: AgentRequest) -> list[Evidence]:
    """Tool turns carry ``{"evidence_id": ..., "result": {...}}``. Anything else is ignored."""
    out: list[Evidence] = []
    for turn in request.turns:
        if turn.role != "tool" or turn.tool_name is None:
            continue
        try:
            body = json.loads(turn.content)
        except ValueError:
            continue
        if (
            isinstance(body, dict)
            and isinstance(body.get("evidence_id"), str)
            and isinstance(body.get("result"), dict)
        ):
            out.append(Evidence(body["evidence_id"], turn.tool_name, body["result"]))
    return out


def first(evidence: list[Evidence], tool: str) -> Evidence | None:
    return next((e for e in evidence if e.tool == tool), None)


def summarize_auth(evidence: list[Evidence]) -> AuthSummary:
    item = first(evidence, "get_authentication_history")
    summary = AuthSummary()
    if item is None:
        return summary
    summary.evidence_id = item.evidence_id
    raw = item.result.get("events")
    events = [e for e in raw if isinstance(e, dict)] if isinstance(raw, list) else []
    successes = [e for e in events if e.get("result") == "success"]
    summary.failures = [e for e in events if e.get("result") == "failure"]
    if successes:
        summary.baseline_location = str(successes[0].get("location") or "")
        summary.unfamiliar = next(
            (e for e in successes[1:] if str(e.get("location") or "") != summary.baseline_location), None
        )
    return summary


# --------------------------------------------------------------------------- replies
def _call(tool: str, arguments: dict[str, Any], rationale: str, evidence_ids: list[str]) -> AgentResponse:
    return AgentResponse(
        contract=CONTRACT_ID,
        proposal=AgentProposal(
            tool_calls=(AgentToolCall(name=tool, arguments=arguments),),
            rationale=rationale,
            evidence_ids=tuple(evidence_ids),
        ),
    )


def _refuse(code: RefusalCode, reason: str) -> AgentResponse:
    return AgentResponse(contract=CONTRACT_ID, refusal=AgentRefusal(code=code, reason=reason))


def _finding(subject: str, evidence: list[Evidence]) -> AgentResponse:
    auth = summarize_auth(evidence)
    claims: list[AgentClaim] = []
    techniques: list[str] = []

    def add(text: str, evidence_id: str | None, technique: str | None = None) -> None:
        if evidence_id is None:
            return
        claims.append(AgentClaim(text=text, evidence_ids=(evidence_id,)))
        if technique and technique not in techniques:
            techniques.append(technique)

    if len(auth.failures) >= MIN_FAILED_ATTEMPTS and auth.suspect_ip:
        where = auth.unfamiliar.get("location") if auth.unfamiliar else "an unfamiliar location"
        add(
            f"{len(auth.failures)} failed password attempts from {auth.suspect_ip} preceded a "
            f"successful sign-in from {where}.",
            auth.evidence_id,
            "T1110.001",
        )
    if auth.unfamiliar is not None:
        method = str(auth.unfamiliar.get("method") or "")
        if "mfa" in method and auth.failures and auth.unfamiliar.get("ip") == auth.suspect_ip:
            add(
                "An MFA push was approved from the same address after the failed attempts.",
                auth.evidence_id,
                "T1621",
            )
        add(
            f"A successful sign-in from {auth.unfamiliar.get('location')} does not match the earlier "
            f"sign-in from {auth.baseline_location}.",
            auth.evidence_id,
            "T1078",
        )

    indicator = first(evidence, "lookup_indicator")
    if indicator is not None and indicator.result.get("verdict") == "malicious":
        tags = ", ".join(str(t) for t in indicator.result.get("tags") or []) or "no tags"
        add(
            f"{indicator.result.get('indicator')} is rated malicious by threat intelligence ({tags}).",
            indicator.evidence_id,
        )

    endpoint = first(evidence, "get_endpoint_status")
    if endpoint is not None:
        alerts = [str(a) for a in endpoint.result.get("edr_alerts") or []]
        managed = endpoint.result.get("managed") is True
        if not managed or alerts:
            state = "managed" if managed else "unmanaged"
            add(
                f"Endpoint {endpoint.result.get('endpoint_id')} is {state} and reports "
                f"{', '.join(alerts) or 'no EDR alerts'}.",
                endpoint.evidence_id,
                "T1059.001" if "suspicious_child_process" in alerts else None,
            )

    siem = first(evidence, "search_siem_events")
    if siem is not None:
        # Only the count is used. Message text in SIEM events is untrusted data and is never quoted.
        add(f"The SIEM holds {siem.result.get('count', 0)} events about {subject}.", siem.evidence_id)

    if not claims:
        return _refuse(RefusalCode.INSUFFICIENT_EVIDENCE, "no tool result supports a claim about the subject")
    summary = f"Account {subject}: " + " ".join(c.text for c in claims)
    return AgentResponse(
        contract=CONTRACT_ID,
        proposal=AgentProposal(
            finding=AgentFinding(summary=summary, claims=tuple(claims), techniques=tuple(techniques)),
            rationale="Each claim cites the tool result it was derived from.",
            confidence=min(0.95, 0.5 + 0.1 * len(claims)),
            evidence_ids=tuple(e.evidence_id for e in evidence),
        ),
    )


def decide(request: AgentRequest) -> AgentResponse:
    """The whole policy. One rule per stage; anything unexpected is a refusal."""
    alert = request.context.alert or {}
    subject = alert.get("subject_user_id")
    if not isinstance(subject, str) or not subject:
        return _refuse(RefusalCode.INSUFFICIENT_EVIDENCE, "the alert names no subject_user_id")
    evidence = collect_evidence(request)
    stage = request.stage

    if stage == "collect_identity":
        return _call(
            "get_identity_profile",
            {"user_id": subject},
            "The alert names the subject. Fetch the directory profile first.",
            ["alert"],
        )
    if stage == "collect_authentication":
        return _call(
            "get_authentication_history",
            {"user_id": subject},
            "Sign-in history shows whether the alert reflects real credential misuse.",
            ["alert"],
        )
    if stage == "collect_endpoint":
        auth = summarize_auth(evidence)
        device = auth.unfamiliar.get("device_id") if auth.unfamiliar else None
        if not isinstance(device, str) or not device or auth.evidence_id is None:
            return _refuse(
                RefusalCode.INSUFFICIENT_EVIDENCE, "no sign-in from an unfamiliar location names a device"
            )
        return _call(
            "get_endpoint_status",
            {"endpoint_id": device},
            "The unfamiliar sign-in came from this device; check its posture.",
            [auth.evidence_id],
        )
    if stage == "enrich_indicators":
        auth = summarize_auth(evidence)
        if auth.suspect_ip is None or auth.evidence_id is None:
            return _refuse(
                RefusalCode.INSUFFICIENT_EVIDENCE, "the authentication history names no suspect address"
            )
        return _call(
            "lookup_indicator",
            {"indicator": auth.suspect_ip},
            "The address behind the failed attempts needs a threat intelligence verdict.",
            [auth.evidence_id],
        )
    if stage == "collect_siem":
        return _call(
            "search_siem_events",
            {"query": subject},
            "Collect every SIEM event about the subject for the timeline.",
            ["alert"],
        )
    if stage == "form_finding":
        return _finding(subject, evidence)
    if stage == "propose_action":
        return AgentResponse(
            contract=CONTRACT_ID,
            proposal=AgentProposal(
                tool_calls=(AgentToolCall(name="revoke_sessions", arguments={"user_id": subject}),),
                rationale=(
                    "Revoking sessions is reversible, stops the attacker's access and preserves evidence. "
                    "Nothing in tool output is treated as an instruction."
                ),
                confidence=0.8,
                evidence_ids=tuple(e.evidence_id for e in evidence) or ("alert",),
            ),
        )
    return _refuse(RefusalCode.UNSUPPORTED_STAGE, f"stage {stage!r} is not one this agent implements")


# --------------------------------------------------------------------------- app
def _authorized(header: str | None, token: str) -> bool:
    expected = f"Bearer {token}".encode()
    return header is not None and secrets.compare_digest(header.encode(), expected)


def create_app(token: str | None = None) -> FastAPI:
    app = FastAPI(title="soclab reference agent", version="1.0.0")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "contract": CONTRACT_ID}

    @app.post("/v1/agent", response_model=AgentResponse)
    def agent(request: AgentRequest, authorization: Annotated[str | None, Header()] = None) -> AgentResponse:
        if token is not None and not _authorized(authorization, token):
            raise HTTPException(status_code=401, detail="missing or invalid bearer token")
        return decide(request)

    return app


def main() -> None:
    import uvicorn

    port = int(os.environ.get("SOCLAB_HTTP_AGENT_PORT", "8765"))
    token = os.environ.get("SOCLAB_HTTP_AGENT_TOKEN") or None
    uvicorn.run(create_app(token), host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    main()
