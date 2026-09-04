import json
import sys
from pathlib import Path

import httpx
import pytest

from soclab.contracts import (
    ActionProposal,
    AuthorityLevel,
    DecisionOutcome,
    EvidenceRef,
    RiskTier,
    TrustLabel,
)
from soclab.policy import (
    ApprovalContext,
    AuthorizationContext,
    LimitContext,
    OpaExecPolicyEngine,
    OpaHttpPolicyEngine,
    PolicyUnavailableError,
    build_policy_input,
    default_tool_registry,
    find_opa_binary,
)

INC = "INC-1001"
HASH = "b" * 64


def evidence(n: int) -> tuple[EvidenceRef, ...]:
    return tuple(
        EvidenceRef(
            evidence_id=f"ev-{i}",
            source_tool="search_siem_events",
            incident_id=INC,
            trust=TrustLabel.UNTRUSTED,
            content_hash=HASH,
            summary="s",
        )
        for i in range(n)
    )


def proposal(tool: str = "get_identity_profile", n_evidence: int = 3, **kw: object) -> ActionProposal:
    args = {"user_id": "u-alex-rivera"} if tool != "search_siem_events" else {"query": "x"}
    base: dict[str, object] = {
        "agent_id": "soc-investigator",
        "delegated_user_id": "analyst-1",
        "incident_id": INC,
        "tool_name": tool,
        "arguments": args,
        "evidence_refs": evidence(n_evidence),
        "rationale": "r",
        "provider": "mock",
        "model": "mock-investigator-v1",
        "trace_id": "t",
    }
    base.update(kw)
    return ActionProposal(**base)  # type: ignore[arg-type]


def context(
    level: AuthorityLevel = AuthorityLevel.L4_ACT_WITH_APPROVAL, **kw: object
) -> AuthorizationContext:
    base: dict[str, object] = {
        "incident_id": INC,
        "authority_level": level,
        "approved_models": (("mock", "mock-investigator-v1"),),
        "tools": default_tool_registry(),
        "limits": LimitContext(
            calls_made=1,
            max_calls=50,
            cost_used_usd=0.0,
            max_cost_usd=5.0,
            elapsed_seconds=1,
            max_elapsed_seconds=600,
        ),
    }
    base.update(kw)
    return AuthorizationContext(**base)  # type: ignore[arg-type]


# ----------------------------------------------------------------- input document
def test_policy_input_is_explicit_and_serializable() -> None:
    doc = build_policy_input(proposal(), context())
    assert doc["proposal"]["evidence_count"] == 3
    assert doc["context"]["authority_level"] == "L4"
    assert doc["context"]["tools"]["disable_account"] == {
        "risk_tier": "high",
        "allowed_arguments": ["user_id"],
    }
    json.dumps(doc)


def test_default_registry_covers_all_ten_tools() -> None:
    registry = default_tool_registry()
    assert len(registry) == 10
    assert registry["revoke_sessions"].risk_tier is RiskTier.LOW


# ----------------------------------------------------------------- HTTP engine with fake transport
def _transport(handler: object) -> httpx.MockTransport:
    return httpx.MockTransport(handler)  # type: ignore[arg-type]


async def test_http_engine_maps_result_to_decision() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["input"]["proposal"]["tool_name"] == "disable_account"
        return httpx.Response(
            200,
            json={
                "result": {
                    "decision": "require_approval",
                    "reason_codes": ["approval_required_high_impact"],
                    "obligations": [],
                    "risk_tier": "high",
                    "policy_version": "test",
                }
            },
        )

    engine = OpaHttpPolicyEngine("http://opa.test", transport=_transport(handler))
    decision = await engine.decide(proposal("disable_account"), context())
    assert decision.outcome is DecisionOutcome.REQUIRE_APPROVAL
    assert decision.risk_tier is RiskTier.HIGH
    assert decision.policy_version == "test"


async def test_http_engine_timeout_is_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    engine = OpaHttpPolicyEngine("http://opa.test", transport=_transport(handler))
    with pytest.raises(PolicyUnavailableError, match="ReadTimeout"):
        await engine.decide(proposal(), context())


async def test_http_engine_unreachable_is_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    engine = OpaHttpPolicyEngine("http://opa.test", transport=_transport(handler))
    with pytest.raises(PolicyUnavailableError, match="ConnectError"):
        await engine.decide(proposal(), context())


@pytest.mark.parametrize(
    "payload",
    [
        {},  # policy not loaded
        {"result": "deny"},  # wrong type
        {
            "result": {
                "decision": "permit",
                "reason_codes": ["x"],
                "obligations": [],
                "risk_tier": "low",
                "policy_version": "v",
            }
        },
        {
            "result": {
                "decision": "allow_with_obligations",
                "reason_codes": ["x"],
                "obligations": [],
                "risk_tier": "low",
                "policy_version": "v",
            }
        },
        {
            "result": {
                "decision": "allow",
                "reason_codes": [],
                "obligations": [],
                "risk_tier": "low",
                "policy_version": "v",
            }
        },
    ],
)
async def test_http_engine_rejects_invalid_documents(payload: dict[str, object]) -> None:
    engine = OpaHttpPolicyEngine(
        "http://opa.test", transport=_transport(lambda r: httpx.Response(200, json=payload))
    )
    with pytest.raises(PolicyUnavailableError):
        await engine.decide(proposal(), context())


async def test_http_engine_server_error_is_unavailable() -> None:
    engine = OpaHttpPolicyEngine(
        "http://opa.test", transport=_transport(lambda r: httpx.Response(500, text="boom"))
    )
    with pytest.raises(PolicyUnavailableError):
        await engine.decide(proposal(), context())


# ----------------------------------------------------------------- exec engine against the real policy
opa_available = pytest.mark.skipif(find_opa_binary() is None, reason="opa binary not installed")


@opa_available
@pytest.mark.policy
async def test_exec_engine_read_only_allowed_with_redaction() -> None:
    decision = await OpaExecPolicyEngine().decide(proposal(), context(AuthorityLevel.L1_OBSERVE))
    assert decision.outcome is DecisionOutcome.ALLOW_WITH_OBLIGATIONS
    assert decision.obligations[0].name == "redact_secrets"
    assert decision.reason_codes == ("read_only_tool",)


@opa_available
@pytest.mark.policy
async def test_exec_engine_high_impact_requires_then_allows_with_approval() -> None:
    engine = OpaExecPolicyEngine()
    first = await engine.decide(proposal("disable_account"), context())
    assert first.outcome is DecisionOutcome.REQUIRE_APPROVAL
    second = await engine.decide(
        proposal("disable_account"), context(approval=ApprovalContext(present=True, valid=True))
    )
    assert second.outcome is DecisionOutcome.ALLOW_WITH_OBLIGATIONS
    assert {o.name for o in second.obligations} == {"record_reversal_plan", "notify_incident_owner"}


@opa_available
@pytest.mark.policy
async def test_exec_engine_cross_incident_and_unknown_tool_denied() -> None:
    engine = OpaExecPolicyEngine()
    cross = await engine.decide(proposal(), context(incident_id="INC-OTHER"))
    assert cross.outcome is DecisionOutcome.DENY
    assert "cross_incident_scope" in cross.reason_codes
    unknown = await engine.decide(proposal("drop_database"), context())
    assert unknown.outcome is DecisionOutcome.DENY
    assert unknown.risk_tier is RiskTier.HIGH


@opa_available
@pytest.mark.policy
async def test_exec_engine_missing_policy_dir_is_unavailable(tmp_path: Path) -> None:
    engine = OpaExecPolicyEngine(policy_dir=tmp_path / "nowhere")
    with pytest.raises(PolicyUnavailableError):
        await engine.decide(proposal(), context())


def test_exec_engine_requires_binary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SOCLAB_OPA_BIN", str(tmp_path / "missing"))
    monkeypatch.setattr("soclab.policy.client.shutil.which", lambda _: None)
    monkeypatch.setattr("soclab.policy.client.REPO_ROOT", tmp_path)
    with pytest.raises(PolicyUnavailableError, match="opa binary not found"):
        OpaExecPolicyEngine()


async def test_exec_engine_bad_binary_is_unavailable(tmp_path: Path) -> None:
    if sys.platform == "win32":
        fake = tmp_path / "opa.cmd"
        fake.write_text("@echo off\r\nexit 3\r\n")
    else:
        fake = tmp_path / "opa"
        fake.write_text("#!/bin/sh\nexit 3\n")
        fake.chmod(0o755)
    engine = OpaExecPolicyEngine(binary=fake)
    with pytest.raises(PolicyUnavailableError, match="exited 3"):
        await engine.decide(proposal(), context())
