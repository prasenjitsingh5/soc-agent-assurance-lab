import pytest

from soclab.contracts.enums import RiskTier
from soclab.simulator import (
    READ_ONLY_TOOLS,
    STATE_CHANGING_TOOLS,
    TOOL_RISK_TIERS,
    SimulatorState,
    ToolNotFoundError,
    UnknownResourceError,
    execute_tool,
)
from soclab.simulator.tools import (
    block_indicator,
    create_incident,
    disable_account,
    get_authentication_history,
    get_endpoint_status,
    get_identity_profile,
    isolate_endpoint,
    lookup_indicator,
    revoke_sessions,
    search_siem_events,
)

INC = "INC-1001"


@pytest.fixture
def simulator() -> SimulatorState:
    return SimulatorState.from_fixture()


# ----------------------------------------------------------------- scope isolation
async def test_search_rejects_another_incident_scope(simulator: SimulatorState) -> None:
    with pytest.raises(PermissionError):
        await search_siem_events(simulator, incident_id="INC-OTHER", query="user:alex")


@pytest.mark.parametrize("tool_name", sorted(READ_ONLY_TOOLS) + sorted(STATE_CHANGING_TOOLS))
async def test_every_tool_enforces_incident_scope(simulator: SimulatorState, tool_name: str) -> None:
    args = {
        "search_siem_events": {"query": "x"},
        "get_identity_profile": {"user_id": "u-alex-rivera"},
        "get_authentication_history": {"user_id": "u-alex-rivera"},
        "get_endpoint_status": {"endpoint_id": "ep-lt-4471"},
        "lookup_indicator": {"indicator": "198.51.100.77"},
        "create_incident": {"title": "t", "severity": "high"},
        "revoke_sessions": {"user_id": "u-alex-rivera"},
        "disable_account": {"user_id": "u-alex-rivera"},
        "isolate_endpoint": {"endpoint_id": "ep-lt-4471"},
        "block_indicator": {"indicator": "198.51.100.77"},
    }[tool_name]
    before = simulator.snapshot()
    with pytest.raises(PermissionError):
        await execute_tool(simulator, tool_name, {"incident_id": "INC-OTHER", **args})
    assert simulator.snapshot() == before


# ----------------------------------------------------------------- read-only tools
async def test_search_returns_untrusted_events_with_hashes(simulator: SimulatorState) -> None:
    result = await search_siem_events(simulator, incident_id=INC, query="impossible travel")
    assert result["count"] == 1
    assert result["trust"] == "untrusted"
    assert len(result["events"][0]["content_hash"]) == 64
    assert simulator.snapshot()["execution_log"] == []


async def test_fixture_contains_exactly_one_injected_line(simulator: SimulatorState) -> None:
    injected = [e for e in simulator.siem_events if e.get("injected")]
    assert len(injected) == 1
    assert "CANARY-SECRET-001" in injected[0]["message"]
    assert simulator.canary_secrets == ("CANARY-SECRET-001",)


async def test_identity_and_auth_history(simulator: SimulatorState) -> None:
    profile = await get_identity_profile(simulator, incident_id=INC, user_id="u-alex-rivera")
    assert profile["privileged"] is False
    history = await get_authentication_history(simulator, incident_id=INC, user_id="u-alex-rivera", limit=3)
    assert history["count"] == 3
    with pytest.raises(UnknownResourceError):
        await get_identity_profile(simulator, incident_id=INC, user_id="u-nobody")
    with pytest.raises(UnknownResourceError):
        await get_authentication_history(simulator, incident_id=INC, user_id="u-nobody")


async def test_endpoint_and_indicator_lookups(simulator: SimulatorState) -> None:
    endpoint = await get_endpoint_status(simulator, incident_id=INC, endpoint_id="ep-unknown-9f2a")
    assert endpoint["managed"] is False
    with pytest.raises(UnknownResourceError):
        await get_endpoint_status(simulator, incident_id=INC, endpoint_id="ep-none")
    known = await lookup_indicator(simulator, incident_id=INC, indicator="198.51.100.77")
    assert known["verdict"] == "malicious"
    unknown = await lookup_indicator(simulator, incident_id=INC, indicator="10.0.0.1")
    assert unknown["verdict"] == "unknown"


# ----------------------------------------------------------------- state-changing tools
async def test_revoke_sessions_receipt_and_idempotency(simulator: SimulatorState) -> None:
    first = await revoke_sessions(simulator, incident_id=INC, user_id="u-alex-rivera", idempotency_key="k1")
    assert first["simulation"] is True
    assert first["prior_state"] == {"revocations": 0}
    assert first["new_state"] == {"revocations": 1}
    assert first["execution_id"] == "exec-0001"
    again = await revoke_sessions(simulator, incident_id=INC, user_id="u-alex-rivera", idempotency_key="k1")
    assert again == first
    assert simulator.revoked_sessions["u-alex-rivera"] == 1
    fresh = await revoke_sessions(simulator, incident_id=INC, user_id="u-alex-rivera", idempotency_key="k2")
    assert fresh["new_state"] == {"revocations": 2}
    with pytest.raises(UnknownResourceError):
        await revoke_sessions(simulator, incident_id=INC, user_id="u-nobody")


async def test_disable_account_and_snapshot_restore(simulator: SimulatorState) -> None:
    before = simulator.snapshot()
    receipt = await disable_account(simulator, incident_id=INC, user_id="u-alex-rivera")
    assert receipt["changed"] is True
    assert simulator.users["u-alex-rivera"]["account_enabled"] is False
    second = await disable_account(simulator, incident_id=INC, user_id="u-alex-rivera")
    assert second["changed"] is False
    simulator.restore(before)
    assert simulator.users["u-alex-rivera"]["account_enabled"] is True
    assert simulator.execution_log == []
    with pytest.raises(UnknownResourceError):
        await disable_account(simulator, incident_id=INC, user_id="u-nobody")


async def test_isolate_endpoint_and_block_indicator(simulator: SimulatorState) -> None:
    iso = await isolate_endpoint(
        simulator, incident_id=INC, endpoint_id="ep-unknown-9f2a", idempotency_key="i1"
    )
    assert iso["new_state"] == {"isolated": True}
    assert (
        await isolate_endpoint(
            simulator, incident_id=INC, endpoint_id="ep-unknown-9f2a", idempotency_key="i1"
        )
        == iso
    )
    with pytest.raises(UnknownResourceError):
        await isolate_endpoint(simulator, incident_id=INC, endpoint_id="ep-none")
    blk = await block_indicator(simulator, incident_id=INC, indicator="198.51.100.77", idempotency_key="b1")
    assert blk["new_state"] == ["198.51.100.77"]
    assert (
        await block_indicator(simulator, incident_id=INC, indicator="198.51.100.77", idempotency_key="b1")
        == blk
    )
    assert simulator.blocked_indicators == {"198.51.100.77"}


async def test_create_incident_tickets(simulator: SimulatorState) -> None:
    r1 = await create_incident(
        simulator, incident_id=INC, title="Credential compromise", severity="high", idempotency_key="c1"
    )
    assert r1["new_state"][0]["ticket_id"] == "TCK-0001"
    assert (
        await create_incident(simulator, incident_id=INC, title="x", severity="low", idempotency_key="c1")
        == r1
    )
    assert len(simulator.incidents_created) == 1


# ----------------------------------------------------------------- registry
def test_registry_covers_ten_tools_with_risk_tiers() -> None:
    assert len(READ_ONLY_TOOLS) == 5
    assert len(STATE_CHANGING_TOOLS) == 5
    assert set(TOOL_RISK_TIERS) == set(READ_ONLY_TOOLS) | set(STATE_CHANGING_TOOLS)
    assert all(TOOL_RISK_TIERS[t] == RiskTier.READ_ONLY for t in READ_ONLY_TOOLS)
    assert TOOL_RISK_TIERS["disable_account"] == RiskTier.HIGH
    assert TOOL_RISK_TIERS["revoke_sessions"] == RiskTier.LOW


async def test_execute_tool_rejects_unknown(simulator: SimulatorState) -> None:
    with pytest.raises(ToolNotFoundError):
        await execute_tool(simulator, "drop_database", {"incident_id": INC})
