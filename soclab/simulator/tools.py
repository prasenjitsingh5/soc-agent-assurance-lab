"""The ten simulated SOC tools.

Read-only tools return copies of fixture data with a trust label. State-changing
tools mutate simulated state and return a receipt with ``simulation=True``,
the prior state, the new state and an execution id. Retrying a state-changing
tool with the same ``idempotency_key`` returns the original receipt without a
second mutation.

This module has no knowledge of policy. Authorization happens in the gateway;
the executor is the only caller in production paths. Tests call it directly.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable
from typing import Any

from soclab.contracts.enums import RiskTier
from soclab.simulator.state import SimulatorState


class ToolError(Exception):
    """Base for simulator errors surfaced to the executor."""


class ToolNotFoundError(ToolError):
    pass


class UnknownResourceError(ToolError):
    pass


def _hash(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


def _record(state: SimulatorState, tool: str, args: dict[str, Any]) -> str:
    execution_id = f"exec-{len(state.execution_log) + 1:04d}"
    state.execution_log.append({"execution_id": execution_id, "tool": tool, "arguments": args})
    return execution_id


def _receipt(
    state: SimulatorState, tool: str, args: dict[str, Any], before: Any, after: Any
) -> dict[str, Any]:
    return {
        "simulation": True,
        "tool": tool,
        "execution_id": _record(state, tool, args),
        "prior_state": before,
        "new_state": after,
        "changed": before != after,
    }


def _idempotent(state: SimulatorState, key: str | None) -> dict[str, Any] | None:
    if key is None:
        return None
    for entry in state.execution_log:
        if entry.get("idempotency_key") == key:
            receipt: dict[str, Any] = entry["receipt"]
            return receipt
    return None


def _remember(state: SimulatorState, key: str | None, receipt: dict[str, Any]) -> dict[str, Any]:
    if key is not None:
        state.execution_log[-1]["idempotency_key"] = key
        state.execution_log[-1]["receipt"] = receipt
    return receipt


# --------------------------------------------------------------------------- #
# Read-only tools
# --------------------------------------------------------------------------- #
async def search_siem_events(
    state: SimulatorState, *, incident_id: str, query: str, **_: Any
) -> dict[str, Any]:
    state.assert_incident(incident_id)
    state.access_log.append({"tool": "search_siem_events", "incident_id": incident_id, "query": query})
    terms = [t.strip().lower() for t in query.split() if t.strip()]
    hits = []
    for event in state.siem_events:
        haystack = json.dumps(event).lower()
        if all(term in haystack for term in terms):
            hits.append({**event, "content_hash": _hash(event)})
    return {"query": query, "count": len(hits), "events": hits, "trust": "untrusted"}


async def get_identity_profile(
    state: SimulatorState, *, incident_id: str, user_id: str, **_: Any
) -> dict[str, Any]:
    state.assert_incident(incident_id)
    state.access_log.append({"tool": "get_identity_profile", "incident_id": incident_id, "user_id": user_id})
    user = state.users.get(user_id)
    if user is None:
        raise UnknownResourceError(f"unknown user {user_id!r}")
    return {**user, "content_hash": _hash(user), "trust": "untrusted"}


async def get_authentication_history(
    state: SimulatorState, *, incident_id: str, user_id: str, limit: int = 50, **_: Any
) -> dict[str, Any]:
    state.assert_incident(incident_id)
    state.access_log.append(
        {"tool": "get_authentication_history", "incident_id": incident_id, "user_id": user_id}
    )
    if user_id not in state.users:
        raise UnknownResourceError(f"unknown user {user_id!r}")
    events = [e for e in state.authentication_events if e["user_id"] == user_id][: max(1, limit)]
    return {
        "user_id": user_id,
        "count": len(events),
        "events": events,
        "content_hash": _hash(events),
        "trust": "untrusted",
    }


async def get_endpoint_status(
    state: SimulatorState, *, incident_id: str, endpoint_id: str, **_: Any
) -> dict[str, Any]:
    state.assert_incident(incident_id)
    state.access_log.append(
        {"tool": "get_endpoint_status", "incident_id": incident_id, "endpoint_id": endpoint_id}
    )
    endpoint = state.endpoints.get(endpoint_id)
    if endpoint is None:
        raise UnknownResourceError(f"unknown endpoint {endpoint_id!r}")
    return {**endpoint, "content_hash": _hash(endpoint), "trust": "untrusted"}


async def lookup_indicator(
    state: SimulatorState, *, incident_id: str, indicator: str, **_: Any
) -> dict[str, Any]:
    state.assert_incident(incident_id)
    state.access_log.append({"tool": "lookup_indicator", "incident_id": incident_id, "indicator": indicator})
    record = state.indicators.get(indicator)
    if record is None:
        return {
            "indicator": indicator,
            "verdict": "unknown",
            "confidence": 0.0,
            "tags": [],
            "trust": "untrusted",
        }
    return {**record, "content_hash": _hash(record), "trust": "untrusted"}


# --------------------------------------------------------------------------- #
# State-changing tools
# --------------------------------------------------------------------------- #
async def create_incident(
    state: SimulatorState,
    *,
    incident_id: str,
    title: str,
    severity: str,
    idempotency_key: str | None = None,
    **_: Any,
) -> dict[str, Any]:
    state.assert_incident(incident_id)
    if (cached := _idempotent(state, idempotency_key)) is not None:
        return cached
    before = list(state.incidents_created)
    ticket = {
        "ticket_id": f"TCK-{len(state.incidents_created) + 1:04d}",
        "title": title,
        "severity": severity,
    }
    state.incidents_created.append(ticket)
    receipt = _receipt(
        state,
        "create_incident",
        {"title": title, "severity": severity},
        before,
        list(state.incidents_created),
    )
    return _remember(state, idempotency_key, receipt)


async def revoke_sessions(
    state: SimulatorState, *, incident_id: str, user_id: str, idempotency_key: str | None = None, **_: Any
) -> dict[str, Any]:
    state.assert_incident(incident_id)
    if user_id not in state.users:
        raise UnknownResourceError(f"unknown user {user_id!r}")
    if (cached := _idempotent(state, idempotency_key)) is not None:
        return cached
    before = state.revoked_sessions.get(user_id, 0)
    state.revoked_sessions[user_id] = before + 1
    receipt = _receipt(
        state, "revoke_sessions", {"user_id": user_id}, {"revocations": before}, {"revocations": before + 1}
    )
    return _remember(state, idempotency_key, receipt)


async def disable_account(
    state: SimulatorState, *, incident_id: str, user_id: str, idempotency_key: str | None = None, **_: Any
) -> dict[str, Any]:
    state.assert_incident(incident_id)
    user = state.users.get(user_id)
    if user is None:
        raise UnknownResourceError(f"unknown user {user_id!r}")
    if (cached := _idempotent(state, idempotency_key)) is not None:
        return cached
    before = {"account_enabled": user["account_enabled"]}
    user["account_enabled"] = False
    receipt = _receipt(state, "disable_account", {"user_id": user_id}, before, {"account_enabled": False})
    return _remember(state, idempotency_key, receipt)


async def isolate_endpoint(
    state: SimulatorState, *, incident_id: str, endpoint_id: str, idempotency_key: str | None = None, **_: Any
) -> dict[str, Any]:
    state.assert_incident(incident_id)
    endpoint = state.endpoints.get(endpoint_id)
    if endpoint is None:
        raise UnknownResourceError(f"unknown endpoint {endpoint_id!r}")
    if (cached := _idempotent(state, idempotency_key)) is not None:
        return cached
    before = {"isolated": endpoint["isolated"]}
    endpoint["isolated"] = True
    receipt = _receipt(state, "isolate_endpoint", {"endpoint_id": endpoint_id}, before, {"isolated": True})
    return _remember(state, idempotency_key, receipt)


async def block_indicator(
    state: SimulatorState, *, incident_id: str, indicator: str, idempotency_key: str | None = None, **_: Any
) -> dict[str, Any]:
    state.assert_incident(incident_id)
    if (cached := _idempotent(state, idempotency_key)) is not None:
        return cached
    before = sorted(state.blocked_indicators)
    state.blocked_indicators.add(indicator)
    receipt = _receipt(
        state, "block_indicator", {"indicator": indicator}, before, sorted(state.blocked_indicators)
    )
    return _remember(state, idempotency_key, receipt)


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
ToolFn = Callable[..., Awaitable[dict[str, Any]]]

READ_ONLY_TOOLS: dict[str, ToolFn] = {
    "search_siem_events": search_siem_events,
    "get_identity_profile": get_identity_profile,
    "get_authentication_history": get_authentication_history,
    "get_endpoint_status": get_endpoint_status,
    "lookup_indicator": lookup_indicator,
}

STATE_CHANGING_TOOLS: dict[str, ToolFn] = {
    "create_incident": create_incident,
    "revoke_sessions": revoke_sessions,
    "disable_account": disable_account,
    "isolate_endpoint": isolate_endpoint,
    "block_indicator": block_indicator,
}

TOOL_RISK_TIERS: dict[str, RiskTier] = {
    **{name: RiskTier.READ_ONLY for name in READ_ONLY_TOOLS},
    "create_incident": RiskTier.LOW,
    "revoke_sessions": RiskTier.LOW,
    "disable_account": RiskTier.HIGH,
    "isolate_endpoint": RiskTier.HIGH,
    "block_indicator": RiskTier.HIGH,
}

ALL_TOOLS: dict[str, ToolFn] = {**READ_ONLY_TOOLS, **STATE_CHANGING_TOOLS}


async def execute_tool(state: SimulatorState, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Dispatch by name. Unknown tools raise; nothing is guessed."""
    fn = ALL_TOOLS.get(tool_name)
    if fn is None:
        raise ToolNotFoundError(f"unknown tool {tool_name!r}")
    return await fn(state, **arguments)
