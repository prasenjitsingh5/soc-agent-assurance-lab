"""In-memory simulated enterprise state with snapshot and restore."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str = "identity_compromise") -> dict[str, Any]:
    """Load a named fixture. Fixtures are the only source of simulated data."""
    path = FIXTURE_DIR / f"{name}.json"
    with path.open(encoding="utf-8") as handle:
        data: dict[str, Any] = json.load(handle)
    return data


class SimulatorState:
    """Mutable simulated state for one incident.

    The state knows which incident it belongs to. Every tool call carries an
    incident id and the state refuses calls for any other incident, which is
    the first line of cross-incident isolation. The gateway enforces the same
    rule independently so the simulator is never the only control.
    """

    def __init__(self, fixture: dict[str, Any]) -> None:
        self._fixture = copy.deepcopy(fixture)
        self.incident_id: str = self._fixture["incident"]["incident_id"]
        self.fixture_version: str = self._fixture["fixture_version"]
        self.users: dict[str, dict[str, Any]] = self._fixture["users"]
        self.endpoints: dict[str, dict[str, Any]] = self._fixture["endpoints"]
        self.indicators: dict[str, dict[str, Any]] = self._fixture["indicators"]
        self.authentication_events: list[dict[str, Any]] = self._fixture["authentication_events"]
        self.siem_events: list[dict[str, Any]] = self._fixture["siem_events"]
        self.incident: dict[str, Any] = self._fixture["incident"]
        self.attack_mapping: list[dict[str, Any]] = self._fixture["attack_mapping"]
        self.canary_secrets: tuple[str, ...] = tuple(self._fixture.get("canary_secrets", []))
        # Mutable simulated control state.
        self.revoked_sessions: dict[str, int] = {}
        self.blocked_indicators: set[str] = set()
        self.incidents_created: list[dict[str, Any]] = []
        self.execution_log: list[dict[str, Any]] = []

    @classmethod
    def from_fixture(cls, name: str = "identity_compromise") -> SimulatorState:
        return cls(load_fixture(name))

    def assert_incident(self, incident_id: str) -> None:
        if incident_id != self.incident_id:
            msg = f"incident {incident_id!r} is outside this simulator's scope ({self.incident_id!r})"
            raise PermissionError(msg)

    def snapshot(self) -> dict[str, Any]:
        """Deep copy of everything that can change. Used for before/after assertions and restore."""
        return copy.deepcopy(
            {
                "users": self.users,
                "endpoints": self.endpoints,
                "revoked_sessions": self.revoked_sessions,
                "blocked_indicators": sorted(self.blocked_indicators),
                "incidents_created": self.incidents_created,
                "execution_log": self.execution_log,
            }
        )

    def restore(self, snapshot: dict[str, Any]) -> None:
        data = copy.deepcopy(snapshot)
        self.users = data["users"]
        self.endpoints = data["endpoints"]
        self.revoked_sessions = data["revoked_sessions"]
        self.blocked_indicators = set(data["blocked_indicators"])
        self.incidents_created = data["incidents_created"]
        self.execution_log = data["execution_log"]
