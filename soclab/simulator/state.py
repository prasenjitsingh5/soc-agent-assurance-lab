"""In-memory simulated enterprise state with snapshot and restore."""

from __future__ import annotations

import copy
import json
import unicodedata
from pathlib import Path
from typing import Any

FIXTURE_DIR = Path(__file__).parent / "fixtures"

# Characters from other scripts that render like Latin letters. A lenient directory
# lookup folds them, which is exactly what makes them dangerous for string-keyed policy.
_CONFUSABLES = str.maketrans(
    {
        "а": "a",  # Cyrillic a
        "е": "e",  # Cyrillic ie
        "о": "o",  # Cyrillic o
        "р": "p",  # Cyrillic er
        "с": "c",  # Cyrillic es
        "у": "y",  # Cyrillic u
        "х": "x",  # Cyrillic ha
        "і": "i",  # Cyrillic byelorussian-ukrainian i
        "ѕ": "s",  # Cyrillic dze
        "ј": "j",  # Cyrillic je
        "һ": "h",  # Cyrillic shha
        "ο": "o",  # Greek omicron
        "α": "a",  # Greek alpha
        "ν": "v",  # Greek nu
    }
)


def fold_identifier(value: str) -> str:
    """Case fold, NFKC normalize and map common cross-script confusables to ASCII."""
    return unicodedata.normalize("NFKC", value).translate(_CONFUSABLES).casefold()


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

    Fixtures may declare named ``injections``: untrusted payloads that are only
    present when a scenario asks for them. ``apply_injection`` merges one into
    the live state so the same fixture serves every attack channel without the
    channels contaminating each other.
    """

    def __init__(self, fixture: dict[str, Any], *, enforce_scope: bool = True) -> None:
        self._fixture = copy.deepcopy(fixture)
        self.enforce_scope = enforce_scope
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
        declared = self._fixture.get("protected_assets", {})
        self.protected_assets: dict[str, list[str]] = {
            "user_ids": list(declared.get("user_ids", [])),
            "endpoint_ids": list(declared.get("endpoint_ids", [])),
            "indicators": list(declared.get("indicators", [])),
        }
        self.injections: dict[str, list[dict[str, Any]]] = self._fixture.get("injections", {})
        self.applied_injections: list[str] = []
        # Mutable simulated control state.
        self.revoked_sessions: dict[str, int] = {}
        self.blocked_indicators: set[str] = set()
        self.incidents_created: list[dict[str, Any]] = []
        self.execution_log: list[dict[str, Any]] = []
        self.access_log: list[dict[str, Any]] = []

    @classmethod
    def from_fixture(
        cls,
        name: str = "identity_compromise",
        *,
        enforce_scope: bool = True,
        injections: tuple[str, ...] = (),
    ) -> SimulatorState:
        state = cls(load_fixture(name), enforce_scope=enforce_scope)
        for key in injections:
            state.apply_injection(key)
        return state

    def apply_injection(self, key: str) -> None:
        """Merge one named untrusted payload into the live state. Unknown keys raise."""
        operations = self.injections.get(key)
        if operations is None:
            msg = f"fixture declares no injection {key!r}"
            raise KeyError(msg)
        collections: dict[str, Any] = {
            "users": self.users,
            "endpoints": self.endpoints,
            "indicators": self.indicators,
            "incident": self.incident,
        }
        for op in operations:
            kind = op["op"]
            if kind == "insert_siem_event":
                self.siem_events.insert(int(op.get("index", 0)), copy.deepcopy(op["event"]))
            elif kind == "set":
                path = list(op["path"])
                target: Any = collections[path[0]]
                for segment in path[1:-1]:
                    target = target[segment]
                target[path[-1]] = copy.deepcopy(op["value"])
            else:
                msg = f"unknown injection operation {kind!r}"
                raise ValueError(msg)
        self.applied_injections.append(key)

    def assert_incident(self, incident_id: str) -> None:
        """Refuse calls for any other incident. Baseline mode disables this to model tools without tenancy."""
        if self.enforce_scope and incident_id != self.incident_id:
            msg = f"incident {incident_id!r} is outside this simulator's scope ({self.incident_id!r})"
            raise PermissionError(msg)

    def resolve_user_id(self, user_id: str) -> str | None:
        """Directory lookup that folds case and confusables, as lenient directories do.

        Returns the canonical id or None. The folding is deliberate: it models the
        gap between a directory that resolves lookalike identifiers and a policy
        that compares strings, which is the gap the confusable-identifier scenario
        measures.
        """
        if user_id in self.users:
            return user_id
        wanted = fold_identifier(user_id)
        for known in self.users:
            if fold_identifier(known) == wanted:
                return known
        return None

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
                "access_log": self.access_log,
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
        self.access_log = data.get("access_log", [])
