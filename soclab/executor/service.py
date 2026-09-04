"""The executor trusts nothing it is handed except a grant it can verify itself."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from soclab.contracts import ActionProposal
from soclab.grants import ExecutionGrant, GrantSigner, GrantVerificationError
from soclab.simulator import STATE_CHANGING_TOOLS, SimulatorState, ToolError, execute_tool


class AuthorizationError(Exception):
    pass


class Executor:
    """Runs approved simulated actions.

    The executor holds the simulator and a verifier for grants. It refuses any
    state-changing call without a valid grant, refuses a grant it has already
    honored, and passes the incident id from the proposal so the simulator's
    own scope check runs as well.
    """

    def __init__(self, simulator: SimulatorState, signer: GrantSigner) -> None:
        self._simulator = simulator
        self._signer = signer
        self._honored: set[UUID] = set()
        self.receipts: list[dict[str, Any]] = []

    async def execute(
        self, proposal: ActionProposal, grant: ExecutionGrant | None, *, now: datetime | None = None
    ) -> dict[str, Any]:
        state_changing = proposal.tool_name in STATE_CHANGING_TOOLS
        if grant is None:
            msg = f"no execution grant for {proposal.tool_name}"
            raise AuthorizationError(msg)
        try:
            self._signer.verify(grant, proposal, now=now)
        except GrantVerificationError as exc:
            raise AuthorizationError(str(exc)) from exc
        if grant.grant_id in self._honored:
            msg = "grant already used"
            raise AuthorizationError(msg)
        self._honored.add(grant.grant_id)

        arguments: dict[str, Any] = {"incident_id": proposal.incident_id, **proposal.arguments}
        if state_changing:
            arguments["idempotency_key"] = str(proposal.proposal_id)
        try:
            result = await execute_tool(self._simulator, proposal.tool_name, arguments)
        except (ToolError, PermissionError, TypeError) as exc:
            raise AuthorizationError(f"{type(exc).__name__}: {exc}") from exc
        if state_changing:
            self.receipts.append({**result, "grant_id": str(grant.grant_id)})
        return result
