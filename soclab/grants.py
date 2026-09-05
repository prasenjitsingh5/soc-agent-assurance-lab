"""Short-lived signed execution grants.

The gateway signs a grant only after policy and approval checks pass. The
executor verifies the signature, the proposal hash, the tool, the incident and
the expiry before touching the simulator, and refuses to honor the same grant
twice. The signing key is held by the gateway and the executor. The
orchestrator and the model never see it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from pydantic import Field

from soclab.contracts import ActionProposal, StrictModel


class GrantVerificationError(Exception):
    pass


def proposal_hash(proposal: ActionProposal) -> str:
    """Hash of the fields a grant binds to. Changing any of them invalidates the grant."""
    bound = {
        "proposal_id": str(proposal.proposal_id),
        "incident_id": proposal.incident_id,
        "tool_name": proposal.tool_name,
        "arguments": proposal.arguments,
        "agent_id": proposal.agent_id,
        "delegated_user_id": proposal.delegated_user_id,
    }
    return hashlib.sha256(json.dumps(bound, sort_keys=True, default=str).encode()).hexdigest()


class ExecutionGrant(StrictModel):
    grant_id: UUID = Field(default_factory=uuid4)
    proposal_id: UUID
    proposal_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    incident_id: str
    tool_name: str
    policy_version: str
    approval_id: UUID | None = None
    obligations_fulfilled: tuple[str, ...] = ()
    issued_at: datetime
    expires_at: datetime
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")

    def signing_payload(self) -> bytes:
        body = self.model_dump(mode="json", exclude={"signature"})
        return json.dumps(body, sort_keys=True).encode()


class GrantSigner:
    """HMAC-SHA256 over the grant body. Keys are bytes, never logged."""

    def __init__(self, key: bytes | None = None, *, ttl_seconds: int = 60) -> None:
        if key is not None and len(key) < 32:
            msg = "grant signing key must be at least 32 bytes"
            raise ValueError(msg)
        self._key = key or secrets.token_bytes(32)
        self._ttl = ttl_seconds

    @classmethod
    def from_environment(cls, *, ttl_seconds: int = 60) -> GrantSigner:
        """Build a signer from ``SOCLAB_GRANT_SIGNING_KEY`` when it is set.

        The variable holds the raw key text; it must be at least 32 bytes once
        encoded. When it is absent or blank a fresh random key is generated for
        this process, which is the right default for a single-process run. The
        key value is never logged.
        """
        raw = os.environ.get("SOCLAB_GRANT_SIGNING_KEY", "").strip()
        if not raw:
            return cls(ttl_seconds=ttl_seconds)
        return cls(raw.encode("utf-8"), ttl_seconds=ttl_seconds)

    def issue(
        self,
        proposal: ActionProposal,
        *,
        policy_version: str,
        approval_id: UUID | None,
        obligations_fulfilled: tuple[str, ...],
        now: datetime | None = None,
    ) -> ExecutionGrant:
        issued = now or datetime.now(tz=UTC)
        unsigned = ExecutionGrant(
            proposal_id=proposal.proposal_id,
            proposal_hash=proposal_hash(proposal),
            incident_id=proposal.incident_id,
            tool_name=proposal.tool_name,
            policy_version=policy_version,
            approval_id=approval_id,
            obligations_fulfilled=obligations_fulfilled,
            issued_at=issued,
            expires_at=issued + timedelta(seconds=self._ttl),
            signature="0" * 64,
        )
        return unsigned.model_copy(update={"signature": self._sign(unsigned)})

    def _sign(self, grant: ExecutionGrant) -> str:
        return hmac.new(self._key, grant.signing_payload(), hashlib.sha256).hexdigest()

    def verify(self, grant: ExecutionGrant, proposal: ActionProposal, *, now: datetime | None = None) -> None:
        """Raise GrantVerificationError unless the grant is authentic, unexpired and bound to the proposal."""
        moment = now or datetime.now(tz=UTC)
        if not hmac.compare_digest(self._sign(grant), grant.signature):
            msg = "grant signature invalid"
            raise GrantVerificationError(msg)
        if moment >= grant.expires_at:
            msg = "grant expired"
            raise GrantVerificationError(msg)
        if grant.proposal_id != proposal.proposal_id:
            msg = "grant is for a different proposal"
            raise GrantVerificationError(msg)
        if grant.proposal_hash != proposal_hash(proposal):
            msg = "proposal changed after the grant was issued"
            raise GrantVerificationError(msg)
        if grant.incident_id != proposal.incident_id or grant.tool_name != proposal.tool_name:
            msg = "grant scope does not match the proposal"
            raise GrantVerificationError(msg)
