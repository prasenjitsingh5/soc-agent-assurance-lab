"""Deterministic synthetic SOC environment.

Everything here is fixture driven. Nothing connects to a real SIEM, identity
provider, endpoint agent or threat-intelligence service. State-changing tools
modify in-memory simulated state and return receipts marked ``simulation=True``.
"""

from soclab.simulator.state import SimulatorState, load_fixture
from soclab.simulator.tools import (
    READ_ONLY_TOOLS,
    STATE_CHANGING_TOOLS,
    TOOL_RISK_TIERS,
    ToolError,
    ToolNotFoundError,
    UnknownResourceError,
    execute_tool,
)

__all__ = [
    "READ_ONLY_TOOLS",
    "STATE_CHANGING_TOOLS",
    "TOOL_RISK_TIERS",
    "SimulatorState",
    "ToolError",
    "ToolNotFoundError",
    "UnknownResourceError",
    "execute_tool",
    "load_fixture",
]
