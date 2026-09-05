"""SOC Agent Assurance Lab.

A model-agnostic laboratory for measuring whether an AI security-operations
agent has earned a defined level of operational authority.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("soclab")
except PackageNotFoundError:  # pragma: no cover - only when imported from an uninstalled checkout
    __version__ = "0.0.0"
