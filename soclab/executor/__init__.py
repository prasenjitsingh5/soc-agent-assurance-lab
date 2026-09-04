"""Isolated executor: the only component that changes simulated state."""

from soclab.executor.service import AuthorizationError, Executor

__all__ = ["AuthorizationError", "Executor"]
