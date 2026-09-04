"""Shared fixtures. One OPA server per test session keeps policy-backed tests fast."""

from collections.abc import Iterator

import pytest

from soclab.policy import OpaHttpPolicyEngine, find_opa_binary
from soclab.policy.server import ManagedOpaServer


@pytest.fixture(scope="session")
def opa_engine() -> Iterator[OpaHttpPolicyEngine]:
    if find_opa_binary() is None:
        pytest.skip("opa binary not installed")
    with ManagedOpaServer() as engine:
        yield engine
