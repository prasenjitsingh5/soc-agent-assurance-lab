from pathlib import Path
from uuid import UUID, uuid4

import pytest

from soclab.evidence import (
    GENESIS_HASH,
    AuditEvent,
    EvidenceRepository,
    canonical_json,
    payload_hash,
    verify_events,
)


@pytest.fixture
def repository() -> EvidenceRepository:
    return EvidenceRepository()


def seed(repository: EvidenceRepository, n: int = 3) -> UUID:
    run_id = uuid4()
    for i in range(1, n + 1):
        repository.append_event(
            AuditEvent(run_id=run_id, event_type="policy.decision", payload={"step": i, "outcome": "deny"})
        )
    return run_id


# ----------------------------------------------------------------- happy path
def test_chain_links_and_verifies(repository: EvidenceRepository) -> None:
    run_id = seed(repository)
    events = repository.events_for(run_id)
    assert [e.sequence for e in events] == [1, 2, 3]
    assert events[0].previous_hash == GENESIS_HASH
    assert events[1].previous_hash == events[0].event_hash
    assert events[2].previous_hash == events[1].event_hash
    result = repository.verify_chain(run_id)
    assert result.valid is True
    assert result.length == 3
    assert result.root_hash == events[2].event_hash


def test_runs_are_independent_chains(repository: EvidenceRepository) -> None:
    a = seed(repository, 2)
    b = seed(repository, 4)
    assert repository.verify_chain(a).length == 2
    assert repository.verify_chain(b).length == 4
    assert set(repository.run_ids()) == {a, b}
    empty = repository.verify_chain(uuid4())
    assert empty.valid is True and empty.length == 0 and empty.root_hash is None


def test_canonical_json_is_order_independent() -> None:
    assert canonical_json({"b": 1, "a": [1, {"z": 0, "y": 1}]}) == canonical_json(
        {"a": [1, {"y": 1, "z": 0}], "b": 1}
    )
    assert payload_hash({"x": "é"}) == payload_hash({"x": "é"})
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})


def test_file_backed_store_persists(tmp_path: Path) -> None:
    url = f"sqlite+pysqlite:///{tmp_path / 'evidence.sqlite'}"
    run_id = seed(EvidenceRepository(url))
    reopened = EvidenceRepository(url)
    assert reopened.verify_chain(run_id).valid is True


# ----------------------------------------------------------------- tampering
def test_modified_event_breaks_chain(repository: EvidenceRepository) -> None:
    run_id = seed(repository)
    repository.unsafe_modify_for_test(run_id, sequence=2, field="outcome", value="allow")
    result = repository.verify_chain(run_id)
    assert result.valid is False
    assert result.first_invalid_sequence == 2
    assert result.reason == "payload modified"


def test_deleted_event_breaks_chain_at_the_gap(repository: EvidenceRepository) -> None:
    run_id = seed(repository, 4)
    repository.unsafe_delete_for_test(run_id, sequence=2)
    result = repository.verify_chain(run_id)
    assert result.valid is False
    assert result.first_invalid_sequence == 2


def test_deleting_the_last_event_is_detected_by_root_hash(repository: EvidenceRepository) -> None:
    run_id = seed(repository, 3)
    root_before = repository.root_hash(run_id)
    repository.unsafe_delete_for_test(run_id, sequence=3)
    result = repository.verify_chain(run_id)
    # A truncated chain is internally consistent; the published root hash is what exposes it.
    assert result.valid is True
    assert result.length == 2
    assert result.root_hash != root_before


def test_inserted_event_breaks_chain(repository: EvidenceRepository) -> None:
    run_id = seed(repository, 3)
    repository.unsafe_insert_for_test(
        run_id, sequence=2, event_type="policy.decision", payload={"forged": True}
    )
    result = repository.verify_chain(run_id)
    assert result.valid is False
    assert result.first_invalid_sequence == 2


def test_reordered_events_break_chain(repository: EvidenceRepository) -> None:
    run_id = seed(repository, 3)
    repository.unsafe_swap_for_test(run_id, 1, 2)
    result = repository.verify_chain(run_id)
    assert result.valid is False
    assert result.first_invalid_sequence == 1


def test_verify_events_rejects_foreign_run() -> None:
    repo = EvidenceRepository()
    a = seed(repo, 1)
    b = seed(repo, 1)
    mixed = repo.events_for(a) + repo.events_for(b)
    result = verify_events(a, mixed)
    assert result.valid is False
    assert result.first_invalid_sequence == 2
