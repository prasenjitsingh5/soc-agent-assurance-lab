"""The corpus tables in the documentation must match the scenario files."""

from __future__ import annotations

import re
from pathlib import Path

from soclab.evaluator import load_attack_scenarios

REPO = Path(__file__).resolve().parents[2]
ROW = re.compile(r"^\|\s*(ATK-\d{3})\s*\|(.*)\|\s*$")


def _rows(doc: str) -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for line in (REPO / doc).read_text(encoding="utf-8").splitlines():
        match = ROW.match(line)
        if match:
            rows[match.group(1)] = [cell.strip() for cell in match.group(2).split("|")]
    return rows


def test_methodology_table_lists_every_scenario_with_family_difficulty_and_references() -> None:
    rows = _rows("docs/evaluation-methodology.md")
    scenarios = {s.id: s for s in load_attack_scenarios()}
    assert set(rows) == set(scenarios)
    for scenario_id, cells in rows.items():
        s = scenarios[scenario_id]
        title, family, difficulty, atlas, owasp = cells
        assert title == s.title, scenario_id
        assert family == s.family, scenario_id
        assert difficulty == s.difficulty, scenario_id
        assert set(atlas.split(", ")) == {a.id for a in s.atlas}, scenario_id
        assert set(owasp.split(", ")) == {o.id for o in s.owasp_llm}, scenario_id


def test_threat_model_names_every_scenario() -> None:
    text = (REPO / "docs/threat-model.md").read_text(encoding="utf-8")
    for s in load_attack_scenarios():
        assert s.id in text, s.id


def test_documented_difficulty_counts_match_the_corpus() -> None:
    text = (REPO / "docs/evaluation-methodology.md").read_text(encoding="utf-8")
    scenarios = load_attack_scenarios()
    for tier in ("low", "medium", "high"):
        count = sum(s.difficulty == tier for s in scenarios)
        assert re.search(rf"\b{count} {tier}\b", text), f"{count} {tier} not documented"
