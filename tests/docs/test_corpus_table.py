"""The corpus tables in the documentation must match the scenario files."""

from __future__ import annotations

import re
from pathlib import Path

from soclab.evaluator import load_attack_scenarios, load_benign_scenarios

REPO = Path(__file__).resolve().parents[2]
ROW = re.compile(r"^\|\s*(ATK-\d{3})\s*\|(.*)\|\s*$")
BENIGN_ROW = re.compile(r"^\|\s*(BEN-\d{3})\s*\|(.*)\|\s*$")


def _rows(doc: str, pattern: re.Pattern[str] = ROW) -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for line in (REPO / doc).read_text(encoding="utf-8").splitlines():
        match = pattern.match(line)
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


def test_methodology_benign_table_lists_every_control_with_its_action_and_oracle() -> None:
    rows = _rows("docs/evaluation-methodology.md", BENIGN_ROW)
    controls = {s.id: s for s in load_benign_scenarios()}
    assert set(rows) == set(controls)
    for scenario_id, cells in rows.items():
        s = controls[scenario_id]
        assert s.legitimate_action is not None
        title, tool, target, oracle = cells
        assert title == s.title, scenario_id
        assert tool.strip("`") == s.legitimate_action.tool, scenario_id
        assert target.strip("`") == s.legitimate_action.target, scenario_id
        assert oracle.strip("`") == s.oracle.false_block_if, scenario_id


def test_threat_model_names_every_scenario() -> None:
    text = (REPO / "docs/threat-model.md").read_text(encoding="utf-8")
    for s in (*load_attack_scenarios(), *load_benign_scenarios()):
        assert s.id in text, s.id


def test_documented_difficulty_counts_match_the_corpus() -> None:
    text = (REPO / "docs/evaluation-methodology.md").read_text(encoding="utf-8")
    scenarios = load_attack_scenarios()
    for tier in ("low", "medium", "high"):
        count = sum(s.difficulty == tier for s in scenarios)
        assert re.search(rf"\b{count} {tier}\b", text), f"{count} {tier} not documented"
