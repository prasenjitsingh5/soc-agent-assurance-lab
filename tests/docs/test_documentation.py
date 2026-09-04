"""Documentation checks: required files exist, internal links resolve, claims stay honest, commands exist."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

REQUIRED_FILES = [
    "README.md",
    "LICENSE",
    "NOTICE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "CHANGELOG.md",
    ".github/workflows/ci.yml",
    ".github/workflows/security.yml",
    ".github/dependabot.yml",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    "docs/architecture.md",
    "docs/engineering-standards.md",
    "docs/threat-model.md",
    "docs/provider-compatibility.md",
    "docs/evaluation-methodology.md",
    "docs/policy-guide.md",
    "docs/custom-provider.md",
    "docs/demo-script.md",
    "docs/limitations.md",
    "docs/THIRD-PARTY-NOTICES.md",
    "docs/PROJECT-ACCEPTANCE.md",
    "docs/adr/0001-single-python-package.md",
]

FORBIDDEN_CLAIMS = [
    r"\bproduction[- ]ready\b",
    r"\benterprise[- ]grade\b",
    r"\bunhackable\b",
    r"\bfully compliant\b",
    r"\bcertified secure\b",
    r"\bguarantee[sd]? security\b",
]

PUBLIC_DOCS = [
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    *[str(p.relative_to(REPO)) for p in (REPO / "docs").glob("*.md")],
]


@pytest.mark.parametrize("path", REQUIRED_FILES)
def test_required_file_exists(path: str) -> None:
    assert (REPO / path).exists(), path


@pytest.mark.parametrize("doc", PUBLIC_DOCS)
def test_internal_links_resolve(doc: str) -> None:
    text = (REPO / doc).read_text(encoding="utf-8")
    for target in re.findall(r"\]\((?!https?://|mailto:)([^)#]+)(?:#[^)]*)?\)", text):
        resolved = (REPO / doc).parent / target
        assert resolved.exists(), f"{doc} links to missing {target}"


@pytest.mark.parametrize("doc", PUBLIC_DOCS)
def test_no_unsupported_claims(doc: str) -> None:
    text = (REPO / doc).read_text(encoding="utf-8").lower()
    for pattern in FORBIDDEN_CLAIMS:
        for match in re.finditer(pattern, text):
            context = text[max(0, match.start() - 60) : match.end() + 60]
            # Allowed only when the document is telling the reader NOT to use the phrase.
            assert any(word in context for word in ("avoid", "not ", "never", "no claim")), (
                f"{doc}: {context!r}"
            )


def test_documented_make_targets_exist() -> None:
    makefile = (REPO / "Makefile").read_text(encoding="utf-8")
    targets = set(re.findall(r"^([a-z][a-z-]*):", makefile, flags=re.M))
    for required in (
        "bootstrap",
        "lint",
        "typecheck",
        "test",
        "policy-test",
        "security",
        "sbom",
        "up",
        "down",
        "demo",
        "verify",
    ):
        assert required in targets, required
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    for used in re.findall(r"\bmake ([a-z-]+)", readme):
        assert used in targets, f"README uses undefined make target {used}"


def test_documented_cli_commands_exist() -> None:
    from typer.main import get_command

    from soclab.cli import app

    commands = set(get_command(app).commands)  # type: ignore[attr-defined]
    docs = "\n".join((REPO / p).read_text(encoding="utf-8") for p in ("README.md", "docs/demo-script.md"))
    for used in set(re.findall(r"soclab ([a-z][a-z-]+)", docs)):
        assert used in commands, f"docs reference unknown command soclab {used}"


def test_status_labels_are_used_in_architecture_doc() -> None:
    text = (REPO / "docs/architecture.md").read_text(encoding="utf-8")
    for label in ("implemented", "simulated", "planned"):
        assert label in text


def test_readme_leads_with_the_decision_not_the_stack() -> None:
    lines = [line for line in (REPO / "README.md").read_text(encoding="utf-8").splitlines() if line.strip()]
    first_paragraph = " ".join(lines[1:6]).lower()
    assert "authority" in first_paragraph or "decision" in first_paragraph
