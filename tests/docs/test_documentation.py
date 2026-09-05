"""Documentation checks: required files exist, internal links resolve, claims stay honest, commands exist."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]

REQUIRED_FILES = [
    "README.md",
    "LICENSE",
    "NOTICE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "DISCLAIMER.md",
    "CHANGELOG.md",
    "mkdocs.yml",
    "docs/index.md",
    "docs/quickstart.md",
    "docs/assets/logo.png",
    "docs/assets/social-preview.png",
    "scripts/make_social_preview.py",
    ".devcontainer/devcontainer.json",
    ".devcontainer/post-create.sh",
    ".devcontainer/README.md",
    ".github/workflows/ci.yml",
    ".github/workflows/security.yml",
    ".github/workflows/docs.yml",
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
    "DISCLAIMER.md",
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


class _MkDocsLoader(yaml.SafeLoader):
    """SafeLoader that keeps MkDocs-specific tags such as ``!relative`` as plain strings."""


def _keep_tagged_scalar(loader: yaml.SafeLoader, tag_suffix: str, node: yaml.Node) -> str:
    assert isinstance(node, yaml.ScalarNode)
    return str(loader.construct_scalar(node))


_MkDocsLoader.add_multi_constructor("!", _keep_tagged_scalar)


def _load_mkdocs_config() -> dict[str, Any]:
    config = yaml.load((REPO / "mkdocs.yml").read_text(encoding="utf-8"), Loader=_MkDocsLoader)  # noqa: S506
    assert isinstance(config, dict)
    return config


def _nav_pages(nav: Any) -> list[str]:
    """Flatten a MkDocs nav into the list of page paths it references."""
    pages: list[str] = []
    if isinstance(nav, str):
        pages.append(nav)
    elif isinstance(nav, list):
        for item in nav:
            pages.extend(_nav_pages(item))
    elif isinstance(nav, dict):
        for value in nav.values():
            pages.extend(_nav_pages(value))
    return pages


def test_every_page_in_mkdocs_nav_exists() -> None:
    config = _load_mkdocs_config()
    docs_dir = REPO / str(config.get("docs_dir", "docs"))
    pages = _nav_pages(config["nav"])
    assert pages, "mkdocs.yml nav is empty"
    for page in pages:
        assert (docs_dir / page).is_file(), f"mkdocs.yml nav lists missing page {page}"
    for required in (
        "index.md",
        "quickstart.md",
        "architecture.md",
        "threat-model.md",
        "evaluation-methodology.md",
        "policy-guide.md",
        "custom-provider.md",
        "provider-compatibility.md",
        "demo-script.md",
        "limitations.md",
        "engineering-standards.md",
        "adr/0001-single-python-package.md",
        "releases/0.1.0-evidence.md",
        "DISCLAIMER.md",
        "SECURITY.md",
    ):
        assert required in pages, f"mkdocs.yml nav does not list {required}"


def test_docs_site_loads_nothing_from_third_parties() -> None:
    config = _load_mkdocs_config()
    assert config["theme"]["name"] == "material"
    assert config["theme"]["font"] is False, "theme.font must be false so no web fonts are fetched"
    assert config["plugins"] == ["search"], "only the built-in search plugin is allowed"
    assert config["site_url"] == "https://prasenjitsingh5.github.io/soc-agent-assurance-lab/"
    assert "analytics" not in config.get("extra", {}), "no analytics provider may be configured"
    text = (REPO / "mkdocs.yml").read_text(encoding="utf-8").lower()
    for forbidden in ("googleapis", "gstatic", "cdn.jsdelivr", "unpkg.com", "cdnjs"):
        assert forbidden not in text, forbidden


def test_docs_index_is_a_landing_page_not_the_readme() -> None:
    index = (REPO / "docs/index.md").read_text(encoding="utf-8")
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert index != readme
    assert "## What is in the box" not in index
    assert "five minute path" in index.lower()
    for link in ("quickstart.md", "architecture.md", "limitations.md", "DISCLAIMER.md", "SECURITY.md"):
        assert f"({link})" in index, f"docs/index.md must link to {link}"


def test_docs_workflow_pins_every_action_to_a_commit_sha() -> None:
    text = (REPO / ".github/workflows/docs.yml").read_text(encoding="utf-8")
    uses = re.findall(r"uses:\s*(\S+)(.*)", text)
    assert uses, "docs.yml declares no actions"
    for ref, trailer in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), f"{ref} is not pinned to a commit SHA"
        assert re.search(r"#\s*v\d", trailer), f"{ref} lacks a version comment"
    assert "actions/upload-pages-artifact@" in text
    assert "actions/deploy-pages@" in text
    assert "mkdocs build --strict" in text
    assert "group: pages" in text
    config = yaml.safe_load(text)
    assert config["permissions"] == {"contents": "read", "pages": "write", "id-token": "write"}


def test_devcontainer_is_pinned_and_checks_the_opa_download() -> None:
    container = json.loads((REPO / ".devcontainer/devcontainer.json").read_text(encoding="utf-8"))
    image = container["image"]
    assert re.fullmatch(r"python:3\.12\.\d+-[a-z]+", image), f"image {image} is not a pinned Python 3.12 tag"
    assert 8000 in container["forwardPorts"]
    assert "post-create.sh" in container["postCreateCommand"]
    script = (REPO / ".devcontainer/post-create.sh").read_text(encoding="utf-8")
    assert "uv sync --all-extras" in script
    assert 'OPA_VERSION="v1.20.2"' in script
    assert re.search(r'OPA_SHA256="[0-9a-f]{64}"', script)
    assert "sha256sum -c" in script


def test_docs_extra_pins_exact_versions() -> None:
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    block = re.search(r"^docs = \[(.*?)^\]", pyproject, flags=re.M | re.S)
    assert block, "pyproject.toml has no docs extra"
    entries = re.findall(r'"([^"]+)"', block.group(1))
    names = {entry.split("==")[0].lower() for entry in entries}
    assert {"mkdocs", "mkdocs-material", "pillow"} <= names
    for entry in entries:
        assert re.fullmatch(r"[A-Za-z0-9_.-]+==\d+(\.\d+)+", entry), (
            f"{entry} is not pinned to an exact version"
        )
