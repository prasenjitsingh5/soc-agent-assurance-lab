"""Command-line entry point.

Every command runs entirely locally. ``demo`` is the five-minute path: it runs
the baseline and protected campaigns with the mock provider, writes both
reports and prints where they are.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer

from soclab import __version__
from soclab.contracts import AuthorityLevel
from soclab.evaluator import CampaignConfig, load_attack_scenarios, run_campaign
from soclab.evidence import EvidenceRepository
from soclab.orchestrator import BaselinePort, ToolProposalPort, run_investigation
from soclab.policy import (
    ManagedOpaServer,
    OpaHttpPolicyEngine,
    PolicyEngine,
    PolicyUnavailableError,
    find_opa_binary,
)
from soclab.providers.registry import ProviderRegistry
from soclab.reports import ReportAudience, ReportGenerator
from soclab.scoring import AssuranceResult, CampaignResult, score_campaign
from soclab.simulator import SimulatorState

app = typer.Typer(help="SOC Agent Assurance Lab", no_args_is_help=True)

DEFAULT_DB = "sqlite+pysqlite:///./runs/soclab.sqlite"


def _repository(database_url: str | None) -> EvidenceRepository:
    url = database_url or os.environ.get("SOCLAB_DATABASE_URL", DEFAULT_DB)
    if url.startswith("sqlite+pysqlite:///./"):
        Path(url.removeprefix("sqlite+pysqlite:///./")).parent.mkdir(parents=True, exist_ok=True)
    return EvidenceRepository(url)


def _policy_engine() -> tuple[PolicyEngine, ManagedOpaServer | None]:
    """Prefer a configured OPA server; otherwise start a managed one from the local binary."""
    url = os.environ.get("SOCLAB_OPA_URL")
    if url:
        return OpaHttpPolicyEngine(url), None
    if find_opa_binary() is None:
        msg = "no OPA available: set SOCLAB_OPA_URL or install the opa binary (see README)"
        raise PolicyUnavailableError(msg)
    server = ManagedOpaServer()
    return server.start(), server


@app.command()
def version() -> None:
    """Print the lab version."""
    typer.echo(__version__)


@app.command()
def providers() -> None:
    """Show the provider compatibility matrix from the current environment."""
    registry = ProviderRegistry()
    for row in registry.matrix():
        caps = row["capabilities"]
        flags = ",".join(k for k, v in caps.items() if v)
        typer.echo(f"{row['provider_id']:<18} approved={row['approved']!s:<5} caps={flags}")
        for note in row["limitations"]:
            typer.echo(f"{'':<18}   {note}")


@app.command()
def scenarios() -> None:
    """List the versioned attack scenarios."""
    for s in load_attack_scenarios():
        typer.echo(f"{s.id} v{s.version} {s.attack_class:<40} {s.title}")


@app.command()
def investigate(
    provider: Annotated[str, typer.Option(help="Provider id from the registry")] = "mock",
    model: Annotated[str | None, typer.Option(help="Model id; defaults to the registry default")] = None,
    mode: Annotated[str, typer.Option(help="baseline or protected")] = "protected",
    level: Annotated[str, typer.Option(help="Authority level L1 to L5 for protected mode")] = "L4",
    database_url: Annotated[str | None, typer.Option(help="SQLAlchemy URL for the evidence store")] = None,
) -> None:
    """Run one identity-compromise investigation and print the result."""
    registry = ProviderRegistry()
    model_provider = registry.get(provider, model=model)
    simulator = SimulatorState.from_fixture(enforce_scope=mode == "protected")

    async def _run() -> None:
        server = None
        try:
            port: ToolProposalPort
            if mode == "protected":
                from soclab.approvals import ApprovalService
                from soclab.executor import Executor
                from soclab.gateway import ControlGateway, GatewayConfig
                from soclab.grants import GrantSigner

                engine, server = _policy_engine()
                signer = GrantSigner()
                gateway = ControlGateway(
                    config=GatewayConfig(
                        incident_id=simulator.incident_id,
                        authority_level=AuthorityLevel(level),
                        approved_models=((model_provider.provider_id, model_provider.model),),
                    ),
                    policy=engine,
                    executor=Executor(simulator, signer),
                    signer=signer,
                    approvals=ApprovalService(),
                )
                port = gateway
            else:
                port = BaselinePort(simulator)
            result = await run_investigation(
                simulator.incident_id, dict(simulator.incident), model_provider, port
            )
        finally:
            if server is not None:
                server.stop()
        typer.echo(json.dumps(result.model_dump(mode="json"), indent=2, default=str))

    asyncio.run(_run())


@app.command()
def campaign(
    mode: Annotated[str, typer.Option(help="baseline or protected")] = "protected",
    level: Annotated[str, typer.Option(help="Authority level for protected mode")] = "L4",
    repeats: Annotated[int, typer.Option(min=1)] = 1,
    scenario: Annotated[list[str] | None, typer.Option(help="Scenario id, repeatable")] = None,
    out: Annotated[Path, typer.Option(help="Output folder for reports")] = Path("runs/latest"),
    database_url: Annotated[str | None, typer.Option()] = None,
) -> None:
    """Run the adversarial campaign with the mock provider and write reports."""
    repository = _repository(database_url)
    config = CampaignConfig(
        mode=mode,
        authority_level=AuthorityLevel(level),
        repeats=repeats,
        scenario_ids=tuple(scenario) if scenario else None,
    )

    async def _run() -> None:
        server = None
        try:
            engine: PolicyEngine | None = None
            if mode == "protected":
                engine, server = _policy_engine()
            result = await run_campaign(config, policy=engine, repository=repository)
        finally:
            if server is not None:
                server.stop()
        assurance = score_campaign(result)
        _write_reports(repository, result, assurance, out, mode)
        gates = list(assurance.gate_failures) or "none"
        typer.echo(
            f"{mode}: attack success {assurance.attack_success_rate.value:.0%}, "
            f"composite {assurance.composite:.2f}, gates {gates}, "
            f"authority {assurance.recommended_authority_level.value}"
        )

    asyncio.run(_run())


@app.command()
def compare(
    out: Annotated[Path, typer.Option()] = Path("runs/latest"),
    database_url: Annotated[str | None, typer.Option()] = None,
) -> None:
    """Run baseline and protected campaigns side by side and write both reports."""
    repository = _repository(database_url)

    async def _run() -> None:
        engine, server = _policy_engine()
        try:
            baseline = await run_campaign(CampaignConfig(mode="baseline"), policy=None, repository=repository)
            protected = await run_campaign(
                CampaignConfig(mode="protected"), policy=engine, repository=repository
            )
        finally:
            if server is not None:
                server.stop()
        base_score = score_campaign(baseline)
        prot_score = score_campaign(protected)
        generator = ReportGenerator(repository)
        out.mkdir(parents=True, exist_ok=True)
        for audience in ReportAudience:
            report = generator.generate(
                protected, prot_score, audience, baseline=base_score, comparison=[base_score, prot_score]
            )
            (out / f"{audience.value}.html").write_text(report.html, encoding="utf-8")
            (out / f"{audience.value}.json").write_text(report.json_payload, encoding="utf-8")
        for label, score in (("baseline ", base_score), ("protected", prot_score)):
            typer.echo(
                f"{label}: attack success {score.attack_success_rate.value:.0%}, "
                f"authority {score.recommended_authority_level.value}"
            )
        typer.echo(f"reports  : {out / 'executive.html'} and {out / 'technical.html'}")

    asyncio.run(_run())


@app.command()
def demo() -> None:
    """Five-minute path: compare baseline and protected with the mock provider."""
    compare(out=Path("runs/demo"), database_url=None)


@app.command(name="verify-chain")
def verify_chain(
    run_id: Annotated[str | None, typer.Argument(help="Run id; omit to verify every run")] = None,
    database_url: Annotated[str | None, typer.Option()] = None,
) -> None:
    """Verify the hash chain of one run or every run in the evidence store."""
    repository = _repository(database_url)
    ids = [UUID(run_id)] if run_id else repository.run_ids()
    bad = 0
    for rid in ids:
        v = repository.verify_chain(rid)
        status = "valid" if v.valid else f"INVALID at sequence {v.first_invalid_sequence} ({v.reason})"
        typer.echo(f"{rid} {v.length:>4} events {status} root={v.root_hash}")
        bad += 0 if v.valid else 1
    if bad:
        raise typer.Exit(code=1)


def _write_reports(
    repository: EvidenceRepository, result: CampaignResult, assurance: AssuranceResult, out: Path, mode: str
) -> None:
    generator = ReportGenerator(repository)
    out.mkdir(parents=True, exist_ok=True)
    for audience in ReportAudience:
        report = generator.generate(result, assurance, audience)
        (out / f"{mode}-{audience.value}.html").write_text(report.html, encoding="utf-8")
        (out / f"{mode}-{audience.value}.json").write_text(report.json_payload, encoding="utf-8")


if __name__ == "__main__":
    app()
