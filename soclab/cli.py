"""Command-line entry point. Commands are added as milestones land."""

import typer

from soclab import __version__

app = typer.Typer(help="SOC Agent Assurance Lab", no_args_is_help=True)


@app.command()
def version() -> None:
    """Print the lab version."""
    typer.echo(__version__)


if __name__ == "__main__":
    app()
