"""FastAPI composition root."""

from fastapi import FastAPI

from soclab import __version__

app = FastAPI(title="SOC Agent Assurance Lab", version=__version__)


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe used by the container health check and the smoke test."""
    return {"status": "ok"}
