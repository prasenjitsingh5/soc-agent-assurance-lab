# syntax=docker/dockerfile:1.7
# Lab API and CLI image. Non-root, read-only root filesystem friendly, no credentials baked in.

FROM python:3.12.7-slim-bookworm AS build
COPY --from=ghcr.io/astral-sh/uv:0.12.9 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=1 UV_PYTHON_DOWNLOADS=never
COPY pyproject.toml uv.lock README.md ./
COPY soclab ./soclab
COPY policies ./policies
COPY scenarios ./scenarios
RUN uv sync --locked --no-dev --no-editable

FROM python:3.12.7-slim-bookworm AS runtime
RUN groupadd --system soclab && useradd --system --gid soclab --uid 10001 --home /app soclab
WORKDIR /app
COPY --from=build --chown=soclab:soclab /app/.venv /app/.venv
COPY --from=build --chown=soclab:soclab /app/policies /app/policies
COPY --from=build --chown=soclab:soclab /app/scenarios /app/scenarios
ENV PATH="/app/.venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN mkdir -p /app/runs && chown soclab:soclab /app/runs
USER soclab
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=6 CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"
CMD ["uvicorn", "soclab.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
