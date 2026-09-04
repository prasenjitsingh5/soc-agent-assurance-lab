# Third-party notices

The lab depends on the following projects through their published packages. None of their source is copied into this repository. Licenses were reviewed on 2026-09-04; re-check when bumping versions.

| Project | Use | License |
|---|---|---|
| FastAPI, Starlette, Uvicorn | HTTP API | MIT, BSD-3-Clause |
| Pydantic | contracts and validation | MIT |
| SQLAlchemy | evidence store | MIT |
| httpx | HTTP client for OPA, Ollama and Phoenix | BSD-3-Clause |
| PyYAML | scenario files | MIT |
| Jinja2 | report templates | BSD-3-Clause |
| Typer | command line | MIT |
| Open Policy Agent | policy decision point, run as a separate binary or container | Apache-2.0 |
| openai (Python SDK) | OpenAI, Azure OpenAI, xAI and compatible adapters, optional | Apache-2.0 |
| anthropic (Python SDK) | Anthropic adapter, optional | MIT |
| google-genai | Gemini and Vertex adapter, optional | Apache-2.0 |
| psycopg | PostgreSQL driver in the Docker profile, optional | LGPL-3.0 |
| pytest, ruff, mypy, bandit, pip-audit, cyclonedx-bom | development and security tooling | MIT, MIT, MIT, Apache-2.0, Apache-2.0, Apache-2.0 |
| PostgreSQL, Redis, OPA container images | Docker profile | PostgreSQL License, RSALv2/SSPLv1 (Redis 7.4), Apache-2.0 |

All product and company names above are trademarks or registered marks of their respective owners, referenced only to identify interoperability; no affiliation or endorsement is implied. MITRE ATT&CK technique identifiers appear in fixtures and findings. ATT&CK is a registered trademark of The MITRE Corporation and is used under its terms of use for reference.

The reference projects listed in `docs/REFERENCE-INVENTORY.md` informed the design. No code from them is included.

Run `make sbom` for the complete, versioned bill of materials.
