# Local Docker profile

Four containers: the lab API, Open Policy Agent, PostgreSQL and Redis. Everything is synthetic; no provider keys are needed. Copy `postgres_password.example` to `postgres_password.local` (gitignored) before the first start.

```bash
cp infrastructure/docker/postgres_password.example infrastructure/docker/postgres_password.local
make up          # docker compose up -d --wait
curl http://127.0.0.1:8000/health
make down        # docker compose down -v
```

Design choices:

- Images are pinned by tag. Bump them deliberately and re-run the container scan.
- OPA, Redis and the API run with read-only root filesystems and non-root users. PostgreSQL manages its own user.
- The API is published on loopback only. Nothing listens on external interfaces.
- The policy directory is mounted read-only into OPA from the repository, so the container evaluates exactly the Rego that the tests cover.
- The database password is a Compose secret from a local file, never an environment variable in the compose file.
- The PostgreSQL URL uses `psycopg`, which is included in the `docker` extra. The default outside Docker remains SQLite.

The smoke test in `tests/smoke/test_local_stack.py` brings the stack up, checks health, runs a baseline campaign through the API and verifies the evidence chain. It is skipped automatically when Docker is not available.
