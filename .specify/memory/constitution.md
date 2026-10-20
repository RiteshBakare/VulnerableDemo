# Project Constitution

## Mission
Create a deliberately vulnerable, local-only FastAPI task API as a repeatable SecureFix AI test fixture.

## Principles
- Bind to `127.0.0.1`; never deploy publicly.
- Synthetic data only; no real credentials.
- No destructive behavior, external callbacks, malware, persistence, shell execution, or exploit automation.
- Preserve exactly the eight catalogued findings; do not silently fix them.
- Every finding has stable ID SFV-001–SFV-008, severity, source location, rationale, and safe local verification.
- Deterministic seed data, tests, and SARIF.
- Prominent warning: intentionally vulnerable, not for production.
- No outbound network calls during normal startup/tests.
- Keep the project small and patch-friendly.

## Stack
Python 3.12+, FastAPI, Uvicorn, SQLite, pytest. Include pyproject.toml, .env.example, .gitignore, and README.
