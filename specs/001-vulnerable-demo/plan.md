# Implementation Plan

## Layout
- `app/main.py`: FastAPI routes and app setup.
- `app/db.py`: SQLite schema, connection, seed helpers.
- `app/services.py`: task/report logic and designated findings.
- `app/config.py`: local configuration and fake scanner fixture value.
- `tests/`: functional and safe security-behavior tests.
- `security/findings-catalog.json`: authoritative metadata.
- `fixtures/securefix-vuln-lab.sarif`: SARIF fixture.
- `pyproject.toml`: dependencies and pytest settings.

## Stages
1. Scaffold package, app, dependencies, and health route.
2. Implement SQLite schema, synthetic seed data, task routes, and functional tests.
3. Add exactly SFV-001 through SFV-008 from `security-findings.md`.
4. Add safe local tests for the intended behaviors.
5. Create catalog and SARIF; reconcile paths and line numbers.
6. Document setup and warnings.
7. Run tests and JSON validation; report actual outcomes.
8. Confirm loopback binding and no outbound calls.

Do not add extra vulnerabilities, exploit chains, scanner/provider dependencies, or automatic fixes.
