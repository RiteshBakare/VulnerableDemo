# Feature Specification: Intentionally Vulnerable Task API

## User story
As a SecureFix AI developer, I need 5–10 documented findings across low, medium, and high severity to test import, normalization, remediation planning, patch proposal validation, and human review using synthetic data.

## Functional requirements
- `GET /health` returns a static health response.
- `GET /tasks` lists synthetic tasks.
- `GET /tasks/{task_id}` returns a task or 404.
- `POST /tasks` creates a task in local SQLite.
- `GET /reports/summary` returns a simple summary.
- The service binds to `127.0.0.1` by default.
- Seed data is synthetic and repeatable.
- Tests use safe synthetic inputs.
- `security/findings-catalog.json` describes all eight findings.
- `fixtures/securefix-vuln-lab.sarif` is valid JSON using SARIF 2.1.0 with eight results.
- SARIF line numbers must be reconciled with generated source files.

## Nonfunctional requirements
No outbound network calls, real secrets, public deployment, exploit automation, automatic remediation, cloud services, hidden backdoors, shell execution, file-deletion endpoints, or unlisted vulnerabilities. Keep the codebase to roughly 5–10 source files and tests deterministic.

## API
`GET /health`, `GET /tasks`, `GET /tasks/{task_id}`, `POST /tasks`, `GET /reports/summary`.

## Definition of done
Fresh setup works on Python 3.12+, functional tests pass, the app binds to loopback, and all eight findings match the catalog and SARIF fixture.
