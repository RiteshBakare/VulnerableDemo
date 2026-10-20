# Tasks

## T001 — Scaffold
- [ ] Create package layout, pyproject.toml, .gitignore, .env.example.
- [ ] Create FastAPI app with loopback-only startup and `/health`.

## T002 — API and database
- [ ] Implement SQLite schema and deterministic synthetic seed data.
- [ ] Implement list/read/create task routes and report summary.
- [ ] Add normal behavior tests.

## T003 — Intentional findings
- [ ] Implement exactly SFV-001 through SFV-008 from `security-findings.md`.
- [ ] Use synthetic inputs and safe tests.
- [ ] Comment each defect with its SFV ID.
- [ ] Do not add unlisted issues.

## T004 — Catalog and SARIF
- [ ] Create `security/findings-catalog.json`.
- [ ] Create valid SARIF 2.1.0 with eight results.
- [ ] Match IDs, levels, descriptions, paths, and line numbers.

## T005 — Tests and documentation
- [ ] Test all routes and each finding safely.
- [ ] Confirm no external calls or destructive behavior.
- [ ] Document setup, start, test, and safe usage.
- [ ] Report actual test results; don't claim scanner detection unless a scanner ran.
