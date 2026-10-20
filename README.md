# SecureFix AI — Vulnerable Demo Lab (`securefix-vuln-lab`)

> [!CAUTION]
> **INTENTIONALLY VULNERABLE LAB — FOR LOCAL TESTING ONLY**  
> This application contains intentional security vulnerabilities designed as a test fixture for the **SecureFix AI** automated security remediation platform.
> - **Never deploy this application publicly or host it on an untrusted network.**
> - **Bind strictly to local loopback (`127.0.0.1`).**
> - **Never introduce real credentials, production data, or personal information.**
> - **Do not add automated exploit tools, destructive payloads, shell execution, or external network callbacks.**

---

## 1. Project Purpose

`securefix-vuln-lab` is a deliberately vulnerable, self-contained task-management API built with FastAPI and SQLite. It serves as a benchmark and regression fixture for SecureFix AI to evaluate:

1. **SARIF Finding Ingestion & Normalization**: Parsing static analysis findings and mapping them to source code locations.
2. **Remediation Planning**: Analyzing vulnerabilities and generating targeted, context-aware remediation proposals.
3. **Patch Validation**: Verifying that proposed patches resolve security defects without breaking functional contracts.
4. **Human Review & Auditing**: Inspecting patch diffs, evidence rationales, and audit histories.

### Synthetic Provenance Notice
- The findings catalog ([`security/findings-catalog.json`](file:///d:/Project/SecureFixAI_VulnerableDemo/security/findings-catalog.json)) and SARIF fixture ([`fixtures/securefix-vuln-lab.sarif`](file:///d:/Project/SecureFixAI_VulnerableDemo/fixtures/securefix-vuln-lab.sarif)) are **hand-authored synthetic test fixtures**.
- They test SecureFix AI's ingestion and remediation pipelines; they do **not** imply that a third-party commercial static analyzer was executed or that an analyzer would automatically detect all eight planted findings.

---

## 2. Technology Stack & Architecture

- **Language & Runtime**: Python 3.12+ (tested on Python 3.13)
- **Web Framework**: FastAPI (ASGI)
- **Server**: Uvicorn
- **Database**: SQLite3 (Python standard library `sqlite3` with parameterized queries for normal operations)
- **Validation**: Pydantic v2
- **Testing**: pytest & HTTPX
- **Package Management**: `uv` and `pyproject.toml`

### Repository Layout
```
securefix-vuln-lab/
├── app/
│   ├── __init__.py
│   ├── config.py         # Loopback binding, settings, fake credential marker (SFV-007)
│   ├── db.py             # SQLite schema, idempotent seed data, connection context
│   ├── main.py           # FastAPI app, routes, CORS (SFV-004), headers (SFV-006), error handling (SFV-005)
│   ├── schemas.py        # Pydantic request & response models
│   └── services.py       # Task business logic, SQL concatenation (SFV-002), eval filter (SFV-003)
├── fixtures/
│   └── securefix-vuln-lab.sarif   # SARIF 2.1.0 ingestion fixture (8 reconciled findings)
├── security/
│   └── findings-catalog.json     # Authoritative metadata for all eight findings
├── specs/001-vulnerable-demo/     # SDD specifications, plan, tasks, and acceptance criteria
├── tests/
│   ├── __init__.py
│   ├── test_api.py               # Functional database and API route tests
│   ├── test_health.py            # Loopback binding and socket isolation tests
│   ├── test_sarif_catalog.py     # Structural parity and source construct tests
│   └── test_security_findings.py # Safe local verification tests for SFV-001 to SFV-008
├── .env.example                  # Environment configuration template
├── .gitignore                    # Git ignores for SQLite DBs, Python cache, and .venv
├── pyproject.toml                # Project metadata and dependencies
└── README.md                     # Lab documentation
```

---

## 3. Prerequisites

- **Python**: Version 3.12 or newer. Check with:
  ```powershell
  python --version
  ```
- **uv**: Modern, high-performance Python package manager. Check with:
  ```powershell
  uv --version
  ```
- **Operating System**: Windows (PowerShell), macOS, or Linux.

---

## 4. Setup & Installation

All commands are shown for **Windows PowerShell** (compatible with bash/zsh):

1. **Navigate to the project root**:
   ```powershell
   cd d:\Project\SecureFixAI_VulnerableDemo
   ```

2. **Synchronize dependencies into virtual environment**:
   ```powershell
   uv sync
   ```
   This automatically creates a local `.venv` and installs all runtime and development dependencies.

3. **Configure Environment Variables (Optional)**:
   A template is provided in `.env.example`. Defaults operate safely without modifications:
   ```powershell
   Copy-Item .env.example .env
   ```
   Default configuration values:
   - `APP_HOST=127.0.0.1` (Strictly local loopback)
   - `APP_PORT=8000`
   - `DATABASE_PATH=securefix_lab.db`
   - `APP_ENV=local_demo`

---

## 5. Running the Application

### Start the Service (Local Loopback Only)
Run via PowerShell using `uv`:
```powershell
uv run python -m app.main
```
Or directly with Uvicorn:
```powershell
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Accessing the API
Once started, the API is available locally at:
- **Base URL**: `http://127.0.0.1:8000`
- **Health Check**: `http://127.0.0.1:8000/health`
- **Swagger UI Docs**: `http://127.0.0.1:8000/docs`
- **ReDoc Documentation**: `http://127.0.0.1:8000/redoc`

### Stopping the Service
Press `Ctrl + C` in your terminal to gracefully shut down the server.

> [!IMPORTANT]
> **Loopback Guard**: The application includes a startup validation guard. Attempting to start the application bound to `0.0.0.0` or a public/LAN IP address triggers a fatal `RuntimeError` preventing insecure exposure.

---

## 6. API Reference & Endpoints

| Method | Endpoint | Description | Intentional Demo Note |
|:---|:---|:---|:---|
| `GET` | `/health` | Application status & version | **SFV-008**: Exposes application version metadata. |
| `GET` | `/tasks` | List synthetic tasks | Supports optional filtering by `?owner_id=owner_1`. |
| `GET` | `/tasks/{task_id}` | Retrieve task by ID | **SFV-001**: Does not enforce owner scope against simulated caller (`X-User-Id`). |
| `POST` | `/tasks` | Create a new task | Accepts JSON body (`title`, `description`, `status`, `owner_id`). |
| `GET` | `/tasks/search` | Search tasks by keyword | **SFV-002**: Direct SQL query string concatenation on `?q=...`. |
| `GET` | `/reports/summary` | Aggregate task statistics | **SFV-003**: Evaluates optional `?filter_expr=...` dynamically via `eval()`. |
| `GET` | `/debug/controlled-error` | Controlled diagnostic test | **SFV-005**: Returns internal exception class and synthetic diagnostic field. |

---

## 7. The Eight Intentional Security Findings

This repository preserves **exactly eight intentional security findings** (3 High, 3 Medium, 2 Low). These defects must **never** be silently removed or fixed in the base lab repository:

| Finding ID | Severity | Category | Source Location | Intentional Behavior | Safe Verification |
|:---|:---:|:---|:---|:---|:---|
| **SFV-001** | **High** | Broken Object-Level Authorization (IDOR) | [`app/main.py:138-141`](file:///d:/Project/SecureFixAI_VulnerableDemo/app/main.py#L138-L141) | Task detail route returns tasks without verifying if caller identity (`X-User-Id`) matches task owner. | Simulate `X-User-Id: owner_1` requesting task owned by `owner_2`. |
| **SFV-002** | **High** | SQL Query Concatenation | [`app/services.py:73-77`](file:///d:/Project/SecureFixAI_VulnerableDemo/app/services.py#L73-L77) | Search helper constructs a read-only `SELECT` query via f-string string concatenation rather than parameterized SQL. | Local query construction check using benign search terms. |
| **SFV-003** | **High** | Unsafe Dynamic Evaluation | [`app/services.py:138`](file:///d:/Project/SecureFixAI_VulnerableDemo/app/services.py#L138) | Report summary filter helper evaluates dynamic filter expressions using Python `eval()`. | Evaluate harmless boolean expression (`completed > 0`). |
| **SFV-004** | **Medium** | Permissive CORS Configuration | [`app/main.py:43-49`](file:///d:/Project/SecureFixAI_VulnerableDemo/app/main.py#L43-L49) | CORS middleware configured with wildcard origin (`*`), methods, and headers. | Send preflight `OPTIONS /tasks` with simulated origin. |
| **SFV-005** | **Medium** | Verbose Error Responses | [`app/main.py:72-79`](file:///d:/Project/SecureFixAI_VulnerableDemo/app/main.py#L72-L79) | Controlled error handler exposes internal exception class name and synthetic diagnostic trace field. | Request `/debug/controlled-error` and verify response keys. |
| **SFV-006** | **Medium** | Missing Defensive Security Headers | [`app/main.py:56-60`](file:///d:/Project/SecureFixAI_VulnerableDemo/app/main.py#L56-L60) | Standard defensive headers (`X-Content-Type-Options`, `Content-Security-Policy`, `HSTS`) are omitted. | Assert omission of defensive headers in HTTP responses. |
| **SFV-007** | **Low** | Hardcoded Fake Credential | [`app/config.py:6`](file:///d:/Project/SecureFixAI_VulnerableDemo/app/config.py#L6) | Nonfunctional placeholder string `demo-only-not-a-real-secret` present for scanner ingestion testing. | Verify constant presence and confirm it is unused for authentication. |
| **SFV-008** | **Low** | Version Disclosure | [`app/main.py:88-93`](file:///d:/Project/SecureFixAI_VulnerableDemo/app/main.py#L88-L93) | Health check route exposes application version metadata (`1.0.0-demo`). | Assert version field is present in `/health` payload. |

---

## 8. Running Tests

Run the full automated test suite using `uv`:
```powershell
uv run pytest -v
```

### Test Suite Structure
The test suite consists of **31 deterministic tests** running against isolated temporary databases:

- [`tests/test_health.py`](file:///d:/Project/SecureFixAI_VulnerableDemo/tests/test_health.py) (4 tests): Health check status, loopback binding validation, rejection of external/LAN IP addresses, and outbound socket isolation guard.
- [`tests/test_api.py`](file:///d:/Project/SecureFixAI_VulnerableDemo/tests/test_api.py) (10 tests): SQLite schema generation, idempotent seeding, task CRUD operations, input validation (422/400), summary calculations, and connection cleanup on failure.
- [`tests/test_security_findings.py`](file:///d:/Project/SecureFixAI_VulnerableDemo/tests/test_security_findings.py) (8 tests): Safe local-only behavioral verification of SFV-001 through SFV-008 without destructive payloads or external calls.
- [`tests/test_sarif_catalog.py`](file:///d:/Project/SecureFixAI_VulnerableDemo/tests/test_sarif_catalog.py) (9 tests): Structural validation of JSON/SARIF schemas, finding ID parity, severity level mapping, file existence, line-range integrity, and code construct matching.

### What the Tests Guarantee (and What They Do Not Prove)
- **Guaranteed**:
  - The API operates correctly according to specification.
  - All eight intentional security findings remain present and observable locally.
  - The SARIF fixture, findings catalog, and source code line numbers are in 100% agreement.
  - All tests execute locally without outbound network access or destructive actions.
- **Not Proven**:
  - Passing tests do not imply that a static security scanner was executed or that any specific commercial scanner would report these findings. The SARIF file is a synthetic benchmark fixture.

---

## 9. Safe Testing Workflow for SecureFix AI

When using this demo lab to evaluate SecureFix AI remediation:

1. **Ingest the Fixture**: Import [`fixtures/securefix-vuln-lab.sarif`](file:///d:/Project/SecureFixAI_VulnerableDemo/fixtures/securefix-vuln-lab.sarif) into SecureFix AI.
2. **Review Normalization**: Verify that SecureFix AI registers exactly eight findings with their respective severities (3 High, 3 Medium, 2 Low).
3. **Generate Remediation Proposals**: Select a finding (e.g., `SFV-001` or `SFV-002`) and instruct SecureFix AI to generate a patch proposal and validation plan.
4. **Inspect Patch Diffs Safely**: Review the generated code diff in isolation without automatically applying it to the working repository.
5. **Human Verdict**: Record human reviewer verdicts and audit trails through the SecureFix AI dashboard.
6. **Reset Database**: When testing concludes, delete `securefix_lab.db` (it will be regenerated automatically on the next startup).
